#!/usr/bin/env python3
"""Fail-closed ruleset transition broker for HELM authority generations."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
import urllib.error
import urllib.request

from autonomous_release_permit import PermitInputError, require_sha


API_VERSION = "2026-03-10"
ORGANIZATION = "Mindburn-Labs"
AUTHORITY_REPOSITORY_ID = 1159255601
STABLE_RULESET_ID = 18924515
CANDIDATE_RULESET_ID = 18927405
STABLE_RULESET_NAME = "HELM Autonomous Release Permit"
CANDIDATE_RULESET_NAME = "HELM Autonomous Release Permit Candidate Shadow"
WORKFLOW_PATH = ".github/workflows/ci.yml"
MAIN_REF = "refs/heads/main"
CANDIDATE_REPOSITORY_IDS = (
    1158479649,
    1159255601,
    1250514808,
    1268806323,
    1283905989,
    1286471668,
    1300498536,
    1301786253,
)
PUBLIC_AUTONOMOUS_REPOSITORY_IDS = (
    1158479649,
    1159255601,
    1300498536,
    1301786253,
)
LEGACY_STABLE_WORKFLOW_SHA = "8500b6549a61a9c1caf7575964132651ffb754c8"
LEGACY_PARENT_WORKFLOW_SHA = "52a1ef42118e618e811bce48204f4a49a41b8bca"
LEGACY_WORKFLOW_REF = "refs/heads/codex/autonomous-release-permit"
AUTHORITY_REPOSITORY = "Mindburn-Labs/.github"
RECONCILE_SCHEMA = "mindburn.release-authority-ruleset-reconcile/v1"


@dataclass(frozen=True)
class APIResponse:
    body: dict[str, Any]
    etag: str | None


class GitHubRulesetClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise PermitInputError("GH_TOKEN is required")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        if_match: str | None = None,
    ) -> APIResponse:
        content = None
        if payload is not None:
            content = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": " ".join(("Bearer", self.token)),
            "X-GitHub-Api-Version": API_VERSION,
        }
        if content is not None:
            headers["Content-Type"] = "application/json"
        if if_match is not None:
            headers["If-Match"] = if_match
        request = urllib.request.Request(
            self.api_url + path,
            data=content,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
                body = json.loads(response.read().decode("utf-8"))
                if not isinstance(body, dict):
                    raise PermitInputError(
                        "GitHub returned a non-object ruleset response"
                    )
                return APIResponse(body=body, etag=response.headers.get("ETag"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            if exc.code == 412:
                raise PermitInputError(
                    f"ruleset changed before {method} {path}"
                ) from exc
            raise PermitInputError(
                f"GitHub {method} {path} failed with HTTP {exc.code}: {detail}",
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise PermitInputError(f"GitHub {method} {path} failed: {exc}") from exc

    def get_main_sha(self) -> str:
        response = self.request(
            "GET",
            f"/repos/{AUTHORITY_REPOSITORY}/git/ref/heads/main",
        )
        object_value = response.body.get("object")
        if not isinstance(object_value, dict):
            raise PermitInputError("GitHub main ref response is malformed")
        return require_sha(
            object_value.get("sha"),
            label="live authority main SHA",
            length=40,
        )


def validate_ref(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("refs/heads/")
        or len(value) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PermitInputError(f"{label} must be a bounded branch ref")
    check = subprocess.run(
        ["git", "check-ref-format", value],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if check.returncode != 0:
        raise PermitInputError(f"{label} is not a valid Git branch ref")
    return value


def expected_conditions(kind: str) -> dict[str, Any]:
    ref_condition = {"exclude": [], "include": ["~DEFAULT_BRANCH"]}
    if kind == "stable":
        return {
            "ref_name": ref_condition,
            "repository_id": {
                "repository_ids": list(PUBLIC_AUTONOMOUS_REPOSITORY_IDS),
            },
        }
    return {
        "ref_name": ref_condition,
        "repository_id": {"repository_ids": list(CANDIDATE_REPOSITORY_IDS)},
    }


def legacy_stable_conditions() -> dict[str, Any]:
    return {
        "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
        "repository_name": {"exclude": [], "include": ["~ALL"]},
    }


def workflow_binding(ruleset: dict[str, Any]) -> dict[str, Any]:
    rules = ruleset.get("rules")
    if not isinstance(rules, list) or len(rules) != 1:
        raise PermitInputError("ruleset must contain exactly one rule")
    rule = rules[0]
    if not isinstance(rule, dict) or rule.get("type") != "workflows":
        raise PermitInputError("ruleset must contain exactly one workflow rule")
    parameters = rule.get("parameters")
    if not isinstance(parameters, dict) or set(parameters) != {
        "do_not_enforce_on_create",
        "workflows",
    }:
        raise PermitInputError("workflow rule parameters are not exact")
    if parameters["do_not_enforce_on_create"] is not False:
        raise PermitInputError("workflow rule must enforce on branch creation")
    workflows = parameters["workflows"]
    if not isinstance(workflows, list) or len(workflows) != 1:
        raise PermitInputError("workflow rule must bind exactly one workflow")
    workflow = workflows[0]
    if not isinstance(workflow, dict) or set(workflow) != {
        "path",
        "ref",
        "repository_id",
        "sha",
    }:
        raise PermitInputError("workflow binding keys are not exact")
    if workflow["repository_id"] != AUTHORITY_REPOSITORY_ID:
        raise PermitInputError("workflow binding uses the wrong authority repository")
    if workflow["path"] != WORKFLOW_PATH:
        raise PermitInputError("workflow binding uses the wrong authority path")
    require_sha(workflow["sha"], label="ruleset workflow sha", length=40)
    validate_ref(workflow["ref"], label="ruleset workflow ref")
    return workflow


def validate_ruleset(
    ruleset: dict[str, Any],
    *,
    kind: str,
    expected_sha: str,
    expected_ref: str,
    expected_enforcement: str | None = None,
    expected_coverage: dict[str, Any] | None = None,
) -> None:
    expected_id = STABLE_RULESET_ID if kind == "stable" else CANDIDATE_RULESET_ID
    expected_name = STABLE_RULESET_NAME if kind == "stable" else CANDIDATE_RULESET_NAME
    enforcement = expected_enforcement or ("active" if kind == "stable" else "evaluate")
    coverage = expected_coverage or expected_conditions(kind)
    if ruleset.get("id") != expected_id or ruleset.get("name") != expected_name:
        raise PermitInputError(f"unexpected {kind} ruleset identity")
    if ruleset.get("target") != "branch" or ruleset.get("enforcement") != enforcement:
        raise PermitInputError(f"unexpected {kind} ruleset target or enforcement")
    if ruleset.get("bypass_actors") != []:
        raise PermitInputError(f"{kind} ruleset cannot have bypass actors")
    if ruleset.get("conditions") != coverage:
        raise PermitInputError(f"unexpected {kind} ruleset coverage")
    workflow = workflow_binding(ruleset)
    if workflow["sha"] != expected_sha or workflow["ref"] != expected_ref:
        raise PermitInputError(f"unexpected {kind} workflow generation")


def validate_ruleset_identity(ruleset: dict[str, Any], *, kind: str) -> dict[str, Any]:
    workflow = workflow_binding(ruleset)
    validate_ruleset(
        ruleset,
        kind=kind,
        expected_sha=workflow["sha"],
        expected_ref=workflow["ref"],
    )
    return workflow


def update_payload(
    ruleset: dict[str, Any],
    *,
    workflow_sha: str,
    workflow_ref: str,
    enforcement: str | None = None,
    conditions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    require_sha(workflow_sha, label="new workflow sha", length=40)
    validate_ref(workflow_ref, label="new workflow ref")
    payload = {
        key: ruleset[key]
        for key in (
            "name",
            "target",
            "enforcement",
            "bypass_actors",
            "conditions",
            "rules",
        )
    }
    payload = json.loads(json.dumps(payload))
    if enforcement is not None:
        if enforcement not in {"active", "evaluate"}:
            raise PermitInputError("new ruleset enforcement is invalid")
        payload["enforcement"] = enforcement
    if conditions is not None:
        payload["conditions"] = json.loads(json.dumps(conditions))
    payload["rules"][0]["parameters"]["workflows"][0]["sha"] = workflow_sha
    payload["rules"][0]["parameters"]["workflows"][0]["ref"] = workflow_ref
    return payload


def get_ruleset(client: GitHubRulesetClient, ruleset_id: int) -> APIResponse:
    return client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}")


def put_ruleset(
    client: GitHubRulesetClient,
    current: APIResponse,
    *,
    workflow_sha: str,
    workflow_ref: str,
    enforcement: str | None = None,
    conditions: dict[str, Any] | None = None,
) -> APIResponse:
    ruleset_id = current.body["id"]
    refetched = get_ruleset(client, ruleset_id)
    if not current.etag or not refetched.etag:
        raise PermitInputError("ruleset GET did not return an ETag")
    if refetched.body != current.body or refetched.etag != current.etag:
        raise PermitInputError("ruleset changed during the transition")
    payload = update_payload(
        current.body,
        workflow_sha=workflow_sha,
        workflow_ref=workflow_ref,
        enforcement=enforcement,
        conditions=conditions,
    )
    client.request(
        "PUT",
        f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}",
        payload=payload,
        if_match=refetched.etag,
    )
    confirmed = get_ruleset(client, ruleset_id)
    confirmed_payload = {
        key: confirmed.body.get(key)
        for key in (
            "name",
            "target",
            "enforcement",
            "bypass_actors",
            "conditions",
            "rules",
        )
    }
    if confirmed_payload != payload:
        raise PermitInputError("ruleset changed before transition confirmation")
    return confirmed


def transition(args: argparse.Namespace, client: GitHubRulesetClient) -> dict[str, Any]:
    parent_sha = require_sha(args.parent_sha, label="parent_sha", length=40)
    candidate_sha = require_sha(args.candidate_sha, label="candidate_sha", length=40)
    candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    stable = get_ruleset(client, STABLE_RULESET_ID)
    candidate = get_ruleset(client, CANDIDATE_RULESET_ID)

    if args.operation == "reconcile":
        merge_sha = require_sha(args.merge_sha, label="merge_sha", length=40)
        current_main_sha = client.get_main_sha()
        stable_binding = validate_ruleset_identity(stable.body, kind="stable")
        candidate_binding = validate_ruleset_identity(candidate.body, kind="candidate")
        parent_binding = (parent_sha, MAIN_REF)
        candidate_binding_expected = (candidate_sha, candidate_ref)
        merged_binding = (merge_sha, MAIN_REF)
        stable_state = (stable_binding["sha"], stable_binding["ref"])
        candidate_state = (candidate_binding["sha"], candidate_binding["ref"])
        if current_main_sha == parent_sha:
            if stable_state != parent_binding or candidate_state not in {
                parent_binding,
                candidate_binding_expected,
            }:
                raise PermitInputError(
                    "pre-merge rulesets are outside resumable states"
                )
            result = receipt(
                args.operation,
                parent_sha,
                candidate_sha,
                candidate_ref,
                merge_sha,
            )
            result.update(
                {
                    "schema": RECONCILE_SCHEMA,
                    "current_main_sha": current_main_sha,
                    "rulesets_active": False,
                    "state": "pre-merge",
                }
            )
            return result
        if current_main_sha != merge_sha:
            raise PermitInputError("main is outside the reconciler lineage")
        if stable_state == merged_binding:
            if candidate_state != merged_binding:
                if candidate_state not in {parent_binding, candidate_binding_expected}:
                    raise PermitInputError(
                        "active candidate ruleset is outside resumable states"
                    )
                candidate = put_ruleset(
                    client,
                    candidate,
                    workflow_sha=merge_sha,
                    workflow_ref=MAIN_REF,
                )
                validate_ruleset(
                    candidate.body,
                    kind="candidate",
                    expected_sha=merge_sha,
                    expected_ref=MAIN_REF,
                )
            result = receipt(
                args.operation,
                parent_sha,
                candidate_sha,
                candidate_ref,
                merge_sha,
            )
            result.update(
                {
                    "schema": RECONCILE_SCHEMA,
                    "current_main_sha": current_main_sha,
                    "rulesets_active": True,
                    "state": "active",
                }
            )
            return result
        if stable_state != parent_binding or candidate_state not in {
            parent_binding,
            candidate_binding_expected,
            merged_binding,
        }:
            raise PermitInputError("post-merge rulesets are outside resumable states")
        if candidate_state == merged_binding:
            candidate = put_ruleset(
                client,
                candidate,
                workflow_sha=parent_sha,
                workflow_ref=MAIN_REF,
            )
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=parent_sha,
                expected_ref=MAIN_REF,
            )
        result = receipt(
            args.operation,
            parent_sha,
            candidate_sha,
            candidate_ref,
            merge_sha,
        )
        result.update(
            {
                "schema": RECONCILE_SCHEMA,
                "current_main_sha": current_main_sha,
                "rulesets_active": False,
                "state": "post-merge-retry",
            }
        )
        return result

    if args.operation in {"bootstrap-stage", "bootstrap-restore"}:
        if parent_sha != LEGACY_PARENT_WORKFLOW_SHA:
            raise PermitInputError("bootstrap requires the exact generation-1 parent")
        validate_ruleset(
            stable.body,
            kind="stable",
            expected_sha=LEGACY_STABLE_WORKFLOW_SHA,
            expected_ref=LEGACY_WORKFLOW_REF,
            expected_enforcement="evaluate",
            expected_coverage=legacy_stable_conditions(),
        )

        if args.operation == "bootstrap-stage":
            try:
                validate_ruleset(
                    candidate.body,
                    kind="candidate",
                    expected_sha=candidate_sha,
                    expected_ref=candidate_ref,
                )
            except PermitInputError:
                validate_ruleset(
                    candidate.body,
                    kind="candidate",
                    expected_sha=LEGACY_PARENT_WORKFLOW_SHA,
                    expected_ref=LEGACY_WORKFLOW_REF,
                )
            else:
                return receipt(
                    args.operation, parent_sha, candidate_sha, candidate_ref, None
                )
            updated = put_ruleset(
                client,
                candidate,
                workflow_sha=candidate_sha,
                workflow_ref=candidate_ref,
            )
            validate_ruleset(
                updated.body,
                kind="candidate",
                expected_sha=candidate_sha,
                expected_ref=candidate_ref,
            )
            return receipt(
                args.operation, parent_sha, candidate_sha, candidate_ref, None
            )

        if args.operation == "bootstrap-restore":
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=candidate_sha,
                expected_ref=candidate_ref,
            )
            updated = put_ruleset(
                client,
                candidate,
                workflow_sha=LEGACY_PARENT_WORKFLOW_SHA,
                workflow_ref=LEGACY_WORKFLOW_REF,
            )
            validate_ruleset(
                updated.body,
                kind="candidate",
                expected_sha=LEGACY_PARENT_WORKFLOW_SHA,
                expected_ref=LEGACY_WORKFLOW_REF,
            )
            return receipt(
                args.operation, parent_sha, candidate_sha, candidate_ref, None
            )

    if args.operation == "bootstrap-enforce":
        if parent_sha != LEGACY_PARENT_WORKFLOW_SHA:
            raise PermitInputError("bootstrap requires the exact generation-1 parent")
        validate_ruleset(
            candidate.body,
            kind="candidate",
            expected_sha=candidate_sha,
            expected_ref=candidate_ref,
        )
        try:
            validate_ruleset(
                stable.body,
                kind="stable",
                expected_sha=candidate_sha,
                expected_ref=candidate_ref,
            )
        except PermitInputError:
            validate_ruleset(
                stable.body,
                kind="stable",
                expected_sha=LEGACY_STABLE_WORKFLOW_SHA,
                expected_ref=LEGACY_WORKFLOW_REF,
                expected_enforcement="evaluate",
                expected_coverage=legacy_stable_conditions(),
            )
        else:
            return receipt(
                args.operation, parent_sha, candidate_sha, candidate_ref, None
            )
        stable_updated = put_ruleset(
            client,
            stable,
            workflow_sha=candidate_sha,
            workflow_ref=candidate_ref,
            enforcement="active",
            conditions=expected_conditions("stable"),
        )
        validate_ruleset(
            stable_updated.body,
            kind="stable",
            expected_sha=candidate_sha,
            expected_ref=candidate_ref,
        )
        return receipt(args.operation, parent_sha, candidate_sha, candidate_ref, None)

    if args.operation == "bootstrap-finalize":
        if parent_sha != LEGACY_PARENT_WORKFLOW_SHA:
            raise PermitInputError("bootstrap requires the exact generation-1 parent")
        merge_sha = require_sha(args.merge_sha, label="merge_sha", length=40)
        try:
            validate_ruleset(
                stable.body,
                kind="stable",
                expected_sha=merge_sha,
                expected_ref=MAIN_REF,
            )
        except PermitInputError:
            validate_ruleset(
                stable.body,
                kind="stable",
                expected_sha=candidate_sha,
                expected_ref=candidate_ref,
            )
        else:
            try:
                validate_ruleset(
                    candidate.body,
                    kind="candidate",
                    expected_sha=merge_sha,
                    expected_ref=MAIN_REF,
                )
            except PermitInputError:
                validate_ruleset(
                    candidate.body,
                    kind="candidate",
                    expected_sha=candidate_sha,
                    expected_ref=candidate_ref,
                )
                candidate = put_ruleset(
                    client,
                    candidate,
                    workflow_sha=merge_sha,
                    workflow_ref=MAIN_REF,
                )
                validate_ruleset(
                    candidate.body,
                    kind="candidate",
                    expected_sha=merge_sha,
                    expected_ref=MAIN_REF,
                )
            return receipt(
                args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha
            )
        try:
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=merge_sha,
                expected_ref=MAIN_REF,
            )
            candidate_updated = candidate
        except PermitInputError:
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=candidate_sha,
                expected_ref=candidate_ref,
            )
            candidate_updated = put_ruleset(
                client,
                candidate,
                workflow_sha=merge_sha,
                workflow_ref=MAIN_REF,
            )
            validate_ruleset(
                candidate_updated.body,
                kind="candidate",
                expected_sha=merge_sha,
                expected_ref=MAIN_REF,
            )
        try:
            stable_updated = put_ruleset(
                client,
                stable,
                workflow_sha=merge_sha,
                workflow_ref=MAIN_REF,
            )
        except PermitInputError as activation_error:
            try:
                put_ruleset(
                    client,
                    candidate_updated,
                    workflow_sha=candidate_sha,
                    workflow_ref=candidate_ref,
                )
            except PermitInputError as compensation_error:
                raise PermitInputError(
                    "stable bootstrap finalization and candidate compensation both failed: "
                    f"activation={activation_error}; compensation={compensation_error}",
                ) from compensation_error
            raise PermitInputError(
                f"stable bootstrap finalization failed; candidate was restored: {activation_error}",
            ) from activation_error
        validate_ruleset(
            stable_updated.body,
            kind="stable",
            expected_sha=merge_sha,
            expected_ref=MAIN_REF,
        )
        return receipt(
            args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha
        )

    if args.operation == "advance":
        validate_ruleset(
            stable.body, kind="stable", expected_sha=parent_sha, expected_ref=MAIN_REF
        )
        try:
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=candidate_sha,
                expected_ref=candidate_ref,
            )
        except PermitInputError:
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=parent_sha,
                expected_ref=MAIN_REF,
            )
        else:
            return receipt(
                args.operation,
                parent_sha,
                candidate_sha,
                candidate_ref,
                None,
            )
        updated = put_ruleset(
            client,
            candidate,
            workflow_sha=candidate_sha,
            workflow_ref=candidate_ref,
        )
        validate_ruleset(
            updated.body,
            kind="candidate",
            expected_sha=candidate_sha,
            expected_ref=candidate_ref,
        )
        return receipt(args.operation, parent_sha, candidate_sha, candidate_ref, None)

    if args.operation == "restore":
        # A merge SHA admits the exact post-merge state for recovery; it never
        # selects a forward target. Incomplete promotion always returns both
        # rulesets to the last fully observed parent authority.
        merge_sha = (
            require_sha(args.merge_sha, label="merge_sha", length=40)
            if args.merge_sha
            else None
        )
        stable_binding = validate_ruleset_identity(stable.body, kind="stable")
        candidate_binding = validate_ruleset_identity(candidate.body, kind="candidate")
        allowed_stable = {(parent_sha, MAIN_REF)}
        allowed_candidate = {
            (parent_sha, MAIN_REF),
            (candidate_sha, candidate_ref),
        }
        if merge_sha:
            allowed_stable.add((merge_sha, MAIN_REF))
            allowed_candidate.add((merge_sha, MAIN_REF))
        if (stable_binding["sha"], stable_binding["ref"]) not in allowed_stable:
            raise PermitInputError(
                "stable ruleset is outside the restorable generations"
            )
        if (
            candidate_binding["sha"],
            candidate_binding["ref"],
        ) not in allowed_candidate:
            raise PermitInputError(
                "candidate ruleset is outside the restorable generations"
            )
        target_sha = parent_sha
        if (stable_binding["sha"], stable_binding["ref"]) != (target_sha, MAIN_REF):
            stable = put_ruleset(
                client,
                stable,
                workflow_sha=target_sha,
                workflow_ref=MAIN_REF,
            )
            validate_ruleset(
                stable.body,
                kind="stable",
                expected_sha=target_sha,
                expected_ref=MAIN_REF,
            )
        if (candidate_binding["sha"], candidate_binding["ref"]) != (
            target_sha,
            MAIN_REF,
        ):
            candidate = put_ruleset(
                client,
                candidate,
                workflow_sha=target_sha,
                workflow_ref=MAIN_REF,
            )
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=target_sha,
                expected_ref=MAIN_REF,
            )
        return receipt(
            args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha
        )

    merge_sha = require_sha(args.merge_sha, label="merge_sha", length=40)
    if args.operation == "rebind":
        try:
            validate_ruleset(
                stable.body,
                kind="stable",
                expected_sha=merge_sha,
                expected_ref=MAIN_REF,
            )
        except PermitInputError:
            validate_ruleset(
                stable.body,
                kind="stable",
                expected_sha=parent_sha,
                expected_ref=MAIN_REF,
            )
        else:
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=merge_sha,
                expected_ref=MAIN_REF,
            )
            return receipt(
                args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha
            )
        try:
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=merge_sha,
                expected_ref=MAIN_REF,
            )
        except PermitInputError:
            validate_ruleset(
                candidate.body,
                kind="candidate",
                expected_sha=candidate_sha,
                expected_ref=candidate_ref,
            )
        else:
            return receipt(
                args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha
            )
        candidate_updated = put_ruleset(
            client,
            candidate,
            workflow_sha=merge_sha,
            workflow_ref=MAIN_REF,
        )
        validate_ruleset(
            candidate_updated.body,
            kind="candidate",
            expected_sha=merge_sha,
            expected_ref=MAIN_REF,
        )
        return receipt(
            args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha
        )

    try:
        validate_ruleset(
            stable.body,
            kind="stable",
            expected_sha=merge_sha,
            expected_ref=MAIN_REF,
        )
    except PermitInputError:
        validate_ruleset(
            stable.body,
            kind="stable",
            expected_sha=parent_sha,
            expected_ref=MAIN_REF,
        )
    else:
        validate_ruleset(
            candidate.body,
            kind="candidate",
            expected_sha=merge_sha,
            expected_ref=MAIN_REF,
        )
        return receipt(
            args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha
        )
    validate_ruleset(
        candidate.body,
        kind="candidate",
        expected_sha=merge_sha,
        expected_ref=MAIN_REF,
    )
    stable_updated = put_ruleset(
        client,
        stable,
        workflow_sha=merge_sha,
        workflow_ref=MAIN_REF,
    )
    validate_ruleset(
        stable_updated.body,
        kind="stable",
        expected_sha=merge_sha,
        expected_ref=MAIN_REF,
    )
    return receipt(args.operation, parent_sha, candidate_sha, candidate_ref, merge_sha)


def receipt(
    operation: str,
    parent_sha: str,
    candidate_sha: str,
    candidate_ref: str,
    merge_sha: str | None,
) -> dict[str, Any]:
    return {
        "schema": "mindburn.release-authority-ruleset-transition/v1",
        "operation": operation,
        "organization": ORGANIZATION,
        "stable_ruleset_id": STABLE_RULESET_ID,
        "candidate_ruleset_id": CANDIDATE_RULESET_ID,
        "parent_workflow_sha": parent_sha,
        "candidate_workflow_sha": candidate_sha,
        "candidate_workflow_ref": candidate_ref,
        "merged_workflow_sha": merge_sha,
        "public_autonomous_repository_ids": list(PUBLIC_AUTONOMOUS_REPOSITORY_IDS),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation",
        choices=(
            "reconcile",
            "advance",
            "rebind",
            "activate",
            "restore",
            "bootstrap-stage",
            "bootstrap-enforce",
            "bootstrap-finalize",
            "bootstrap-restore",
        ),
    )
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--merge-sha")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        if (
            args.operation in {"reconcile", "rebind", "activate", "bootstrap-finalize"}
            and not args.merge_sha
        ):
            raise PermitInputError(f"{args.operation} requires --merge-sha")
        if (
            args.operation
            in {
                "advance",
                "bootstrap-stage",
                "bootstrap-enforce",
                "bootstrap-restore",
            }
            and args.merge_sha
        ):
            raise PermitInputError(f"--merge-sha is not valid for {args.operation}")
        client = GitHubRulesetClient(
            os.environ.get("GH_TOKEN", ""),
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        result = transition(args, client)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError) as exc:
        print(f"authority-ruleset-broker: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
