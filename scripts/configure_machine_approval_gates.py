#!/usr/bin/env python3
"""Install the machine-approval interlock before retiring public CODEOWNER gates."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
from typing import Any
import urllib.error
import urllib.request

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from authority_ruleset_broker import (
    API_VERSION,
    ORGANIZATION,
    PUBLIC_AUTONOMOUS_REPOSITORY_IDS,
    STABLE_RULESET_ID,
    validate_ref,
    validate_ruleset,
)
from submit_machine_approval import (
    APPROVER_APP_ID,
    APPROVER_INSTALLATION_ID,
    APPROVER_LOGIN,
    SCHEMA as APPROVAL_SCHEMA,
)


BOOTSTRAP_SCHEMA = "mindburn.release-authority-bootstrap/v2"
CONFIGURATION_SCHEMA = "mindburn.release-authority-machine-gates/v1"
HUMAN_RULESET_ID = 17911735
HUMAN_RULESET_NAME = "Mindburn default branch approval gate"
MACHINE_RULESET_NAME = "HELM Machine Approval Interlock"
AUTHORITY_REPOSITORY_ID = 1159255601
KERNEL_REPOSITORY_ID = 1158479649


@dataclass(frozen=True)
class AdminResponse:
    body: Any
    etag: str | None


class GitHubAdminClient:
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
    ) -> AdminResponse:
        content = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
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
                raw = response.read()
                etag = response.headers.get("ETag")
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            if exc.code == 412:
                raise PermitInputError(f"GitHub rejected stale state for {path}") from exc
            raise PermitInputError(
                f"GitHub {method} {path} failed with HTTP {exc.code}: {detail}",
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PermitInputError(f"GitHub {method} {path} failed: {exc}") from exc
        if not raw:
            return AdminResponse(None, etag)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermitInputError(f"GitHub {method} {path} returned invalid JSON") from exc
        return AdminResponse(value, etag)


def require_object(response: AdminResponse, *, label: str) -> dict[str, Any]:
    if not isinstance(response.body, dict):
        raise PermitInputError(f"{label} returned no object")
    return response.body


def load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def load_contract(path: Path) -> dict[str, Any]:
    value = load_json(path, label="bootstrap contract")
    require_exact_keys(
        value,
        required={
            "schema",
            "approver",
            "machine_approval_ruleset",
            "human_approval_ruleset",
            "classic_branch_protection",
        },
        label="bootstrap contract",
    )
    if value["schema"] != BOOTSTRAP_SCHEMA:
        raise PermitInputError("unsupported bootstrap contract schema")

    approver = value["approver"]
    if approver != {
        "app_id": APPROVER_APP_ID,
        "installation_id": APPROVER_INSTALLATION_ID,
        "login": APPROVER_LOGIN,
        "slug": "helm-authority-approver",
        "organization": ORGANIZATION,
        "permission": {"pull_requests": "write"},
    }:
        raise PermitInputError("bootstrap contract names the wrong approver")

    machine = value["machine_approval_ruleset"]
    if not isinstance(machine, dict):
        raise PermitInputError("machine approval ruleset contract must be an object")
    if machine != machine_ruleset_payload():
        raise PermitInputError("machine approval ruleset contract is not exact")

    human = value["human_approval_ruleset"]
    if not isinstance(human, dict):
        raise PermitInputError("human approval ruleset contract must be an object")
    require_exact_keys(
        human,
        required={
            "id",
            "name",
            "before_repository_ids",
            "after_repository_ids",
            "remove_repository_ids",
            "rules",
        },
        label="human approval ruleset contract",
    )
    before = human["before_repository_ids"]
    after = human["after_repository_ids"]
    remove = human["remove_repository_ids"]
    for ids, label in ((before, "before"), (after, "after"), (remove, "remove")):
        if (
            not isinstance(ids, list)
            or any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in ids)
            or ids != sorted(set(ids))
        ):
            raise PermitInputError(f"bootstrap {label} repository IDs are invalid")
    if human["id"] != HUMAN_RULESET_ID or human["name"] != HUMAN_RULESET_NAME:
        raise PermitInputError("bootstrap contract names the wrong human ruleset")
    if set(remove) != {AUTHORITY_REPOSITORY_ID, KERNEL_REPOSITORY_ID}:
        raise PermitInputError("bootstrap retires the wrong CODEOWNER-gated repositories")
    if set(remove) - set(PUBLIC_AUTONOMOUS_REPOSITORY_IDS):
        raise PermitInputError("bootstrap retirement is outside public machine coverage")
    if after != [repository_id for repository_id in before if repository_id not in remove]:
        raise PermitInputError("bootstrap post-retirement repository IDs are not exact")
    if not isinstance(human["rules"], list) or not human["rules"]:
        raise PermitInputError("bootstrap human rules must be a non-empty list")

    classic = value["classic_branch_protection"]
    if not isinstance(classic, dict):
        raise PermitInputError("classic branch protection contract must be an object")
    require_exact_keys(
        classic,
        required={"repository", "branch", "expected"},
        label="classic branch protection contract",
    )
    if classic["repository"] != "Mindburn-Labs/.github" or classic["branch"] != "main":
        raise PermitInputError("bootstrap contract names the wrong protected branch")
    reviews = classic["expected"].get("required_pull_request_reviews")
    if not isinstance(reviews, dict) or reviews.get("required_approving_review_count") != 1:
        raise PermitInputError("classic protection must retain one required approval")
    return value


def machine_ruleset_payload() -> dict[str, Any]:
    return {
        "name": MACHINE_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
            "repository_id": {
                "repository_ids": list(PUBLIC_AUTONOMOUS_REPOSITORY_IDS),
            },
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["merge", "squash", "rebase"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_last_push_approval": True,
                    "required_approving_review_count": 1,
                    "required_review_thread_resolution": True,
                    "required_reviewers": [],
                },
            },
        ],
    }


def human_ruleset_state(contract: dict[str, Any], state: str) -> dict[str, Any]:
    human = contract["human_approval_ruleset"]
    return {
        "name": human["name"],
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
            "repository_id": {"repository_ids": human[f"{state}_repository_ids"]},
        },
        "rules": human["rules"],
    }


def controlled_ruleset(ruleset: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ruleset.get(key)
        for key in ("name", "target", "enforcement", "bypass_actors", "conditions", "rules")
    }


def boolean_setting(protection: dict[str, Any], key: str) -> bool | None:
    value = protection.get(key)
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        raise PermitInputError(f"classic protection {key} is malformed")
    return value["enabled"]


def normalize_classic_protection(protection: dict[str, Any]) -> dict[str, Any]:
    reviews = protection.get("required_pull_request_reviews")
    if reviews is not None:
        if not isinstance(reviews, dict):
            raise PermitInputError("classic required pull request reviews are malformed")
        reviews = {
            key: reviews.get(key)
            for key in (
                "dismiss_stale_reviews",
                "require_code_owner_reviews",
                "require_last_push_approval",
                "required_approving_review_count",
            )
        }
    return {
        "allow_deletions": boolean_setting(protection, "allow_deletions"),
        "allow_force_pushes": boolean_setting(protection, "allow_force_pushes"),
        "allow_fork_syncing": boolean_setting(protection, "allow_fork_syncing"),
        "block_creations": boolean_setting(protection, "block_creations"),
        "enforce_admins": boolean_setting(protection, "enforce_admins"),
        "lock_branch": boolean_setting(protection, "lock_branch"),
        "required_conversation_resolution": boolean_setting(
            protection,
            "required_conversation_resolution",
        ),
        "required_linear_history": boolean_setting(protection, "required_linear_history"),
        "required_pull_request_reviews": reviews,
        "required_signatures": boolean_setting(protection, "required_signatures"),
        "required_status_checks": protection.get("required_status_checks"),
        "restrictions": protection.get("restrictions"),
    }


def validate_approval(
    path: Path,
    *,
    candidate_sha: str,
    pull_request: int,
) -> dict[str, Any]:
    approval = load_json(path, label="machine approval receipt")
    if (
        approval.get("schema") != APPROVAL_SCHEMA
        or approval.get("repository") != "Mindburn-Labs/.github"
        or approval.get("pull_request") != pull_request
        or approval.get("head_sha") != candidate_sha
        or approval.get("review_state") != "APPROVED"
        or approval.get("approver_login") != APPROVER_LOGIN
        or not isinstance(approval.get("review_id"), int)
    ):
        raise PermitInputError("machine approval receipt is not exact")
    return approval


def ensure_machine_ruleset(client: GitHubAdminClient) -> dict[str, Any]:
    response = client.request("GET", f"/orgs/{ORGANIZATION}/rulesets?per_page=100")
    if not isinstance(response.body, list):
        raise PermitInputError("GitHub ruleset list is malformed")
    matches = [
        item
        for item in response.body
        if isinstance(item, dict) and item.get("name") == MACHINE_RULESET_NAME
    ]
    if len(matches) > 1:
        raise PermitInputError("multiple machine approval rulesets exist")
    if not matches:
        created = require_object(
            client.request(
                "POST",
                f"/orgs/{ORGANIZATION}/rulesets",
                payload=machine_ruleset_payload(),
            ),
            label="created machine approval ruleset",
        )
        ruleset_id = created.get("id")
    else:
        ruleset_id = matches[0].get("id")
    if not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise PermitInputError("machine approval ruleset ID is invalid")
    current = require_object(
        client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}"),
        label="machine approval ruleset",
    )
    if controlled_ruleset(current) != machine_ruleset_payload():
        raise PermitInputError("machine approval ruleset is not exact and active")
    return current


def configure_machine_approval_gates(
    args: argparse.Namespace,
    client: GitHubAdminClient,
) -> dict[str, Any]:
    candidate_sha = require_sha(args.candidate_sha, label="candidate_sha", length=40)
    candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    approved_head_sha = require_sha(
        getattr(args, "approved_head_sha", None) or candidate_sha,
        label="approved_head_sha",
        length=40,
    )
    contract = load_contract(args.contract)
    approval = validate_approval(
        args.approval_receipt,
        candidate_sha=approved_head_sha,
        pull_request=args.pull_request,
    )

    stable = require_object(
        client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{STABLE_RULESET_ID}"),
        label="stable machine workflow ruleset",
    )
    validate_ruleset(
        stable,
        kind="stable",
        expected_sha=candidate_sha,
        expected_ref=candidate_ref,
    )

    machine = ensure_machine_ruleset(client)
    machine_id = machine["id"]

    classic = contract["classic_branch_protection"]
    branch_path = f"/repos/{classic['repository']}/branches/{classic['branch']}/protection"
    protection = require_object(
        client.request("GET", branch_path),
        label="classic branch protection",
    )
    if normalize_classic_protection(protection) != classic["expected"]:
        raise PermitInputError("classic branch protection did not retain its approval interlock")

    human_path = f"/orgs/{ORGANIZATION}/rulesets/{HUMAN_RULESET_ID}"
    human_response = client.request("GET", human_path)
    human = require_object(human_response, label="human CODEOWNER ruleset")
    if human.get("id") != HUMAN_RULESET_ID:
        raise PermitInputError("GitHub returned the wrong human ruleset")
    before_human = human_ruleset_state(contract, "before")
    after_human = human_ruleset_state(contract, "after")
    human_state = controlled_ruleset(human)
    if human_state == before_human:
        if not human_response.etag:
            raise PermitInputError("human ruleset GET did not return an ETag")
        refetched = client.request("GET", human_path)
        if refetched.body != human or refetched.etag != human_response.etag:
            raise PermitInputError("human ruleset changed before machine-gate cutover")
        client.request(
            "PUT",
            human_path,
            payload=after_human,
            if_match=human_response.etag,
        )
        human = require_object(client.request("GET", human_path), label="human ruleset")
        human_state = controlled_ruleset(human)
    if human_state != after_human:
        raise PermitInputError("human ruleset is outside the exact before/after states")

    return {
        "schema": CONFIGURATION_SCHEMA,
        "machine_workflow_ruleset_id": STABLE_RULESET_ID,
        "machine_workflow_sha": candidate_sha,
        "machine_workflow_ref": candidate_ref,
        "machine_approval_ruleset_id": machine_id,
        "machine_approval_review_id": approval["review_id"],
        "machine_approval_head_sha": approved_head_sha,
        "approver_login": APPROVER_LOGIN,
        "human_codeowner_ruleset_id": HUMAN_RULESET_ID,
        "human_codeowner_repository_ids": after_human["conditions"]["repository_id"][
            "repository_ids"
        ],
        "retired_codeowner_repository_ids": contract["human_approval_ruleset"][
            "remove_repository_ids"
        ],
        "classic_repository": classic["repository"],
        "classic_branch": classic["branch"],
        "classic_required_approving_review_count": 1,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--approved-head-sha")
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--approval-receipt", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        receipt = configure_machine_approval_gates(
            args,
            GitHubAdminClient(
                os.environ.get("GH_TOKEN", ""),
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            ),
        )
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"configure-machine-approval-gates: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
