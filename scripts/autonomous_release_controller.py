#!/usr/bin/env python3
"""Plan, approve, and merge ordinary public PRs without human authorization."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path, PurePosixPath
import sys
import time
from typing import Any
import urllib.parse
import zipfile

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from submit_machine_approval import (
    APPROVER_APP_ID,
    APPROVER_INSTALLATION_ID,
    APPROVER_LOGIN,
    APPROVER_SLUG,
    GitHubApprovalClient,
    submit_machine_approval,
)
from authority_ruleset_broker import (
    AUTHORITY_REPOSITORY_ID,
    MAIN_REF,
    STABLE_RULESET_ID,
)
from observe_authority_promotion import (
    PUBLIC_STABLE_REPOSITORIES,
    observe_effective_stable_rules,
)
from verify_authority_promotion import validate_authority_shape, validate_permit
from wait_for_authority_canary import (
    WORKFLOW_NAME,
    WORKFLOW_PATH,
    GitHubReadClient,
    load_json_file,
    require_get_forbidden,
    run_sort_key,
    artifact_for_run,
    verify_candidate_permit,
    verify_attestation,
    verify_permit_reduction,
    verify_run_workflow_provenance,
)
from wait_for_authority_suite import write_attested_case


CONTRACT_SCHEMA = "mindburn.autonomous-release-controller/v1"
STATUS_SCHEMA = "mindburn.autonomous-release-controller-status/v1"
DISCOVERY_SCHEMA = "mindburn.autonomous-release-controller-discovery/v1"
PLAN_SCHEMA = "mindburn.autonomous-release-plan/v1"
APPROVAL_SCHEMA = "mindburn.autonomous-release-approvals/v1"
MERGE_SCHEMA = "mindburn.autonomous-release-merge/v1"
PROMOTION_WORKFLOW_NAME = "Promote HELM Release Authority"
PROMOTION_WORKFLOW_PATH = ".github/workflows/promote-authority.yml"
PROMOTION_RECEIPT_ARTIFACT = "helm-authority-promotion-receipt"
PROMOTION_RECEIPT_SCHEMA = "mindburn.release-authority-observer-receipt/v3"
ORGANIZATION = "Mindburn-Labs"
AUTHORITY_REPOSITORY = "Mindburn-Labs/.github"
SELECTED_REPOSITORIES = {
    "Mindburn-Labs/.github",
    "Mindburn-Labs/helm-ai-kernel",
    "Mindburn-Labs/contracts-autonomous-release-lab",
}
MERGE_METHODS = {"merge", "squash", "rebase"}
UPDATE_REFS_MUTATION = """
mutation($repositoryId: ID!, $beforeOid: GitObjectID!, $afterOid: GitObjectID!) {
  updateRefs(input: {
    repositoryId: $repositoryId,
    refUpdates: [{
      name: "refs/heads/main",
      beforeOid: $beforeOid,
      afterOid: $afterOid,
      force: false
    }]
  }) { clientMutationId }
}
"""
REPOSITORY_ID_QUERY = """
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) { id }
}
"""
AUTHORITY_EXACT_PATHS = {
    "Makefile",
    "config/autonomous-release-authority.json",
    "config/autonomous-release-bootstrap-v1.json",
    "config/autonomous-release-ci-template.yml",
    "config/autonomous-release-controller.json",
    "config/autonomous-release-control-plane.json",
    "config/autonomous-release-gates.json",
    "tests/fixtures/autonomous-release-adversarial.json",
}
AUTHORITY_SCRIPT_PREFIXES = (
    "scripts/atomic_merge_authority.py",
    "scripts/authority_",
    "scripts/autonomous_release_",
    "scripts/bootstrap_authority.py",
    "scripts/configure_machine_approval_gates.py",
    "scripts/observe_authority_promotion.py",
    "scripts/run_autonomous_release_gates.py",
    "scripts/submit_machine_approval.py",
    "scripts/verify_authority_promotion.py",
    "scripts/verify_control_plane.py",
    "scripts/wait_for_authority_",
)


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def positive_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PermitInputError(f"{label} must be a positive integer")
    return value


def validate_contract(value: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        value,
        required={"schema", "enabled", "apps", "repositories"},
        label="controller contract",
    )
    if value["schema"] != CONTRACT_SCHEMA or not isinstance(value["enabled"], bool):
        raise PermitInputError("unsupported controller contract")
    apps = value["apps"]
    if not isinstance(apps, dict):
        raise PermitInputError("controller apps must be an object")
    require_exact_keys(
        apps,
        required={"observer", "approver", "merger"},
        label="controller apps",
    )
    expected_apps = {
        "observer": ("helm-authority-observer", 4296957, 146542079),
        "approver": (APPROVER_SLUG, APPROVER_APP_ID, APPROVER_INSTALLATION_ID),
    }
    for name, (slug, app_id, installation_id) in expected_apps.items():
        app = apps[name]
        if not isinstance(app, dict):
            raise PermitInputError(f"controller {name} App must be an object")
        require_exact_keys(
            app,
            required={"slug", "app_id", "installation_id"},
            label=f"controller {name} App",
        )
        if app != {
            "slug": slug,
            "app_id": app_id,
            "installation_id": installation_id,
        }:
            raise PermitInputError(f"controller {name} App identity drifted")
    merger = apps["merger"]
    if not isinstance(merger, dict):
        raise PermitInputError("controller merger App must be an object")
    require_exact_keys(
        merger,
        required={"slug", "app_id", "installation_id"},
        label="controller merger App",
    )
    if merger.get("slug") != "helm-authority-merger":
        raise PermitInputError("controller merger App slug drifted")
    if value["enabled"]:
        positive_integer(merger.get("app_id"), label="merger app_id")
        positive_integer(merger.get("installation_id"), label="merger installation_id")
    elif merger.get("app_id") is not None or merger.get("installation_id") is not None:
        raise PermitInputError("disabled controller must not declare merger authority")

    repositories = value["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 3:
        raise PermitInputError(
            "controller must define exactly three public repositories"
        )
    observed: set[str] = set()
    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            raise PermitInputError(f"controller repository {index} must be an object")
        require_exact_keys(
            repository,
            required={"repository", "merge_method", "authority_changes"},
            label=f"controller repository {index}",
        )
        name = repository["repository"]
        if name in observed or name not in SELECTED_REPOSITORIES:
            raise PermitInputError("controller repository allowlist is not exact")
        observed.add(name)
        if repository["merge_method"] not in MERGE_METHODS:
            raise PermitInputError("controller merge method is invalid")
        if repository["merge_method"] != "merge":
            raise PermitInputError(
                "controller requires exact reviewed merge commits for atomic base CAS"
            )
        expected_classification = {
            AUTHORITY_REPOSITORY: "promotion-only",
            "Mindburn-Labs/contracts-autonomous-release-lab": "proof-only",
        }.get(name, "not-applicable")
        if repository["authority_changes"] != expected_classification:
            raise PermitInputError("controller authority classification drifted")
    if observed != SELECTED_REPOSITORIES:
        raise PermitInputError("controller repository allowlist is incomplete")
    return value


def require_enabled(contract: dict[str, Any]) -> None:
    if contract["enabled"] is not True:
        raise PermitInputError(
            "autonomous controller remains fail-closed until the distinct merger App is live"
        )


def contract_status(args: argparse.Namespace) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    merger = contract["apps"]["merger"]
    return {
        "schema": STATUS_SCHEMA,
        "enabled": contract["enabled"],
        "merger_configured": (
            isinstance(merger["app_id"], int)
            and not isinstance(merger["app_id"], bool)
            and merger["app_id"] > 0
            and isinstance(merger["installation_id"], int)
            and not isinstance(merger["installation_id"], bool)
            and merger["installation_id"] > 0
        ),
        "repositories": [item["repository"] for item in contract["repositories"]],
    }


def verify_observer_installation(
    client: GitHubReadClient,
    *,
    contract: dict[str, Any],
) -> None:
    expected = contract["apps"]["observer"]
    installation = client.get_json("/installation")
    account = installation.get("account")
    if (
        installation.get("app_id") != expected["app_id"]
        or installation.get("id") != expected["installation_id"]
        or installation.get("permissions")
        != {
            "actions": "read",
            "attestations": "read",
            "contents": "read",
            "pull_requests": "read",
        }
        or not isinstance(account, dict)
        or account.get("login") != ORGANIZATION
    ):
        raise PermitInputError("observer App identity or permissions drifted")
    repositories = client.get_json("/installation/repositories?per_page=100")
    items = repositories.get("repositories")
    if (
        not isinstance(items, list)
        or {item.get("full_name") for item in items if isinstance(item, dict)}
        != SELECTED_REPOSITORIES
    ):
        raise PermitInputError("observer App repository scope is not exact")
    require_get_forbidden(
        client,
        f"/orgs/{ORGANIZATION}/rulesets/{STABLE_RULESET_ID}",
        label="ordinary controller observer organization-ruleset scope",
    )


def verify_repository_settings(
    client: GitHubReadClient,
    *,
    repository: str,
    merge_method: str,
) -> None:
    value = client.get_json(f"/repos/{repository}")
    expected_flag = {
        "merge": "allow_merge_commit",
        "squash": "allow_squash_merge",
        "rebase": "allow_rebase_merge",
    }[merge_method]
    if (
        value.get("full_name") != repository
        or value.get("default_branch") != "main"
        or value.get("archived") is True
        or value.get("visibility") != "public"
        or value.get(expected_flag) is not True
    ):
        raise PermitInputError(
            f"{repository} settings are incompatible with atomic {merge_method}"
        )


def is_authority_path(path: str) -> bool:
    if path in AUTHORITY_EXACT_PATHS or path.startswith(".github/workflows/"):
        return True
    if path.startswith("tools/offline-attest/"):
        return True
    if any(path.startswith(prefix) for prefix in AUTHORITY_SCRIPT_PREFIXES):
        return True
    return path.startswith("tests/test_") and any(
        marker in path
        for marker in (
            "authority",
            "autonomous_release",
            "configure_machine",
            "submit_machine",
            "verify_control_plane",
        )
    )


def nested_string(value: dict[str, Any], *keys: str, label: str) -> str:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            raise PermitInputError(f"GitHub response is missing {label}")
        current = current.get(key)
    if not isinstance(current, str) or not current:
        raise PermitInputError(f"GitHub response has invalid {label}")
    return current


def get_json_value(client: GitHubReadClient, path: str, *, label: str) -> Any:
    try:
        text = client.get_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    return parse_json_strict(text, label=label)


def discover_effective_workflow_sha(client: GitHubReadClient) -> str:
    observed: set[str] = set()
    for repository in PUBLIC_STABLE_REPOSITORIES:
        rules = get_json_value(
            client,
            f"/repos/{repository}/rules/branches/main",
            label=f"effective rules for {repository}",
        )
        if not isinstance(rules, list):
            raise PermitInputError(f"effective rules for {repository} are malformed")
        matches = [
            rule
            for rule in rules
            if isinstance(rule, dict)
            and rule.get("ruleset_id") == STABLE_RULESET_ID
            and rule.get("ruleset_source_type") == "Organization"
            and rule.get("ruleset_source") == ORGANIZATION
            and rule.get("type") == "workflows"
        ]
        if len(matches) != 1:
            raise PermitInputError(
                f"{repository} does not expose one source-owned stable workflow rule"
            )
        parameters = matches[0].get("parameters")
        workflows = (
            parameters.get("workflows") if isinstance(parameters, dict) else None
        )
        if (
            not isinstance(parameters, dict)
            or parameters.get("do_not_enforce_on_create") is not False
            or not isinstance(workflows, list)
            or len(workflows) != 1
            or not isinstance(workflows[0], dict)
            or workflows[0].get("path") != WORKFLOW_PATH
            or workflows[0].get("ref") != MAIN_REF
            or workflows[0].get("repository_id") != AUTHORITY_REPOSITORY_ID
        ):
            raise PermitInputError(f"{repository} stable workflow parameters drifted")
        observed.add(
            require_sha(
                workflows[0].get("sha"),
                label=f"{repository} active workflow SHA",
                length=40,
            )
        )
    if len(observed) != 1:
        raise PermitInputError(
            "public repositories disagree on active release authority"
        )
    return observed.pop()


def discover(args: argparse.Namespace, client: GitHubReadClient) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    verify_observer_installation(client, contract=contract)
    active_workflow_sha = discover_effective_workflow_sha(client)
    observe_effective_stable_rules(client, workflow_sha=active_workflow_sha)
    authority = head_authority(client, head_sha=active_workflow_sha)
    return {
        "schema": DISCOVERY_SCHEMA,
        "control_sha": control_sha,
        "active_workflow_sha": active_workflow_sha,
        "generation": authority["generation"],
        "kernel_sha": authority["kernel_sha"],
    }


def changed_paths(
    client: GitHubReadClient,
    repository: str,
    pull_request: int,
) -> list[str]:
    result: list[str] = []
    for page in range(1, 6):
        payload = get_json_value(
            client,
            f"/repos/{repository}/pulls/{pull_request}/files?per_page=100&page={page}",
            label="pull request files",
        )
        if not isinstance(payload, list):
            raise PermitInputError("pull request files response is malformed")
        for item in payload:
            if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
                raise PermitInputError("pull request file entry is malformed")
            status = item.get("status")
            if status not in {
                "added",
                "modified",
                "removed",
                "renamed",
                "copied",
                "changed",
            }:
                raise PermitInputError("pull request file status is invalid")
            paths = [item["filename"]]
            if status == "renamed":
                previous = item.get("previous_filename")
                if not isinstance(previous, str):
                    raise PermitInputError("renamed file lacks its previous path")
                paths.append(previous)
            for path in paths:
                pure = PurePosixPath(path)
                if pure.is_absolute() or ".." in pure.parts or "\\" in path:
                    raise PermitInputError("pull request file path is invalid")
                result.append(path)
        if len(payload) < 100:
            return result
    raise PermitInputError("pull request changed-file list exceeds controller bound")


def open_pull_requests(
    client: GitHubReadClient,
    repository: str,
) -> list[dict[str, Any]]:
    payload = get_json_value(
        client,
        f"/repos/{repository}/pulls?state=open&base=main&per_page=100",
        label="open pull requests",
    )
    if not isinstance(payload, list):
        raise PermitInputError("open pull request response is malformed")
    return [item for item in payload if isinstance(item, dict)]


def pull_requests_for_commit(
    client: GitHubReadClient,
    repository: str,
    commit_sha: str,
) -> list[dict[str, Any]]:
    payload = get_json_value(
        client,
        f"/repos/{repository}/commits/{commit_sha}/pulls?per_page=100",
        label="commit pull requests",
    )
    if not isinstance(payload, list):
        raise PermitInputError("commit pull request response is malformed")
    return [item for item in payload if isinstance(item, dict)]


def newest_run(
    client: GitHubReadClient,
    repository: str,
    head_sha: str,
    workflow_sha: str,
) -> tuple[dict[str, Any] | None, str | None]:
    query = urllib.parse.urlencode(
        {"event": "pull_request", "head_sha": head_sha, "per_page": 100}
    )
    payload = client.get_json(f"/repos/{repository}/actions/runs?{query}")
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise PermitInputError("workflow runs response is malformed")
    matching = [
        run
        for run in runs
        if isinstance(run, dict)
        and isinstance(run.get("id"), int)
        and run.get("name") == WORKFLOW_NAME
        and run.get("path") == WORKFLOW_PATH
        and run.get("head_sha") == head_sha
    ]
    matching.sort(key=run_sort_key, reverse=True)
    if not matching:
        return None, "NO_WORKFLOW_RUN"
    run = matching[0]
    provenance = verify_run_workflow_provenance(
        client,
        repository,
        run,
        head_sha=head_sha,
        expected_workflow_sha=workflow_sha,
    )
    if provenance is None:
        return None, "NEWEST_RUN_HAS_NO_PROVENANCE"
    if not provenance["is_expected_workflow"]:
        return None, "NEWEST_RUN_USES_DIFFERENT_AUTHORITY"
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return None, "NEWEST_EXACT_RUN_NOT_SUCCESSFUL"
    return run, None


def validate_live_pull_request(
    value: dict[str, Any],
    *,
    repository: str,
    pull_request: int,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> tuple[str, str]:
    observed_base = nested_string(value, "base", "sha", label="pull request base SHA")
    observed_head = nested_string(value, "head", "sha", label="pull request head SHA")
    if (
        value.get("number") != pull_request
        or value.get("state") != "open"
        or value.get("merged") is True
        or value.get("draft") is True
        or nested_string(value, "base", "ref", label="pull request base ref") != "main"
        or nested_string(
            value, "head", "repo", "full_name", label="pull request head repository"
        )
        != repository
        or (base_sha is not None and observed_base != base_sha)
        or (head_sha is not None and observed_head != head_sha)
    ):
        raise PermitInputError(
            "pull request is outside the autonomous controller contract"
        )
    return observed_base, observed_head


def validate_merged_pull_request(
    value: dict[str, Any],
    *,
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    merge_sha: str,
) -> None:
    if (
        value.get("number") != pull_request
        or value.get("state") != "closed"
        or value.get("merged") is not True
        or value.get("draft") is True
        or value.get("merge_commit_sha") != merge_sha
        or nested_string(value, "base", "ref", label="pull request base ref") != "main"
        or nested_string(value, "base", "sha", label="pull request base SHA")
        != base_sha
        or nested_string(value, "head", "sha", label="pull request head SHA")
        != head_sha
        or nested_string(
            value, "head", "repo", "full_name", label="pull request head repository"
        )
        != repository
    ):
        raise PermitInputError(
            "merged pull request differs from the signed controller plan"
        )


def head_authority(
    client: GitHubReadClient,
    *,
    head_sha: str,
) -> dict[str, Any]:
    raw = client.get_bytes(
        "/repos/Mindburn-Labs/.github/contents/"
        f"config/autonomous-release-authority.json?ref={head_sha}",
        accept="application/vnd.github.raw+json",
    )
    try:
        value = parse_json_strict(raw.decode("utf-8"), label="candidate authority")
    except UnicodeDecodeError as exc:
        raise PermitInputError("candidate authority is not UTF-8") from exc
    return validate_authority_shape(value, label="candidate authority")


def verified_plan_entry(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    workflow_sha: str,
    repository_config: dict[str, Any],
    pull_request: int,
    base_sha: str,
    head_sha: str,
    run: dict[str, Any],
    recovery: bool,
) -> dict[str, Any]:
    repository = repository_config["repository"]
    repository_slug = {
        AUTHORITY_REPOSITORY: "github-authority",
        "Mindburn-Labs/helm-ai-kernel": "helm-ai-kernel",
        "Mindburn-Labs/contracts-autonomous-release-lab": "release-lab",
    }[repository]
    evidence = args.output_dir / "evidence" / repository_slug / str(pull_request)
    permit_path, bundle_path, context_path, reviews = write_attested_case(
        client,
        repository,
        run["id"],
        evidence,
    )
    permit = verify_candidate_permit(
        permit_path,
        bundle_path,
        context_path,
        run=run,
        repository=repository,
        pull_request=pull_request,
        head_sha=head_sha,
        expected_workflow_sha=workflow_sha,
        expected_authority=authority,
        kernel_verifier=args.kernel_verifier,
        attestation_token=client.token,
    )
    verify_permit_reduction(
        args.kernel_verifier,
        permit_path,
        context_path,
        reviews,
        evidence / "parent-controller-permit.json",
    )
    if permit["base_sha"] != base_sha:
        raise PermitInputError("permit base moved before controller planning")
    return {
        "repository": repository,
        "pull_request": pull_request,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_sha": permit["merge_sha"],
        "merge_tree_sha": permit["merge_tree_sha"],
        "permit_id": permit["permit_id"],
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "workflow_sha": workflow_sha,
        "evidence": evidence.relative_to(args.output_dir).as_posix(),
        "merge_method": repository_config["merge_method"],
        "recovery": recovery,
    }


def extract_final_promotion_receipt(archive: bytes) -> tuple[bytes, bytes]:
    receipt_name = "final-observer-receipt.json"
    bundle_name = "final-observer-receipt.attestation.json"
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            names = {entry.filename for entry in entries}
            if (
                len(entries) > 256
                or receipt_name not in names
                or bundle_name not in names
                or any(
                    (not entry.is_dir() and entry.file_size <= 0)
                    or entry.file_size > 2 * 1024 * 1024
                    or PurePosixPath(entry.filename).is_absolute()
                    or ".." in PurePosixPath(entry.filename).parts
                    or "\\" in entry.filename
                    or (
                        entry.filename not in {receipt_name, bundle_name}
                        and not entry.filename.startswith("observer-replay-final/")
                    )
                    for entry in entries
                )
            ):
                raise PermitInputError("final promotion receipt artifact is malformed")
            by_name = {entry.filename: entry for entry in entries}
            return bundle.read(by_name[receipt_name]), bundle.read(by_name[bundle_name])
    except zipfile.BadZipFile as exc:
        raise PermitInputError("final promotion receipt is not a ZIP archive") from exc


def has_final_promotion_closure(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    control_sha: str,
    active_workflow_sha: str,
) -> bool:
    query = urllib.parse.urlencode(
        {"event": "workflow_dispatch", "status": "completed", "per_page": 100}
    )
    payload = client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/actions/workflows/"
        f"promote-authority.yml/runs?{query}"
    )
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise PermitInputError("promotion workflow runs response is malformed")
    candidates = [
        run
        for run in runs
        if isinstance(run, dict)
        and isinstance(run.get("id"), int)
        and run.get("name") == PROMOTION_WORKFLOW_NAME
        and run.get("path") == PROMOTION_WORKFLOW_PATH
        and run.get("head_sha") == control_sha
        and run.get("event") == "workflow_dispatch"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
    ]
    candidates.sort(key=run_sort_key, reverse=True)
    for run in candidates:
        artifact_id = artifact_for_run(
            client,
            AUTHORITY_REPOSITORY,
            run["id"],
            PROMOTION_RECEIPT_ARTIFACT,
        )
        if artifact_id is None:
            continue
        receipt_bytes, bundle_bytes = extract_final_promotion_receipt(
            client.get_bytes(
                f"/repos/{AUTHORITY_REPOSITORY}/actions/artifacts/{artifact_id}/zip",
                accept="application/vnd.github+json",
            )
        )
        try:
            receipt = parse_json_strict(
                receipt_bytes.decode("utf-8"), label="final promotion receipt"
            )
        except UnicodeDecodeError as exc:
            raise PermitInputError("final promotion receipt is not UTF-8") from exc
        if not isinstance(receipt, dict):
            raise PermitInputError("final promotion receipt must be an object")
        if (
            receipt.get("schema") != PROMOTION_RECEIPT_SCHEMA
            or receipt.get("phase") != "final"
            or receipt.get("decision") != "ALLOW"
            or receipt.get("control_workflow_sha") != control_sha
            or receipt.get("merged_workflow_sha") != active_workflow_sha
            or receipt.get("candidate_generation") != authority["generation"]
            or receipt.get("promotion_run_id") != run["id"]
            or receipt.get("promotion_run_attempt") != run.get("run_attempt")
        ):
            continue
        closure = args.output_dir / "evidence" / "authority-closure" / str(run["id"])
        closure.mkdir(parents=True, exist_ok=False)
        receipt_path = closure / "final-observer-receipt.json"
        bundle_path = closure / "final-observer-receipt.attestation.json"
        receipt_path.write_bytes(receipt_bytes)
        bundle_path.write_bytes(bundle_bytes)
        verify_attestation(
            receipt_path,
            bundle_path,
            repository=AUTHORITY_REPOSITORY,
            workflow_sha=control_sha,
            source_sha=control_sha,
            github_token=client.token,
            signer_workflow=f"Mindburn-Labs/.github/{PROMOTION_WORKFLOW_PATH}",
        )
        return True
    return False


def verified_activated_recovery_entry(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    control_sha: str,
    active_workflow_sha: str,
    repository_config: dict[str, Any],
) -> dict[str, Any]:
    parent_sha = authority["parent"]["workflow_sha"]
    parent_authority = head_authority(client, head_sha=parent_sha)
    matches: list[dict[str, Any]] = []
    for pull_request_value in pull_requests_for_commit(
        client, AUTHORITY_REPOSITORY, active_workflow_sha
    ):
        number = pull_request_value.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        try:
            validate_merged_pull_request(
                pull_request_value,
                repository=AUTHORITY_REPOSITORY,
                pull_request=number,
                base_sha=parent_sha,
                head_sha=nested_string(
                    pull_request_value,
                    "head",
                    "sha",
                    label="activated successor head SHA",
                ),
                merge_sha=active_workflow_sha,
            )
            head_sha = nested_string(
                pull_request_value,
                "head",
                "sha",
                label="activated successor head SHA",
            )
            if head_authority(client, head_sha=head_sha) != authority:
                continue
            run, reason = newest_run(client, AUTHORITY_REPOSITORY, head_sha, parent_sha)
            if run is None:
                raise PermitInputError(
                    f"activated successor lacks its exact parent permit run: {reason}"
                )
            evidence = (
                args.output_dir
                / "evidence"
                / "github-authority-activated-recovery"
                / str(number)
            )
            permit_path, bundle_path, _, _ = write_attested_case(
                client, AUTHORITY_REPOSITORY, run["id"], evidence
            )
            permit = load_json_file(permit_path, label="activated recovery permit")
            if validate_permit(permit) != parent_authority:
                raise PermitInputError("activated recovery permit authority drifted")
            expected = {
                "repository": AUTHORITY_REPOSITORY,
                "pull_request": number,
                "base_sha": parent_sha,
                "head_sha": head_sha,
                "merge_sha": active_workflow_sha,
                "workflow_sha": parent_sha,
                "run_id": run["id"],
                "run_attempt": run["run_attempt"],
            }
            for field, expected_value in expected.items():
                if permit.get(field) != expected_value:
                    raise PermitInputError(
                        f"activated recovery permit {field} is not exact"
                    )
            verify_attestation(
                permit_path,
                bundle_path,
                repository=AUTHORITY_REPOSITORY,
                workflow_sha=parent_sha,
                source_sha=active_workflow_sha,
                github_token=client.token,
            )
            matches.append(
                {
                    "repository": AUTHORITY_REPOSITORY,
                    "pull_request": number,
                    "base_sha": parent_sha,
                    "head_sha": head_sha,
                    "merge_sha": active_workflow_sha,
                    "merge_tree_sha": permit["merge_tree_sha"],
                    "permit_id": permit["permit_id"],
                    "run_id": run["id"],
                    "run_attempt": run["run_attempt"],
                    "workflow_sha": parent_sha,
                    "evidence": evidence.relative_to(args.output_dir).as_posix(),
                    "merge_method": repository_config["merge_method"],
                    "recovery": True,
                }
            )
        except (OSError, PermitInputError) as exc:
            raise PermitInputError(
                f"activated authority recovery validation failed: {exc}"
            ) from exc
    if len(matches) != 1:
        raise PermitInputError(
            "exactly one merged pull request must explain the activated authority"
        )
    return matches[0]


def recover_merged_authority_promotion(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    workflow_sha: str,
    repository_config: dict[str, Any],
) -> dict[str, Any] | None:
    main = client.get_json(f"/repos/{AUTHORITY_REPOSITORY}/git/ref/heads/main")
    main_sha = nested_string(main, "object", "sha", label="authority main SHA")
    main_authority = head_authority(client, head_sha=main_sha)
    if main_authority == authority:
        return None
    if main_authority["generation"] != authority["generation"] + 1 or main_authority[
        "parent"
    ] != {"generation": authority["generation"], "workflow_sha": workflow_sha}:
        raise PermitInputError(
            "main authority differs from the controller without an exact successor lineage"
        )
    matches: list[dict[str, Any]] = []
    for pull_request_value in pull_requests_for_commit(
        client, AUTHORITY_REPOSITORY, main_sha
    ):
        number = pull_request_value.get("number")
        if (
            not isinstance(number, int)
            or isinstance(number, bool)
            or number <= 0
            or pull_request_value.get("state") != "closed"
            or pull_request_value.get("merged") is not True
            or pull_request_value.get("draft") is True
            or pull_request_value.get("merge_commit_sha") != main_sha
            or nested_string(
                pull_request_value,
                "base",
                "ref",
                label="merged authority base ref",
            )
            != "main"
            or nested_string(
                pull_request_value,
                "head",
                "repo",
                "full_name",
                label="merged authority head repository",
            )
            != AUTHORITY_REPOSITORY
        ):
            continue
        base_sha = nested_string(
            pull_request_value, "base", "sha", label="merged authority base SHA"
        )
        head_sha = nested_string(
            pull_request_value, "head", "sha", label="merged authority head SHA"
        )
        if head_authority(client, head_sha=head_sha) != main_authority:
            continue
        if not any(
            is_authority_path(path)
            for path in changed_paths(client, AUTHORITY_REPOSITORY, number)
        ):
            continue
        run, reason = newest_run(client, AUTHORITY_REPOSITORY, head_sha, workflow_sha)
        if run is None:
            raise PermitInputError(
                f"merged successor authority lacks its exact permit run: {reason}"
            )
        entry = verified_plan_entry(
            args,
            client,
            authority=authority,
            workflow_sha=workflow_sha,
            repository_config=repository_config,
            pull_request=number,
            base_sha=base_sha,
            head_sha=head_sha,
            run=run,
            recovery=True,
        )
        if entry["merge_sha"] != main_sha:
            raise PermitInputError(
                "merged successor does not match its signed merge SHA"
            )
        matches.append(entry)
    if len(matches) != 1:
        raise PermitInputError(
            "exactly one closed pull request must explain the unactivated successor"
        )
    return matches[0]


def plan(args: argparse.Namespace, client: GitHubReadClient) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    active_workflow_sha = require_sha(
        args.active_workflow_sha,
        label="active_workflow_sha",
        length=40,
    )
    verify_observer_installation(client, contract=contract)
    if discover_effective_workflow_sha(client) != active_workflow_sha:
        raise PermitInputError("active release authority changed after discovery")
    observe_effective_stable_rules(client, workflow_sha=active_workflow_sha)
    authority = validate_authority_shape(
        load_json_file(args.authority, label="controller authority"),
        label="controller authority",
    )
    if head_authority(client, head_sha=active_workflow_sha) != authority:
        raise PermitInputError(
            "local authority does not equal the active workflow tree"
        )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    ordinary: list[dict[str, Any]] = []
    promotions: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for repository_config in contract["repositories"]:
        repository = repository_config["repository"]
        verify_repository_settings(
            client,
            repository=repository,
            merge_method=repository_config["merge_method"],
        )
        pull_requests = sorted(
            open_pull_requests(client, repository),
            key=lambda value: value.get("number", 0),
        )
        if repository_config["authority_changes"] == "proof-only":
            for pull_request_value in pull_requests:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": pull_request_value.get("number"),
                        "reason": "PERMANENT_PROOF_FIXTURE",
                    }
                )
            continue
        repository_ordinary: list[dict[str, Any]] = []
        repository_promotions: list[dict[str, Any]] = []
        for pull_request_value in pull_requests:
            number = pull_request_value.get("number")
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                raise PermitInputError("GitHub returned an invalid pull request number")
            try:
                base_sha, head_sha = validate_live_pull_request(
                    pull_request_value,
                    repository=repository,
                    pull_request=number,
                )
                run, reason = newest_run(
                    client,
                    repository,
                    head_sha,
                    active_workflow_sha,
                )
                if run is None:
                    blocked.append(
                        {
                            "repository": repository,
                            "pull_request": number,
                            "reason": reason,
                        }
                    )
                    continue
                entry = verified_plan_entry(
                    args,
                    client,
                    authority=authority,
                    workflow_sha=active_workflow_sha,
                    repository_config=repository_config,
                    pull_request=number,
                    base_sha=base_sha,
                    head_sha=head_sha,
                    run=run,
                    recovery=False,
                )
                if repository_config["authority_changes"] == "promotion-only":
                    paths = changed_paths(client, repository, number)
                    if not paths:
                        raise PermitInputError(
                            "authority promotion has no changed paths"
                        )
                    candidate = head_authority(client, head_sha=head_sha)
                    if candidate["generation"] != authority[
                        "generation"
                    ] + 1 or candidate["parent"] != {
                        "generation": authority["generation"],
                        "workflow_sha": active_workflow_sha,
                    }:
                        raise PermitInputError(
                            "authority-surface PR is not the exact next generation"
                        )
                    repository_promotions.append(entry)
                else:
                    repository_ordinary.append(entry)
            except (OSError, PermitInputError) as exc:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": number,
                        "reason": "VALIDATION_FAILED",
                        "detail": str(exc)[:1000],
                    }
                )
        recovery: dict[str, Any] | None = None
        if repository == AUTHORITY_REPOSITORY:
            try:
                recovery = recover_merged_authority_promotion(
                    args,
                    client,
                    authority=authority,
                    workflow_sha=active_workflow_sha,
                    repository_config=repository_config,
                )
                if recovery is None and not has_final_promotion_closure(
                    args,
                    client,
                    authority=authority,
                    control_sha=control_sha,
                    active_workflow_sha=active_workflow_sha,
                ):
                    recovery = verified_activated_recovery_entry(
                        args,
                        client,
                        authority=authority,
                        control_sha=control_sha,
                        active_workflow_sha=active_workflow_sha,
                        repository_config=repository_config,
                    )
            except (OSError, PermitInputError) as exc:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": None,
                        "reason": "AUTHORITY_RECOVERY_FAILED",
                        "detail": str(exc)[:1000],
                    }
                )
                for entry in repository_promotions + repository_ordinary:
                    blocked.append(
                        {
                            "repository": repository,
                            "pull_request": entry["pull_request"],
                            "reason": "SERIALIZED_BEHIND_AUTHORITY_RECOVERY",
                        }
                    )
                continue
        if recovery is not None:
            promotions.append(recovery)
            for entry in repository_promotions + repository_ordinary:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": entry["pull_request"],
                        "reason": "SERIALIZED_BEHIND_AUTHORITY_RECOVERY",
                    }
                )
        elif repository_promotions:
            repository_promotions.sort(key=lambda entry: entry["pull_request"])
            promotions.append(repository_promotions[0])
            for entry in repository_promotions[1:] + repository_ordinary:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": entry["pull_request"],
                        "reason": "SERIALIZED_BEHIND_AUTHORITY_PROMOTION",
                    }
                )
        elif repository_ordinary:
            repository_ordinary.sort(key=lambda entry: entry["pull_request"])
            ordinary.append(repository_ordinary[0])
            for entry in repository_ordinary[1:]:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": entry["pull_request"],
                        "reason": "SERIALIZED_BEHIND_EARLIER_PR",
                    }
                )
    return {
        "schema": PLAN_SCHEMA,
        "controller_sha": control_sha,
        "active_workflow_sha": active_workflow_sha,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "ordinary": ordinary,
        "promotions": promotions,
        "blocked": blocked,
    }


def validate_plan_entry(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} is malformed")
    require_exact_keys(
        value,
        required={
            "repository",
            "pull_request",
            "base_sha",
            "head_sha",
            "merge_sha",
            "merge_tree_sha",
            "permit_id",
            "run_id",
            "run_attempt",
            "workflow_sha",
            "evidence",
            "merge_method",
            "recovery",
        },
        label=label,
    )
    if value["repository"] not in SELECTED_REPOSITORIES:
        raise PermitInputError(f"{label} repository is outside the allowlist")
    positive_integer(value["pull_request"], label=f"{label} pull_request")
    positive_integer(value["run_id"], label=f"{label} run_id")
    positive_integer(value["run_attempt"], label=f"{label} run_attempt")
    for field in (
        "base_sha",
        "head_sha",
        "merge_sha",
        "merge_tree_sha",
        "workflow_sha",
    ):
        require_sha(value[field], label=f"{label} {field}", length=40)
    if not isinstance(value["permit_id"], str) or not value["permit_id"].startswith(
        "sha256:"
    ):
        raise PermitInputError(f"{label} permit_id is invalid")
    require_sha(
        value["permit_id"].removeprefix("sha256:"),
        label=f"{label} permit_id",
        length=64,
    )
    if value["merge_method"] != "merge" or not isinstance(value["recovery"], bool):
        raise PermitInputError(f"{label} merge contract is invalid")
    evidence = value["evidence"]
    if not isinstance(evidence, str):
        raise PermitInputError(f"{label} evidence path is invalid")
    pure = PurePosixPath(evidence)
    if pure.is_absolute() or ".." in pure.parts or "\\" in evidence:
        raise PermitInputError(f"{label} evidence path escapes its artifact")
    return value


def validate_plan(value: dict[str, Any], *, control_sha: str) -> dict[str, Any]:
    require_exact_keys(
        value,
        required={
            "schema",
            "controller_sha",
            "active_workflow_sha",
            "observed_at",
            "ordinary",
            "promotions",
            "blocked",
        },
        label="controller plan",
    )
    if value["schema"] != PLAN_SCHEMA or value["controller_sha"] != control_sha:
        raise PermitInputError("controller plan was not issued by this authority")
    active_workflow_sha = require_sha(
        value["active_workflow_sha"],
        label="plan active_workflow_sha",
        length=40,
    )
    if not all(
        isinstance(value[name], list) for name in ("ordinary", "promotions", "blocked")
    ):
        raise PermitInputError("controller plan lists are malformed")
    ordinary = [
        validate_plan_entry(entry, label=f"ordinary plan entry {index}")
        for index, entry in enumerate(value["ordinary"])
    ]
    promotions = [
        validate_plan_entry(entry, label=f"promotion plan entry {index}")
        for index, entry in enumerate(value["promotions"])
    ]
    if (
        len(ordinary) > 1
        or len(promotions) > 1
        or any(entry["repository"] == AUTHORITY_REPOSITORY for entry in ordinary)
        or any(entry["repository"] != AUTHORITY_REPOSITORY for entry in promotions)
        or any(
            entry["repository"] == "Mindburn-Labs/contracts-autonomous-release-lab"
            for entry in ordinary
        )
        or len({entry["repository"] for entry in ordinary}) != len(ordinary)
    ):
        raise PermitInputError("controller plan violates fixed serialization")
    if any(entry["workflow_sha"] != active_workflow_sha for entry in ordinary):
        raise PermitInputError("ordinary plan entries do not use the active authority")
    if any(
        entry["workflow_sha"] != active_workflow_sha and entry["recovery"] is not True
        for entry in promotions
    ):
        raise PermitInputError("forward promotion does not use the active authority")
    return value


def select_entry(plan_value: dict[str, Any], repository: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in plan_value["ordinary"]:
        if value.get("repository") == repository:
            result.append(value)
    return result


def evidence_directory(root: Path, entry: dict[str, Any]) -> Path:
    value = entry.get("evidence")
    if not isinstance(value, str):
        raise PermitInputError("controller evidence path is invalid")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "\\" in value:
        raise PermitInputError("controller evidence path escapes its artifact")
    path = root.joinpath(*pure.parts)
    if not path.is_dir() or path.is_symlink():
        raise PermitInputError("controller evidence directory is absent")
    return path


def approve(args: argparse.Namespace) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    if args.repository not in SELECTED_REPOSITORIES:
        raise PermitInputError("approval repository is outside the allowlist")
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    plan_value = validate_plan(
        load_object(args.plan, label="controller plan"),
        control_sha=control_sha,
    )
    observer_token = os.environ.get("GH_TOKEN", "")
    approver_token = os.environ.get("HELM_AUTHORITY_APPROVER_TOKEN", "")
    metadata = GitHubApprovalClient(observer_token)
    approver = GitHubApprovalClient(approver_token)
    receipts: list[dict[str, Any]] = []
    for entry in select_entry(plan_value, args.repository):
        evidence = evidence_directory(args.evidence_root, entry)
        receipt = submit_machine_approval(
            argparse.Namespace(
                permit=evidence / "release-permit.json",
                permit_bundle=evidence / "release-permit.attestation.json",
                trusted_context=evidence / "context.json",
                kernel_verifier=args.kernel_verifier,
                repository=args.repository,
                pull_request=entry["pull_request"],
                head_sha=entry["head_sha"],
                workflow_sha=entry["workflow_sha"],
                approver_app_slug=args.approver_app_slug,
                approver_installation_id=args.approver_installation_id,
            ),
            approver,
            attestation_token=observer_token,
            metadata_client=metadata,
        )
        if receipt["permit_id"] != entry["permit_id"]:
            raise PermitInputError("approval receipt does not match its plan permit")
        receipts.append(receipt)
    return {
        "schema": APPROVAL_SCHEMA,
        "controller_sha": control_sha,
        "repository": args.repository,
        "approvals": receipts,
    }


def repository_config(contract: dict[str, Any], repository: str) -> dict[str, Any]:
    matches = [
        item for item in contract["repositories"] if item["repository"] == repository
    ]
    if len(matches) != 1:
        raise PermitInputError("repository is outside the source-owned controller set")
    return matches[0]


def verify_merger_installation(
    client: GitHubApprovalClient,
    *,
    contract: dict[str, Any],
    repository: str,
) -> None:
    merger = contract["apps"]["merger"]
    installation = client.request("GET", "/installation")
    account = installation.get("account") if isinstance(installation, dict) else None
    if (
        not isinstance(installation, dict)
        or installation.get("app_id") != merger["app_id"]
        or installation.get("id") != merger["installation_id"]
        or installation.get("permissions")
        != {"contents": "write", "pull_requests": "read"}
        or not isinstance(account, dict)
        or account.get("login") != ORGANIZATION
    ):
        raise PermitInputError("merger App identity or permissions drifted")
    repositories = client.request("GET", "/installation/repositories?per_page=100")
    items = repositories.get("repositories") if isinstance(repositories, dict) else None
    if not isinstance(items, list) or {
        item.get("full_name") for item in items if isinstance(item, dict)
    } != {repository}:
        raise PermitInputError("merger token repository scope is not exact")


def graphql(
    client: GitHubApprovalClient,
    query: str,
    variables: dict[str, Any],
) -> dict[str, Any]:
    response = client.request(
        "POST",
        "/graphql",
        payload={"query": query, "variables": variables},
    )
    if not isinstance(response, dict) or response.get("errors"):
        raise PermitInputError("GitHub rejected the atomic controller mutation")
    data = response.get("data")
    if not isinstance(data, dict):
        raise PermitInputError("GitHub GraphQL response has no data")
    return data


def merge(args: argparse.Namespace) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    configuration = repository_config(contract, args.repository)
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    plan_value = validate_plan(
        load_object(args.plan, label="controller plan"), control_sha=control_sha
    )
    approvals = load_object(args.approvals, label="controller approvals")
    require_exact_keys(
        approvals,
        required={"schema", "controller_sha", "repository", "approvals"},
        label="controller approvals",
    )
    if (
        approvals["schema"] != APPROVAL_SCHEMA
        or approvals["controller_sha"] != control_sha
        or approvals["repository"] != args.repository
        or not isinstance(approvals["approvals"], list)
    ):
        raise PermitInputError("controller approval artifact is invalid")
    by_pr = {
        item.get("pull_request"): item
        for item in approvals["approvals"]
        if isinstance(item, dict)
    }
    client = GitHubApprovalClient(os.environ.get("GH_TOKEN", ""))
    verify_merger_installation(client, contract=contract, repository=args.repository)
    receipts: list[dict[str, Any]] = []
    for entry in select_entry(plan_value, args.repository):
        approval = by_pr.get(entry["pull_request"])
        if not isinstance(approval, dict):
            raise PermitInputError("ordinary merge lacks an isolated App approval")
        expected = {
            "schema": "mindburn.release-authority-machine-approval/v2",
            "repository": args.repository,
            "pull_request": entry["pull_request"],
            "head_sha": entry["head_sha"],
            "workflow_sha": entry["workflow_sha"],
            "permit_id": entry["permit_id"],
            "base_sha": entry["base_sha"],
            "merge_sha": entry["merge_sha"],
            "merge_tree_sha": entry["merge_tree_sha"],
            "review_state": "APPROVED",
            "approver_login": APPROVER_LOGIN,
            "approver_app_id": APPROVER_APP_ID,
            "approver_installation_id": APPROVER_INSTALLATION_ID,
        }
        for field, value in expected.items():
            if approval.get(field) != value:
                raise PermitInputError(f"ordinary approval {field} is not exact")
        review_id = positive_integer(approval.get("review_id"), label="review_id")
        review = client.request(
            "GET",
            f"/repos/{args.repository}/pulls/{entry['pull_request']}/reviews/{review_id}",
        )
        author = review.get("user") if isinstance(review, dict) else None
        if (
            not isinstance(review, dict)
            or review.get("state") != "APPROVED"
            or review.get("commit_id") != entry["head_sha"]
            or review.get("body") != f"HELM signed ALLOW permit {entry['permit_id']}"
            or not isinstance(author, dict)
            or author.get("login") != APPROVER_LOGIN
        ):
            raise PermitInputError("live App approval drifted before merge")
        pull_request_value = client.request(
            "GET", f"/repos/{args.repository}/pulls/{entry['pull_request']}"
        )
        if not isinstance(pull_request_value, dict):
            raise PermitInputError("merge pull request response is malformed")
        main_path = f"/repos/{args.repository}/git/ref/heads/main"
        main = client.request("GET", main_path)
        if not isinstance(main, dict):
            raise PermitInputError("main ref response is malformed")
        main_sha = nested_string(main, "object", "sha", label="main SHA")
        merge_commit_sha = require_sha(
            entry["merge_sha"], label="reviewed merge SHA", length=40
        )
        resumed = main_sha == merge_commit_sha
        if resumed:
            if (
                pull_request_value.get("state") != "closed"
                or pull_request_value.get("merged") is not True
            ):
                validate_live_pull_request(
                    pull_request_value,
                    repository=args.repository,
                    pull_request=entry["pull_request"],
                    base_sha=entry["base_sha"],
                    head_sha=entry["head_sha"],
                )
                if pull_request_value.get("merge_commit_sha") != merge_commit_sha:
                    raise PermitInputError(
                        "GitHub reconciliation names a different merge commit"
                    )
                for _ in range(10):
                    pull_request_value = client.request(
                        "GET",
                        f"/repos/{args.repository}/pulls/{entry['pull_request']}",
                    )
                    if (
                        isinstance(pull_request_value, dict)
                        and pull_request_value.get("state") == "closed"
                        and pull_request_value.get("merged") is True
                    ):
                        break
                    time.sleep(2)
                else:
                    raise PermitInputError(
                        "main is exact but GitHub has not reconciled the pull request"
                    )
            validate_merged_pull_request(
                pull_request_value,
                repository=args.repository,
                pull_request=entry["pull_request"],
                base_sha=entry["base_sha"],
                head_sha=entry["head_sha"],
                merge_sha=merge_commit_sha,
            )
        elif main_sha == entry["base_sha"]:
            validate_live_pull_request(
                pull_request_value,
                repository=args.repository,
                pull_request=entry["pull_request"],
                base_sha=entry["base_sha"],
                head_sha=entry["head_sha"],
            )
        else:
            raise PermitInputError("main moved before the atomic merge precondition")
        commit = client.request(
            "GET", f"/repos/{args.repository}/git/commits/{merge_commit_sha}"
        )
        parents = commit.get("parents") if isinstance(commit, dict) else None
        if (
            not isinstance(commit, dict)
            or not isinstance(parents, list)
            or [parent.get("sha") for parent in parents if isinstance(parent, dict)]
            != [entry["base_sha"], entry["head_sha"]]
            or nested_string(commit, "tree", "sha", label="reviewed merge tree")
            != entry["merge_tree_sha"]
        ):
            raise PermitInputError("reviewed merge graph differs from the permit")
        if not resumed:
            repository_name = args.repository.split("/", 1)[1]
            repository_data = graphql(
                client,
                REPOSITORY_ID_QUERY,
                {"owner": ORGANIZATION, "name": repository_name},
            ).get("repository")
            if not isinstance(repository_data, dict) or not isinstance(
                repository_data.get("id"), str
            ):
                raise PermitInputError("GitHub returned no repository node ID")
            update = graphql(
                client,
                UPDATE_REFS_MUTATION,
                {
                    "repositoryId": repository_data["id"],
                    "beforeOid": entry["base_sha"],
                    "afterOid": merge_commit_sha,
                },
            )
            if not isinstance(update.get("updateRefs"), dict):
                raise PermitInputError("GitHub returned no atomic ref-update result")
            main_after = client.request("GET", main_path)
            if (
                not isinstance(main_after, dict)
                or nested_string(main_after, "object", "sha", label="main SHA")
                != merge_commit_sha
            ):
                raise PermitInputError("main does not equal the reviewed merge commit")
        for _ in range(10):
            confirmed = client.request(
                "GET", f"/repos/{args.repository}/pulls/{entry['pull_request']}"
            )
            if (
                isinstance(confirmed, dict)
                and confirmed.get("state") == "closed"
                and confirmed.get("merged") is True
                and confirmed.get("merge_commit_sha") == merge_commit_sha
            ):
                break
            time.sleep(2)
        else:
            raise PermitInputError(
                "main advanced safely but GitHub did not reconcile the pull request"
            )
        receipts.append(
            {
                "repository": args.repository,
                "pull_request": entry["pull_request"],
                "head_sha": entry["head_sha"],
                "permit_id": entry["permit_id"],
                "merge_method": configuration["merge_method"],
                "merge_commit_sha": merge_commit_sha,
                "merge_tree_sha": entry["merge_tree_sha"],
                "resumed": resumed,
            }
        )
    return {
        "schema": MERGE_SCHEMA,
        "controller_sha": control_sha,
        "repository": args.repository,
        "merges": receipts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    status_parser = subparsers.add_parser("validate-contract")
    status_parser.add_argument("--contract", type=Path, required=True)
    status_parser.add_argument("--output", type=Path, required=True)
    discover_parser = subparsers.add_parser("discover")
    discover_parser.add_argument("--contract", type=Path, required=True)
    discover_parser.add_argument("--control-sha", required=True)
    discover_parser.add_argument("--output", type=Path, required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--contract", type=Path, required=True)
    plan_parser.add_argument("--authority", type=Path, required=True)
    plan_parser.add_argument("--kernel-verifier", type=Path, required=True)
    plan_parser.add_argument("--control-sha", required=True)
    plan_parser.add_argument("--active-workflow-sha", required=True)
    plan_parser.add_argument("--output-dir", type=Path, required=True)
    plan_parser.add_argument("--output", type=Path, required=True)
    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("--contract", type=Path, required=True)
    approve_parser.add_argument("--plan", type=Path, required=True)
    approve_parser.add_argument("--evidence-root", type=Path, required=True)
    approve_parser.add_argument("--kernel-verifier", type=Path, required=True)
    approve_parser.add_argument("--control-sha", required=True)
    approve_parser.add_argument("--repository", required=True)
    approve_parser.add_argument("--approver-app-slug", required=True)
    approve_parser.add_argument("--approver-installation-id", type=int, required=True)
    approve_parser.add_argument("--output", type=Path, required=True)
    merge_parser = subparsers.add_parser("merge")
    merge_parser.add_argument("--contract", type=Path, required=True)
    merge_parser.add_argument("--plan", type=Path, required=True)
    merge_parser.add_argument("--approvals", type=Path, required=True)
    merge_parser.add_argument("--control-sha", required=True)
    merge_parser.add_argument("--repository", required=True)
    merge_parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command == "validate-contract":
            result = contract_status(args)
        elif args.command == "discover":
            result = discover(
                args,
                GitHubReadClient(
                    os.environ.get("GH_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
            )
        elif args.command == "plan":
            result = plan(
                args,
                GitHubReadClient(
                    os.environ.get("GH_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
            )
        elif args.command == "approve":
            result = approve(args)
        else:
            result = merge(args)
        write_json(args.output, result)
        sys.stdout.buffer.write(canonical_json(result))
    except (KeyError, OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"autonomous-release-controller: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
