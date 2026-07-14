#!/usr/bin/env python3
"""Independently observe a staged HELM release-authority promotion."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from authority_ruleset_broker import (
    CANDIDATE_RULESET_ID,
    MAIN_REF,
    STABLE_RULESET_ID,
    GitHubRulesetClient,
    get_ruleset,
    validate_ref,
    validate_ruleset,
)
from verify_authority_promotion import validate_authority_shape
from wait_for_authority_canary import (
    WORKFLOW_NAME,
    WORKFLOW_PATH,
    GitHubReadClient,
    artifact_for_run,
    extract_attested_permit,
    extract_trusted_context,
    verify_candidate_permit,
)


EXECUTION_SCHEMA = "mindburn.release-authority-promotion-execution/v1"
OBSERVER_SCHEMA = "mindburn.release-authority-observer-receipt/v1"
AUTHORITY_REPOSITORY = "Mindburn-Labs/.github"
CANARY_REPOSITORY = "Mindburn-Labs/contracts-autonomous-release-lab"
CANARY_PULL_REQUEST = 8
EXECUTION_KEYS = {
    "schema",
    "parent_generation",
    "candidate_generation",
    "parent_base_sha",
    "parent_workflow_sha",
    "candidate_workflow_sha",
    "candidate_workflow_ref",
    "candidate_tree_sha",
    "candidate_pull_request",
    "merged_workflow_sha",
    "merged_tree_sha",
    "ratification_permit_id",
    "ratification_run_id",
    "ratification_run_attempt",
    "canary_run_id",
    "canary_run_attempt",
    "canary_permit_id",
    "authority_suite_sha256",
}
CANARY_RECEIPT_KEYS = {
    "schema",
    "repository",
    "pull_request",
    "head_sha",
    "workflow_sha",
    "run_id",
    "run_attempt",
    "permit_id",
    "merge_sha",
    "merge_tree_sha",
}


def load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def require_positive_int(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PermitInputError(f"{label} must be a positive integer")
    return value


def require_permit_id(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise PermitInputError(f"{label} must be a sha256 permit identifier")
    require_sha(value.removeprefix("sha256:"), label=label, length=64)
    return value


def validate_execution(value: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(value, required=EXECUTION_KEYS, label="promotion execution")
    if value["schema"] != EXECUTION_SCHEMA:
        raise PermitInputError("unsupported promotion execution schema")
    parent_generation = require_positive_int(
        value["parent_generation"],
        label="parent_generation",
    )
    candidate_generation = require_positive_int(
        value["candidate_generation"],
        label="candidate_generation",
    )
    if candidate_generation != parent_generation + 1:
        raise PermitInputError(
            "candidate generation must immediately follow the parent"
        )
    for field in (
        "parent_base_sha",
        "parent_workflow_sha",
        "candidate_workflow_sha",
        "candidate_tree_sha",
        "merged_workflow_sha",
        "merged_tree_sha",
    ):
        require_sha(value[field], label=field, length=40)
    if value["parent_base_sha"] != value["parent_workflow_sha"]:
        raise PermitInputError(
            "ratification base must equal the immutable parent workflow"
        )
    if value["candidate_tree_sha"] != value["merged_tree_sha"]:
        raise PermitInputError("merged tree does not equal the ratified candidate tree")
    validate_ref(value["candidate_workflow_ref"], label="candidate_workflow_ref")
    require_positive_int(
        value["candidate_pull_request"], label="candidate_pull_request"
    )
    require_positive_int(value["ratification_run_id"], label="ratification_run_id")
    require_positive_int(
        value["ratification_run_attempt"],
        label="ratification_run_attempt",
    )
    require_positive_int(value["canary_run_id"], label="canary_run_id")
    require_positive_int(value["canary_run_attempt"], label="canary_run_attempt")
    require_permit_id(value["ratification_permit_id"], label="ratification_permit_id")
    require_permit_id(value["canary_permit_id"], label="canary_permit_id")
    require_sha(
        value["authority_suite_sha256"],
        label="authority_suite_sha256",
        length=64,
    )
    return value


def nested_string(value: dict[str, Any], *keys: str, label: str) -> str:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            raise PermitInputError(f"GitHub response is missing {label}")
        current = current[key]
    if not isinstance(current, str) or not current:
        raise PermitInputError(f"GitHub response has an invalid {label}")
    return current


def observe(
    args: argparse.Namespace,
    read_client: GitHubReadClient,
    ruleset_client: GitHubRulesetClient,
    *,
    attestation_token: str,
) -> dict[str, Any]:
    execution = validate_execution(
        load_json(args.execution, label="promotion execution")
    )
    if (
        hashlib.sha256(args.authority_suite.read_bytes()).hexdigest()
        != execution["authority_suite_sha256"]
    ):
        raise PermitInputError(
            "authority suite receipt does not match promotion execution"
        )
    parent_authority = validate_authority_shape(
        load_json(args.parent_authority, label="parent authority"),
        label="parent authority",
    )
    authority = validate_authority_shape(
        load_json(args.candidate_authority, label="candidate authority"),
        label="candidate authority",
    )
    if authority["generation"] != execution["candidate_generation"]:
        raise PermitInputError(
            "candidate authority generation does not match execution"
        )
    if parent_authority["generation"] != execution["parent_generation"]:
        raise PermitInputError("parent authority generation does not match execution")
    if authority["parent"] != {
        "generation": execution["parent_generation"],
        "workflow_sha": execution["parent_workflow_sha"],
    }:
        raise PermitInputError("candidate authority does not name the observed parent")

    main = read_client.get_json(f"/repos/{AUTHORITY_REPOSITORY}/git/ref/heads/main")
    main_sha = nested_string(main, "object", "sha", label="main SHA")
    if main_sha != execution["merged_workflow_sha"]:
        raise PermitInputError(
            "authority main does not equal the observed merge commit"
        )
    commit = read_client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/git/commits/{main_sha}",
    )
    main_tree_sha = nested_string(commit, "tree", "sha", label="main tree SHA")
    if main_tree_sha != execution["merged_tree_sha"]:
        raise PermitInputError(
            "authority main tree does not equal the ratified candidate tree"
        )

    pull_request = read_client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/pulls/{execution['candidate_pull_request']}",
    )
    if (
        pull_request.get("state") != "closed"
        or pull_request.get("merged") is not True
        or pull_request.get("merge_commit_sha") != main_sha
        or nested_string(pull_request, "base", "ref", label="pull request base")
        != "main"
        or nested_string(pull_request, "head", "sha", label="pull request head SHA")
        != execution["candidate_workflow_sha"]
        or "refs/heads/"
        + nested_string(pull_request, "head", "ref", label="pull request head ref")
        != execution["candidate_workflow_ref"]
        or nested_string(
            pull_request,
            "head",
            "repo",
            "full_name",
            label="pull request head repository",
        )
        != AUTHORITY_REPOSITORY
    ):
        raise PermitInputError(
            "authority pull request does not describe the exact observed merge"
        )

    ratification_run = read_client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/actions/runs/{execution['ratification_run_id']}",
    )
    if (
        ratification_run.get("name") != WORKFLOW_NAME
        or ratification_run.get("path") != WORKFLOW_PATH
        or ratification_run.get("event") != "pull_request"
        or ratification_run.get("head_sha") != execution["candidate_workflow_sha"]
        or ratification_run.get("run_attempt") != execution["ratification_run_attempt"]
        or ratification_run.get("status") != "completed"
        or ratification_run.get("conclusion") != "success"
    ):
        raise PermitInputError(
            "ratification workflow run is not an exact successful parent run"
        )
    ratification_artifact_id = artifact_for_run(
        read_client,
        AUTHORITY_REPOSITORY,
        execution["ratification_run_id"],
    )
    if ratification_artifact_id is None:
        raise PermitInputError("ratification workflow run has no permit artifact")
    ratification_context_artifact_id = artifact_for_run(
        read_client,
        AUTHORITY_REPOSITORY,
        execution["ratification_run_id"],
        "release-permit-input",
    )
    if ratification_context_artifact_id is None:
        raise PermitInputError(
            "ratification workflow run has no permit context artifact"
        )
    ratification_artifact = read_client.get_bytes(
        f"/repos/{AUTHORITY_REPOSITORY}/actions/artifacts/{ratification_artifact_id}/zip",
    )
    artifact_ratification, artifact_ratification_bundle = extract_attested_permit(
        ratification_artifact,
    )
    ratification_context_artifact = read_client.get_bytes(
        f"/repos/{AUTHORITY_REPOSITORY}/actions/artifacts/{ratification_context_artifact_id}/zip",
    )
    artifact_ratification_context = extract_trusted_context(
        ratification_context_artifact
    )
    supplied_ratification = args.ratification_permit.read_bytes()
    supplied_ratification_bundle = args.ratification_bundle.read_bytes()
    if (
        artifact_ratification != supplied_ratification
        or artifact_ratification_bundle != supplied_ratification_bundle
        or artifact_ratification_context != args.ratification_context.read_bytes()
    ):
        raise PermitInputError(
            "supplied ratification permit, bundle, or context is not the run artifact",
        )
    ratification_permit = verify_candidate_permit(
        args.ratification_permit,
        args.ratification_bundle,
        args.ratification_context,
        run=ratification_run,
        repository=AUTHORITY_REPOSITORY,
        pull_request=execution["candidate_pull_request"],
        head_sha=execution["candidate_workflow_sha"],
        expected_workflow_sha=execution["parent_workflow_sha"],
        expected_authority=parent_authority,
        kernel_verifier=args.parent_kernel_verifier,
        attestation_token=attestation_token,
    )
    if (
        ratification_permit["permit_id"] != execution["ratification_permit_id"]
        or ratification_permit["base_sha"] != execution["parent_base_sha"]
        or ratification_permit["merge_tree_sha"] != execution["candidate_tree_sha"]
    ):
        raise PermitInputError(
            "ratification permit does not bind the observed candidate tree"
        )

    canary_receipt = load_json(args.canary_receipt, label="canary receipt")
    require_exact_keys(
        canary_receipt, required=CANARY_RECEIPT_KEYS, label="canary receipt"
    )
    expected_canary = {
        "schema": "mindburn.release-authority-canary/v1",
        "repository": CANARY_REPOSITORY,
        "pull_request": CANARY_PULL_REQUEST,
        "workflow_sha": execution["candidate_workflow_sha"],
        "run_id": execution["canary_run_id"],
        "run_attempt": execution["canary_run_attempt"],
        "permit_id": execution["canary_permit_id"],
    }
    for field, expected in expected_canary.items():
        if canary_receipt.get(field) != expected:
            raise PermitInputError(f"canary receipt {field} does not match execution")
    canary_head_sha = require_sha(
        canary_receipt["head_sha"],
        label="canary head_sha",
        length=40,
    )
    run = read_client.get_json(
        f"/repos/{CANARY_REPOSITORY}/actions/runs/{execution['canary_run_id']}",
    )
    if (
        run.get("name") != WORKFLOW_NAME
        or run.get("path") != WORKFLOW_PATH
        or run.get("event") != "pull_request"
        or run.get("head_sha") != canary_head_sha
        or run.get("run_attempt") != execution["canary_run_attempt"]
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise PermitInputError(
            "canary workflow run is not an exact successful candidate run"
        )
    artifact_id = artifact_for_run(
        read_client, CANARY_REPOSITORY, execution["canary_run_id"]
    )
    if artifact_id is None:
        raise PermitInputError("canary workflow run has no permit artifact")
    context_artifact_id = artifact_for_run(
        read_client,
        CANARY_REPOSITORY,
        execution["canary_run_id"],
        "release-permit-input",
    )
    if context_artifact_id is None:
        raise PermitInputError("canary workflow run has no permit context artifact")
    artifact = read_client.get_bytes(
        f"/repos/{CANARY_REPOSITORY}/actions/artifacts/{artifact_id}/zip",
    )
    artifact_permit, artifact_bundle = extract_attested_permit(artifact)
    context_artifact = read_client.get_bytes(
        f"/repos/{CANARY_REPOSITORY}/actions/artifacts/{context_artifact_id}/zip",
    )
    artifact_context = extract_trusted_context(context_artifact)
    supplied_permit = args.canary_permit.read_bytes()
    supplied_bundle = args.canary_bundle.read_bytes()
    if (
        artifact_permit != supplied_permit
        or artifact_bundle != supplied_bundle
        or artifact_context != args.canary_context.read_bytes()
    ):
        raise PermitInputError(
            "supplied canary permit, bundle, or context is not the run artifact"
        )
    permit = verify_candidate_permit(
        args.canary_permit,
        args.canary_bundle,
        args.canary_context,
        run=run,
        repository=CANARY_REPOSITORY,
        pull_request=CANARY_PULL_REQUEST,
        head_sha=canary_head_sha,
        expected_workflow_sha=execution["candidate_workflow_sha"],
        expected_authority=authority,
        kernel_verifier=args.parent_kernel_verifier,
        attestation_token=attestation_token,
    )
    for field in ("permit_id", "merge_sha", "merge_tree_sha"):
        if permit[field] != canary_receipt[field]:
            raise PermitInputError(f"canary permit {field} does not match its receipt")

    stable_sha = (
        execution["parent_workflow_sha"]
        if args.phase == "pre-activation"
        else execution["merged_workflow_sha"]
    )
    stable = get_ruleset(ruleset_client, STABLE_RULESET_ID)
    candidate = get_ruleset(ruleset_client, CANDIDATE_RULESET_ID)
    validate_ruleset(
        stable.body, kind="stable", expected_sha=stable_sha, expected_ref=MAIN_REF
    )
    validate_ruleset(
        candidate.body,
        kind="candidate",
        expected_sha=execution["merged_workflow_sha"],
        expected_ref=MAIN_REF,
    )

    return {
        "schema": OBSERVER_SCHEMA,
        "phase": args.phase,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "promotion_run_id": require_positive_int(
            args.promotion_run_id,
            label="promotion_run_id",
        ),
        "promotion_run_attempt": require_positive_int(
            args.promotion_run_attempt,
            label="promotion_run_attempt",
        ),
        "parent_workflow_sha": execution["parent_workflow_sha"],
        "candidate_workflow_sha": execution["candidate_workflow_sha"],
        "merged_workflow_sha": main_sha,
        "merged_tree_sha": main_tree_sha,
        "canary_permit_id": permit["permit_id"],
        "ratification_permit_id": ratification_permit["permit_id"],
        "authority_suite_sha256": execution["authority_suite_sha256"],
        "stable_ruleset_id": STABLE_RULESET_ID,
        "stable_workflow_sha": stable_sha,
        "candidate_ruleset_id": CANDIDATE_RULESET_ID,
        "candidate_workflow_binding_sha": execution["merged_workflow_sha"],
        "decision": "ALLOW",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("pre-activation", "final"), required=True)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument("--parent-authority", type=Path, required=True)
    parser.add_argument("--candidate-authority", type=Path, required=True)
    parser.add_argument("--ratification-permit", type=Path, required=True)
    parser.add_argument("--ratification-bundle", type=Path, required=True)
    parser.add_argument("--ratification-context", type=Path, required=True)
    parser.add_argument("--canary-permit", type=Path, required=True)
    parser.add_argument("--canary-bundle", type=Path, required=True)
    parser.add_argument("--canary-context", type=Path, required=True)
    parser.add_argument("--canary-receipt", type=Path, required=True)
    parser.add_argument("--authority-suite", type=Path, required=True)
    parser.add_argument("--parent-kernel-verifier", type=Path, required=True)
    parser.add_argument("--promotion-run-id", type=int, required=True)
    parser.add_argument("--promotion-run-attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        token = os.environ.get("GH_TOKEN", "")
        api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        receipt = observe(
            args,
            GitHubReadClient(token, api_url=api_url),
            GitHubRulesetClient(token, api_url=api_url),
            attestation_token=token,
        )
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError) as exc:
        print(f"observe-authority-promotion: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
