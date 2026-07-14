#!/usr/bin/env python3
"""Execute the one-time, evidence-gated generation-1 authority bootstrap."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

from atomic_merge_authority import (
    GitHubMergeClient,
    MAIN_REF,
    REPOSITORY,
    atomic_merge,
    nested_string,
    validate_pull_request,
)
from authority_ruleset_broker import (
    CANDIDATE_RULESET_ID,
    GitHubRulesetClient,
    LEGACY_PARENT_WORKFLOW_SHA,
    MAIN_REF as RULESET_MAIN_REF,
    STABLE_RULESET_ID,
    get_ruleset,
    transition,
    validate_ref,
    validate_ruleset,
)
from autonomous_release_permit import (
    PermitInputError,
    require_exact_keys,
    require_sha,
)
from remove_human_approval_gates import (
    GitHubAdminClient,
    remove_human_approval_gates,
)
from verify_authority_promotion import verify as verify_promotion
from verify_control_plane import (
    load_json,
    validate_contract,
    verify_live_environments,
)
from wait_for_authority_canary import (
    GitHubReadClient,
    load_json_file,
    verify_attestation,
    verify_candidate_permit,
    wait_for_canary,
)
from wait_for_authority_suite import wait_for_suite


READY_SCHEMA = "mindburn.release-authority-bootstrap-ready/v1"
FINAL_SCHEMA = "mindburn.release-authority-bootstrap/v1"
TRIGGER_SCHEMA = "mindburn.release-authority-suite-trigger/v1"
LAB_REPOSITORY = "Mindburn-Labs/contracts-autonomous-release-lab"


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def nested(value: dict[str, Any], *keys: str, label: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            raise PermitInputError(f"GitHub response is missing {label}")
        current = current.get(key)
    return current


def reopen_pull_request(
    client: GitHubMergeClient,
    *,
    repository: str,
    pull_request: int,
    head_sha: str,
    base_sha: str | None = None,
    head_ref: str | None = None,
) -> dict[str, Any]:
    path = f"/repos/{repository}/pulls/{pull_request}"
    current = client.get(path)
    if (
        current.get("number") != pull_request
        or current.get("merged") is True
        or current.get("draft") is True
        or nested(current, "base", "ref", label="pull request base ref") != "main"
        or nested(current, "head", "sha", label="pull request head SHA") != head_sha
        or nested(current, "head", "repo", "full_name", label="pull request head repository")
        != repository
    ):
        raise PermitInputError(f"{repository}#{pull_request} does not match the proof contract")
    if base_sha is not None and nested(current, "base", "sha", label="base SHA") != base_sha:
        raise PermitInputError(f"{repository}#{pull_request} base moved before proof trigger")
    if head_ref is not None and nested(current, "head", "ref", label="head ref") != head_ref:
        raise PermitInputError(f"{repository}#{pull_request} head ref drifted")
    if current.get("state") == "open":
        current = client.request("PATCH", path, payload={"state": "closed"})
        if current.get("state") != "closed":
            raise PermitInputError(f"GitHub did not close {repository}#{pull_request}")
    reopened = client.request("PATCH", path, payload={"state": "open"})
    if (
        reopened.get("state") != "open"
        or nested(reopened, "head", "sha", label="reopened head SHA") != head_sha
    ):
        raise PermitInputError(f"GitHub did not reopen exact {repository}#{pull_request}")
    return reopened


def trigger_suite(
    contract: dict[str, Any],
    client: GitHubMergeClient,
    *,
    workflow_sha: str,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=2)
    for case in contract["adversarial_suite"]["cases"]:
        reopen_pull_request(
            client,
            repository=LAB_REPOSITORY,
            pull_request=case["pull_request"],
            head_sha=case["head_sha"],
        )
    return {
        "schema": TRIGGER_SCHEMA,
        "repository": LAB_REPOSITORY,
        "workflow_sha": workflow_sha,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "cases": contract["adversarial_suite"]["cases"],
    }


def transition_args(
    operation: str,
    *,
    candidate_sha: str,
    candidate_ref: str,
    merge_sha: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        operation=operation,
        parent_sha=LEGACY_PARENT_WORKFLOW_SHA,
        candidate_sha=candidate_sha,
        candidate_ref=candidate_ref,
        merge_sha=merge_sha,
    )


def suite_args(
    args: argparse.Namespace,
    *,
    trigger: Path,
    output_dir: Path,
) -> argparse.Namespace:
    return argparse.Namespace(
        contract=args.control_contract,
        adversarial_corpus=args.adversarial_corpus,
        trigger=trigger,
        expected_workflow_sha=args.candidate_sha,
        expected_authority=args.candidate_authority,
        kernel_verifier=args.permit_verifier,
        output_dir=output_dir,
        timeout_seconds=args.timeout_seconds,
        poll_seconds=args.poll_seconds,
    )


def verify_ratification(
    args: argparse.Namespace,
    *,
    attestation_token: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    permit = load_json_file(args.permit, label="generation-1 ratification permit")
    if permit.get("workflow_sha") != LEGACY_PARENT_WORKFLOW_SHA:
        raise PermitInputError("bootstrap ratification was not issued by generation 1")
    if permit.get("pull_request") != args.candidate_pr:
        raise PermitInputError("bootstrap ratification names the wrong pull request")
    ratified_merge_sha = require_sha(
        permit.get("merge_sha"),
        label="ratification merge_sha",
        length=40,
    )
    verify_attestation(
        args.permit,
        args.permit_bundle,
        repository=REPOSITORY,
        workflow_sha=LEGACY_PARENT_WORKFLOW_SHA,
        source_sha=ratified_merge_sha,
        github_token=attestation_token,
    )
    promotion = verify_promotion(
        argparse.Namespace(
            permit_verifier=args.permit_verifier,
            permit=args.permit,
            trusted_context=args.trusted_context,
            candidate_repository=args.candidate_repository,
            candidate_sha=args.candidate_sha,
            candidate_pr=args.candidate_pr,
            expected_run_id=permit.get("run_id"),
            expected_run_attempt=permit.get("run_attempt"),
            expected_parent_generation=1,
            expected_parent_workflow_sha=LEGACY_PARENT_WORKFLOW_SHA,
        ),
    )
    return permit, promotion


def verify_control(args: argparse.Namespace, client: GitHubReadClient) -> dict[str, Any]:
    contract = validate_contract(
        load_json(args.control_contract, label="control contract"),
        load_json(args.adversarial_corpus, label="adversarial corpus"),
    )
    return {
        "contract": contract,
        "environments": verify_live_environments(contract, client),
    }


def prepare(args: argparse.Namespace, token: str, observer_token: str) -> dict[str, Any]:
    args.candidate_sha = require_sha(args.candidate_sha, label="candidate_sha", length=40)
    args.candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    if args.candidate_pr <= 0:
        raise PermitInputError("candidate_pr must be positive")
    if args.output_dir.exists():
        raise PermitInputError("bootstrap output directory already exists")
    args.output_dir.mkdir(parents=True)

    read_client = GitHubReadClient(token)
    observer_client = GitHubReadClient(observer_token)
    merge_client = GitHubMergeClient(token)
    ruleset_client = GitHubRulesetClient(token)
    admin_client = GitHubAdminClient(token)
    staged = False
    enforced = False
    enforcement_started = False
    try:
        ratification, promotion = verify_ratification(
            args,
            attestation_token=observer_token,
        )
        control = verify_control(args, read_client)
        observer_control = verify_control(args, observer_client)
        if control != observer_control:
            raise PermitInputError("independent live control-plane reads did not match")
        write_json(args.output_dir / "control-plane-before.json", control)
        write_json(args.output_dir / "control-plane-observer.json", observer_control)
        head_ref = args.candidate_ref.removeprefix("refs/heads/")
        reopen_candidate = merge_client.get(f"/repos/{REPOSITORY}/pulls/{args.candidate_pr}")
        if (
            nested(reopen_candidate, "base", "sha", label="candidate base SHA")
            != ratification["base_sha"]
            or nested(reopen_candidate, "head", "sha", label="candidate head SHA")
            != args.candidate_sha
            or nested(reopen_candidate, "head", "ref", label="candidate head ref") != head_ref
            or reopen_candidate.get("state") != "open"
            or reopen_candidate.get("draft") is True
        ):
            raise PermitInputError("candidate pull request drifted from the ratification")

        live_stable = get_ruleset(ruleset_client, STABLE_RULESET_ID)
        live_candidate = get_ruleset(ruleset_client, CANDIDATE_RULESET_ID)
        try:
            validate_ruleset(
                live_stable.body,
                kind="stable",
                expected_sha=args.candidate_sha,
                expected_ref=args.candidate_ref,
            )
            validate_ruleset(
                live_candidate.body,
                kind="candidate",
                expected_sha=args.candidate_sha,
                expected_ref=args.candidate_ref,
            )
        except PermitInputError:
            stage_receipt = transition(
                transition_args(
                    "bootstrap-stage",
                    candidate_sha=args.candidate_sha,
                    candidate_ref=args.candidate_ref,
                ),
                ruleset_client,
            )
            staged = True
        else:
            stage_receipt = {
                "schema": "mindburn.release-authority-ruleset-transition/v1",
                "operation": "bootstrap-stage-resumed-after-enforcement",
                "candidate_workflow_sha": args.candidate_sha,
                "candidate_workflow_ref": args.candidate_ref,
            }
            staged = True
            enforced = True
        write_json(args.output_dir / "ruleset-stage.json", stage_receipt)

        trigger = trigger_suite(control["contract"], merge_client, workflow_sha=args.candidate_sha)
        trigger_path = args.output_dir / "suite-trigger.json"
        write_json(trigger_path, trigger)
        promoter_suite = wait_for_suite(
            suite_args(
                args,
                trigger=trigger_path,
                output_dir=args.output_dir / "suite-promoter",
            ),
            read_client,
        )
        promoter_path = args.output_dir / "authority-suite.json"
        write_json(promoter_path, promoter_suite)
        observer_suite = wait_for_suite(
            suite_args(
                args,
                trigger=trigger_path,
                output_dir=args.output_dir / "suite-observer",
            ),
            observer_client,
        )
        observer_path = args.output_dir / "authority-suite-observer.json"
        write_json(observer_path, observer_suite)
        if promoter_path.read_bytes() != observer_path.read_bytes():
            raise PermitInputError("independent suite reverification did not match")

        if enforced:
            enforce_receipt = {
                "schema": "mindburn.release-authority-ruleset-transition/v1",
                "operation": "bootstrap-enforce-resumed",
                "candidate_workflow_sha": args.candidate_sha,
                "candidate_workflow_ref": args.candidate_ref,
            }
        else:
            enforcement_started = True
            enforce_receipt = transition(
                transition_args(
                    "bootstrap-enforce",
                    candidate_sha=args.candidate_sha,
                    candidate_ref=args.candidate_ref,
                ),
                ruleset_client,
            )
            enforced = True
        write_json(args.output_dir / "ruleset-enforce.json", enforce_receipt)

        liveness_started = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=2)
        reopen_pull_request(
            merge_client,
            repository=REPOSITORY,
            pull_request=args.candidate_pr,
            head_sha=args.candidate_sha,
            base_sha=ratification["base_sha"],
            head_ref=head_ref,
        )
        liveness_dir = args.output_dir / "authority-liveness"
        liveness_dir.mkdir()
        liveness_args = argparse.Namespace(
            repository=REPOSITORY,
            pull_request=args.candidate_pr,
            head_sha=args.candidate_sha,
            started_at=liveness_started.isoformat().replace("+00:00", "Z"),
            expected_workflow_sha=args.candidate_sha,
            expected_authority=args.candidate_authority,
            kernel_verifier=args.permit_verifier,
            output=liveness_dir / "release-permit.json",
            bundle=liveness_dir / "release-permit.attestation.json",
            context=liveness_dir / "context.json",
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
        liveness = wait_for_canary(liveness_args, observer_client)
        write_json(liveness_dir / "receipt.json", liveness)

        human_receipt = remove_human_approval_gates(
            argparse.Namespace(
                candidate_sha=args.candidate_sha,
                candidate_ref=args.candidate_ref,
                contract=args.bootstrap_contract,
            ),
            admin_client,
        )
        write_json(args.output_dir / "human-gate-removal.json", human_receipt)

        ready = {
            "schema": READY_SCHEMA,
            "repository": REPOSITORY,
            "pull_request": args.candidate_pr,
            "base_sha": ratification["base_sha"],
            "candidate_sha": args.candidate_sha,
            "candidate_ref": args.candidate_ref,
            "candidate_tree_sha": promotion["candidate_tree_sha"],
            "ratification_permit_id": ratification["permit_id"],
            "ratification_run_id": ratification["run_id"],
            "liveness_permit_id": liveness["permit_id"],
            "liveness_run_id": liveness["run_id"],
            "liveness_run_attempt": liveness["run_attempt"],
            "merge_sha": liveness["merge_sha"],
            "merge_tree_sha": liveness["merge_tree_sha"],
            "evidence_sha256": {
                "authority_suite": sha256_file(promoter_path),
                "control_plane": sha256_file(args.output_dir / "control-plane-before.json"),
                "control_plane_observer": sha256_file(
                    args.output_dir / "control-plane-observer.json",
                ),
                "human_gate_removal": sha256_file(args.output_dir / "human-gate-removal.json"),
                "liveness_bundle": sha256_file(liveness_args.bundle),
                "liveness_context": sha256_file(liveness_args.context),
                "liveness_permit": sha256_file(liveness_args.output),
                "ratification_bundle": sha256_file(args.permit_bundle),
                "ratification_context": sha256_file(args.trusted_context),
                "ratification_permit": sha256_file(args.permit),
                "suite_trigger": sha256_file(trigger_path),
            },
        }
        write_json(args.output_dir / "bootstrap-ready.json", ready)
        return ready
    except Exception:
        if staged and not enforced and not enforcement_started:
            try:
                restore = transition(
                    transition_args(
                        "bootstrap-restore",
                        candidate_sha=args.candidate_sha,
                        candidate_ref=args.candidate_ref,
                    ),
                    ruleset_client,
                )
                write_json(args.output_dir / "ruleset-compensation.json", restore)
            except Exception as compensation_error:
                raise PermitInputError(
                    f"bootstrap prepare and candidate compensation failed: {compensation_error}",
                ) from compensation_error
        raise


def validate_ready(args: argparse.Namespace) -> dict[str, Any]:
    ready = load_json_file(args.ready, label="bootstrap-ready receipt")
    require_exact_keys(
        ready,
        required={
            "schema",
            "repository",
            "pull_request",
            "base_sha",
            "candidate_sha",
            "candidate_ref",
            "candidate_tree_sha",
            "ratification_permit_id",
            "ratification_run_id",
            "liveness_permit_id",
            "liveness_run_id",
            "liveness_run_attempt",
            "merge_sha",
            "merge_tree_sha",
            "evidence_sha256",
        },
        label="bootstrap-ready receipt",
    )
    if ready["schema"] != READY_SCHEMA or ready["repository"] != REPOSITORY:
        raise PermitInputError("unsupported bootstrap-ready receipt")
    for field in ("base_sha", "candidate_sha", "candidate_tree_sha", "merge_sha", "merge_tree_sha"):
        require_sha(ready[field], label=f"bootstrap-ready {field}", length=40)
    if ready["candidate_sha"] != args.candidate_sha or ready["pull_request"] != args.candidate_pr:
        raise PermitInputError("bootstrap-ready receipt names the wrong candidate")
    return ready


def confirmed_or_atomic_merge(
    ready: dict[str, Any],
    client: GitHubMergeClient,
) -> dict[str, Any]:
    main = client.get(f"/repos/{REPOSITORY}/git/ref/heads/main")
    main_sha = nested_string(main, "object", "sha", label="main SHA")
    merge_args = argparse.Namespace(
        pull_request=ready["pull_request"],
        base_sha=ready["base_sha"],
        head_sha=ready["candidate_sha"],
        merge_sha=ready["merge_sha"],
        tree_sha=ready["merge_tree_sha"],
    )
    if main_sha == ready["base_sha"]:
        return atomic_merge(merge_args, client)
    if main_sha != ready["merge_sha"]:
        raise PermitInputError("authority main is outside the resumable bootstrap states")
    pull_request = client.get(f"/repos/{REPOSITORY}/pulls/{ready['pull_request']}")
    validate_pull_request(
        pull_request,
        number=ready["pull_request"],
        base_sha=ready["base_sha"],
        head_sha=ready["candidate_sha"],
        merged=True,
        merge_sha=ready["merge_sha"],
    )
    merge_commit = client.get(f"/repos/{REPOSITORY}/git/commits/{ready['merge_sha']}")
    parents = merge_commit.get("parents")
    if (
        not isinstance(parents, list)
        or [parent.get("sha") for parent in parents if isinstance(parent, dict)]
        != [ready["base_sha"], ready["candidate_sha"]]
        or nested_string(merge_commit, "tree", "sha", label="merge tree SHA")
        != ready["merge_tree_sha"]
    ):
        raise PermitInputError("existing bootstrap merge commit drifted")
    return {
        "schema": "mindburn.release-authority-atomic-merge/v1",
        "repository": REPOSITORY,
        "pull_request": ready["pull_request"],
        "base_sha": ready["base_sha"],
        "head_sha": ready["candidate_sha"],
        "merge_sha": ready["merge_sha"],
        "merge_tree_sha": ready["merge_tree_sha"],
        "ref": MAIN_REF,
        "force": False,
    }


def finalize(args: argparse.Namespace, token: str, observer_token: str) -> dict[str, Any]:
    args.candidate_sha = require_sha(args.candidate_sha, label="candidate_sha", length=40)
    args.candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    ready = validate_ready(args)
    if ready["candidate_ref"] != args.candidate_ref:
        raise PermitInputError("bootstrap-ready receipt names the wrong candidate ref")

    read_client = GitHubReadClient(observer_token)
    merge_client = GitHubMergeClient(token)
    ruleset_client = GitHubRulesetClient(token)
    admin_client = GitHubAdminClient(token)
    ratification, promotion = verify_ratification(
        args,
        attestation_token=observer_token,
    )
    if promotion["candidate_tree_sha"] != ready["candidate_tree_sha"]:
        raise PermitInputError("ratification tree does not match bootstrap-ready receipt")
    verify_control(args, read_client)

    liveness_dir = args.ready.parent / "authority-liveness"
    liveness_permit_path = liveness_dir / "release-permit.json"
    liveness_bundle_path = liveness_dir / "release-permit.attestation.json"
    liveness_context_path = liveness_dir / "context.json"
    paths = {
        "authority_suite": args.ready.parent / "authority-suite.json",
        "control_plane": args.ready.parent / "control-plane-before.json",
        "control_plane_observer": args.ready.parent / "control-plane-observer.json",
        "human_gate_removal": args.ready.parent / "human-gate-removal.json",
        "liveness_bundle": liveness_bundle_path,
        "liveness_context": liveness_context_path,
        "liveness_permit": liveness_permit_path,
        "ratification_bundle": args.permit_bundle,
        "ratification_context": args.trusted_context,
        "ratification_permit": args.permit,
        "suite_trigger": args.ready.parent / "suite-trigger.json",
    }
    if {name: sha256_file(path) for name, path in paths.items()} != ready["evidence_sha256"]:
        raise PermitInputError("bootstrap evidence digest mismatch")

    liveness_run = read_client.get_json(
        f"/repos/{REPOSITORY}/actions/runs/{ready['liveness_run_id']}",
    )
    liveness = verify_candidate_permit(
        liveness_permit_path,
        liveness_bundle_path,
        liveness_context_path,
        run=liveness_run,
        repository=REPOSITORY,
        pull_request=args.candidate_pr,
        head_sha=args.candidate_sha,
        expected_workflow_sha=args.candidate_sha,
        expected_authority=load_json_file(args.candidate_authority, label="candidate authority"),
        kernel_verifier=args.permit_verifier,
        attestation_token=observer_token,
    )
    if (
        liveness["permit_id"] != ready["liveness_permit_id"]
        or liveness["merge_sha"] != ready["merge_sha"]
        or liveness["merge_tree_sha"] != ready["merge_tree_sha"]
    ):
        raise PermitInputError("liveness permit does not match bootstrap-ready receipt")

    stable = get_ruleset(ruleset_client, STABLE_RULESET_ID)
    try:
        validate_ruleset(
            stable.body,
            kind="stable",
            expected_sha=args.candidate_sha,
            expected_ref=args.candidate_ref,
        )
        machine_sha = args.candidate_sha
        machine_ref = args.candidate_ref
    except PermitInputError:
        validate_ruleset(
            stable.body,
            kind="stable",
            expected_sha=ready["merge_sha"],
            expected_ref=RULESET_MAIN_REF,
        )
        machine_sha = ready["merge_sha"]
        machine_ref = RULESET_MAIN_REF
    human_receipt = remove_human_approval_gates(
        argparse.Namespace(
            candidate_sha=machine_sha,
            candidate_ref=machine_ref,
            contract=args.bootstrap_contract,
        ),
        admin_client,
    )
    merge_receipt = confirmed_or_atomic_merge(ready, merge_client)
    ruleset_receipt = transition(
        transition_args(
            "bootstrap-finalize",
            candidate_sha=args.candidate_sha,
            candidate_ref=args.candidate_ref,
            merge_sha=ready["merge_sha"],
        ),
        ruleset_client,
    )
    for ruleset_id, kind in (
        (STABLE_RULESET_ID, "stable"),
        (CANDIDATE_RULESET_ID, "candidate"),
    ):
        validate_ruleset(
            get_ruleset(ruleset_client, ruleset_id).body,
            kind=kind,
            expected_sha=ready["merge_sha"],
            expected_ref=RULESET_MAIN_REF,
        )
    if ratification["permit_id"] != ready["ratification_permit_id"]:
        raise PermitInputError("ratification permit changed during finalization")
    return {
        "schema": FINAL_SCHEMA,
        "decision": "ALLOW",
        "repository": REPOSITORY,
        "pull_request": ready["pull_request"],
        "candidate_sha": ready["candidate_sha"],
        "merge_sha": ready["merge_sha"],
        "merge_tree_sha": ready["merge_tree_sha"],
        "ratification_permit_id": ready["ratification_permit_id"],
        "liveness_permit_id": ready["liveness_permit_id"],
        "machine_rulesets": [STABLE_RULESET_ID, CANDIDATE_RULESET_ID],
        "public_human_gate_removal": human_receipt,
        "atomic_merge": merge_receipt,
        "ruleset_finalization": ruleset_receipt,
    }


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--permit", type=Path, required=True)
    parser.add_argument("--permit-bundle", type=Path, required=True)
    parser.add_argument("--trusted-context", type=Path, required=True)
    parser.add_argument("--permit-verifier", type=Path, required=True)
    parser.add_argument("--candidate-repository", type=Path, required=True)
    parser.add_argument("--candidate-authority", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--candidate-pr", type=int, required=True)
    parser.add_argument("--control-contract", type=Path, required=True)
    parser.add_argument("--adversarial-corpus", type=Path, required=True)
    parser.add_argument("--bootstrap-contract", type=Path, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    add_common(prepare_parser)
    prepare_parser.add_argument("--output-dir", type=Path, required=True)
    prepare_parser.add_argument("--timeout-seconds", type=int, default=1800)
    prepare_parser.add_argument("--poll-seconds", type=int, default=15)
    finalize_parser = subparsers.add_parser("finalize")
    add_common(finalize_parser)
    finalize_parser.add_argument("--ready", type=Path, required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        token = os.environ.get("GH_TOKEN", "")
        observer_token = os.environ.get("HELM_AUTHORITY_BOOTSTRAP_OBSERVER_TOKEN", "")
        if not token:
            raise PermitInputError("GH_TOKEN is required")
        if not observer_token:
            raise PermitInputError("HELM_AUTHORITY_BOOTSTRAP_OBSERVER_TOKEN is required")
        if token == observer_token:
            raise PermitInputError("bootstrap executor and observer tokens must be distinct")
        if args.command == "prepare":
            if not 60 <= args.timeout_seconds <= 3600:
                raise PermitInputError("timeout_seconds must be between 60 and 3600")
            if not 5 <= args.poll_seconds <= 60:
                raise PermitInputError("poll_seconds must be between 5 and 60")
            result = prepare(args, token, observer_token)
        else:
            result = finalize(args, token, observer_token)
            write_json(args.output, result)
        sys.stdout.buffer.write(canonical_json(result))
    except (KeyError, OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"bootstrap-authority: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
