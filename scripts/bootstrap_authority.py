#!/usr/bin/env python3
"""Execute the one-time, evidence-gated generation-1 authority bootstrap."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

from atomic_merge_authority import (
    GitHubMergeClient,
    MAIN_REF,
    REPOSITORY,
    atomic_merge,
    nested_string,
    validate_pull_request,
    verify_merger_installation,
)
from authority_evidence_ledger import (
    LEDGER_REF,
    GitHubLedgerClient,
    append_record,
    stable_record_descriptor,
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
from autonomous_release_controller import (
    validate_contract as validate_controller_contract,
)
from configure_machine_approval_gates import (
    GitHubAdminClient,
    configure_machine_approval_gates,
    controlled_ruleset,
    require_object,
    validate_merger,
)
from submit_machine_approval import (
    APPROVER_APP_ID,
    APPROVER_INSTALLATION_ID,
    APPROVER_SLUG,
    GitHubApprovalClient,
    submit_machine_approval,
    verify_installation,
)
from verify_authority_promotion import (
    REVIEW_EVIDENCE_FILENAMES,
    git_blob,
    verify as verify_promotion,
)
from verify_control_plane import (
    AUTHORITY_REPOSITORY,
    CONTROL_BRANCH,
    CONTROL_REF,
    CONTROL_RULESET_NAME,
    load_json,
    validate_contract,
    verify_live_control_workflow,
    verify_live_environments,
    verify_live_repository_settings,
)
from wait_for_authority_canary import (
    WORKFLOW_NAME,
    WORKFLOW_PATH,
    GitHubReadClient,
    artifact_for_run,
    extract_attested_permit,
    extract_trusted_context,
    load_json_file,
    verify_attestation,
    verify_candidate_permit,
    wait_for_canary,
    write_raw_model_review_evidence,
)
from wait_for_authority_suite import wait_for_suite


READY_SCHEMA = "mindburn.release-authority-bootstrap-ready/v3"
FINAL_SCHEMA = "mindburn.release-authority-bootstrap/v3"
TRIGGER_SCHEMA = "mindburn.release-authority-suite-trigger/v1"
LAB_REPOSITORY = "Mindburn-Labs/contracts-autonomous-release-lab"
OBSERVER_APP_ID = 4296957
OBSERVER_INSTALLATION_ID = 146542079
OBSERVER_SLUG = "helm-authority-observer"
OBSERVER_REPOSITORIES = {
    REPOSITORY,
    "Mindburn-Labs/helm-ai-kernel",
    LAB_REPOSITORY,
}
OBSERVER_PERMISSIONS = {
    "actions": "read",
    "attestations": "read",
    "contents": "read",
    "pull_requests": "read",
    "organization_administration": "write",
}
CANDIDATE_ARGUMENT_SOURCE_INPUTS = {
    "candidate_authority": "config/autonomous-release-authority.json",
    "control_contract": "config/autonomous-release-control-plane.json",
    "adversarial_corpus": "tests/fixtures/autonomous-release-adversarial.json",
    "bootstrap_contract": "config/autonomous-release-bootstrap-v1.json",
    "controller_contract": "config/autonomous-release-controller.json",
}
CANDIDATE_LOCAL_SOURCE_INPUTS = (
    "config/autonomous-release-ci-template.yml",
    "scripts/atomic_merge_authority.py",
    "scripts/authority_evidence_ledger.py",
    "scripts/authority_ruleset_broker.py",
    "scripts/autonomous_release_controller.py",
    "scripts/autonomous_release_permit.py",
    "scripts/bootstrap_authority.py",
    "scripts/configure_machine_approval_gates.py",
    "scripts/observe_authority_promotion.py",
    "scripts/submit_machine_approval.py",
    "scripts/verify_authority_promotion.py",
    "scripts/verify_control_plane.py",
    "scripts/wait_for_authority_canary.py",
    "scripts/wait_for_authority_suite.py",
    "tests/test_authority_evidence_ledger.py",
    "tests/test_autonomous_release_controller.py",
    "tests/test_bootstrap_authority.py",
    "tests/test_configure_machine_approval_gates.py",
)
DISABLED_ENVIRONMENT_PAYLOAD = {
    "wait_timer": 0,
    "prevent_self_review": False,
    "reviewers": [],
    "deployment_branch_policy": {
        "protected_branches": False,
        "custom_branch_policies": True,
    },
}
READY_EVIDENCE_NAMES = {
    "authority_suite",
    "authority_suite_observer",
    "suite_evidence",
    "suite_evidence_observer",
    "credential_preflight",
    "source_inputs",
    "parent_verifier",
    "control_plane",
    "control_plane_observer",
    "control_environments_disabled",
    "controller_baselines",
    "repository_settings",
    "machine_approval",
    "machine_gates",
    "evidence_ledger_seed",
    "liveness_bundle",
    "liveness_context",
    "liveness_permit",
    "liveness_evidence",
    "ratification_bundle",
    "ratification_context",
    "ratification_permit",
    "ratification_evidence",
    "suite_trigger",
}


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence_tree_receipt(root: Path) -> dict[str, Any]:
    """Bind every regular evidence file without trusting directory metadata."""
    if not root.is_dir() or root.is_symlink():
        raise PermitInputError(f"evidence tree is not a regular directory: {root}")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PermitInputError(f"evidence tree contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PermitInputError(f"evidence tree contains a special file: {path}")
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    if not entries:
        raise PermitInputError(f"evidence tree is empty: {root}")
    return {
        "schema": "mindburn.release-authority-evidence-tree/v1",
        "entries": entries,
    }


def verify_candidate_source_inputs(args: argparse.Namespace) -> dict[str, str]:
    repository = args.candidate_repository.resolve()
    local_root = Path(__file__).resolve().parents[1]
    receipts: dict[str, str] = {}
    inputs = [
        (getattr(args, argument), source_path)
        for argument, source_path in CANDIDATE_ARGUMENT_SOURCE_INPUTS.items()
    ] + [
        (local_root / source_path, source_path)
        for source_path in CANDIDATE_LOCAL_SOURCE_INPUTS
    ]
    for local_path, source_path in inputs:
        source = git_blob(repository, args.candidate_sha, source_path)
        if local_path.read_bytes() != source:
            raise PermitInputError(
                f"bootstrap input {source_path} is not the reviewed candidate blob"
            )
        receipts[source_path] = hashlib.sha256(source).hexdigest()
    return receipts


def extract_kernel_source(repository: Path, kernel_sha: str, destination: Path) -> None:
    process = subprocess.run(
        ["git", "-C", str(repository), "archive", "--format=tar", kernel_sha, "core"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(f"cannot archive exact Kernel {kernel_sha}: {detail}")
    try:
        with tarfile.open(fileobj=io.BytesIO(process.stdout), mode="r:") as archive:
            members = archive.getmembers()
            if any(member.issym() or member.islnk() for member in members):
                raise PermitInputError("exact Kernel archive cannot contain links")
            archive.extractall(destination, filter="data")
    except (tarfile.TarError, ValueError) as exc:
        raise PermitInputError("exact Kernel archive is invalid") from exc


def build_exact_kernel_verifier(
    repository: Path,
    kernel_sha: str,
    destination: Path,
) -> dict[str, Any]:
    kernel_sha = require_sha(kernel_sha, label="Kernel source SHA", length=40)
    source_dir = destination / "source"
    source_dir.mkdir(parents=True, exist_ok=False)
    extract_kernel_source(repository.resolve(), kernel_sha, source_dir)
    binary = destination / "release-permit-verify"
    process = subprocess.run(
        [
            "go",
            "build",
            "-buildvcs=false",
            "-trimpath",
            "-ldflags=-buildid=",
            "-o",
            str(binary),
            "./cmd/release-permit-verify",
        ],
        cwd=source_dir / "core",
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(
            f"cannot build exact Kernel verifier {kernel_sha}: {detail}"
        )
    if not binary.is_file():
        raise PermitInputError("exact Kernel build emitted no verifier")
    receipt = {
        "schema": "mindburn.release-authority-kernel-verifier-build/v1",
        "kernel_sha": kernel_sha,
        "binary_sha256": sha256_file(binary),
        "command": [
            "go",
            "build",
            "-buildvcs=false",
            "-trimpath",
            "-ldflags=-buildid=",
            "./cmd/release-permit-verify",
        ],
    }
    write_json(destination / "receipt.json", receipt)
    return {"binary": binary, "receipt": receipt}


def authority_kernel_shas(args: argparse.Namespace) -> tuple[str, str]:
    permit = load_json_file(args.permit, label="generation-1 ratification permit")
    parent = permit.get("authority")
    if not isinstance(parent, dict):
        raise PermitInputError("ratification permit has no authority object")
    parent_sha = require_sha(
        parent.get("kernel_sha"),
        label="ratification authority kernel_sha",
        length=40,
    )
    candidate = load_json_file(args.candidate_authority, label="candidate authority")
    candidate_sha = require_sha(
        candidate.get("kernel_sha"),
        label="candidate authority kernel_sha",
        length=40,
    )
    if candidate_sha != parent_sha:
        raise PermitInputError(
            "bootstrap cannot change the Kernel without a separately ratified "
            "Kernel-upgrade protocol"
        )
    return parent_sha, candidate_sha


def nested(value: dict[str, Any], *keys: str, label: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            raise PermitInputError(f"GitHub response is missing {label}")
        current = current.get(key)
    return current


def ensure_evidence_ledger_seed(
    client: GitHubMergeClient,
    *,
    expected_sha: str,
) -> dict[str, Any]:
    expected_sha = require_sha(
        expected_sha, label="evidence ledger seed SHA", length=40
    )
    commit = client.get(f"/repos/{REPOSITORY}/git/commits/{expected_sha}")
    root_tree_sha = require_sha(
        nested(commit, "tree", "sha", label="candidate root tree SHA"),
        label="candidate root tree SHA",
        length=40,
    )
    root_tree = client.get(f"/repos/{REPOSITORY}/git/trees/{root_tree_sha}")
    root_entries = root_tree.get("tree")
    if root_tree.get("truncated") is True or not isinstance(root_entries, list):
        raise PermitInputError("candidate root tree cannot be checked for ledger paths")
    helm_entries = [
        entry
        for entry in root_entries
        if isinstance(entry, dict) and entry.get("path") == ".helm"
    ]
    if len(helm_entries) > 1:
        raise PermitInputError("candidate root tree contains duplicate .helm entries")
    if helm_entries:
        helm_entry = helm_entries[0]
        if helm_entry.get("type") != "tree":
            raise PermitInputError("candidate reserves .helm as a non-directory")
        helm_tree_sha = require_sha(
            helm_entry.get("sha"), label="candidate .helm tree SHA", length=40
        )
        helm_tree = client.get(f"/repos/{REPOSITORY}/git/trees/{helm_tree_sha}")
        helm_children = helm_tree.get("tree")
        if helm_tree.get("truncated") is True or not isinstance(helm_children, list):
            raise PermitInputError(
                "candidate .helm tree cannot be checked for ledger paths"
            )
        if any(
            isinstance(entry, dict) and entry.get("path") == "evidence"
            for entry in helm_children
        ):
            raise PermitInputError(
                "reviewed candidate must not pre-seed the reserved .helm/evidence tree"
            )
    ref_path = LEDGER_REF.removeprefix("refs/")
    path = f"/repos/{REPOSITORY}/git/ref/{ref_path}"
    try:
        ref = client.get(path)
        created = False
    except PermitInputError as exc:
        if "failed with HTTP 404:" not in str(exc):
            raise
        ref = client.request(
            "POST",
            f"/repos/{REPOSITORY}/git/refs",
            payload={"ref": LEDGER_REF, "sha": expected_sha},
        )
        created = True
    if (
        ref.get("ref") != LEDGER_REF
        or not isinstance(ref.get("object"), dict)
        or ref["object"].get("sha") != expected_sha
    ):
        raise PermitInputError("evidence ledger seed ref is not exact")
    confirmed = client.get(path)
    if (
        confirmed.get("ref") != LEDGER_REF
        or not isinstance(confirmed.get("object"), dict)
        or confirmed["object"].get("sha") != expected_sha
    ):
        raise PermitInputError("evidence ledger seed ref drifted after creation")
    return {
        "schema": "mindburn.authority-evidence-ledger-seed/v1",
        "repository": REPOSITORY,
        "ref": LEDGER_REF,
        "sha": expected_sha,
        "created": created,
    }


def verify_evidence_ledger_descendant(
    client: GitHubMergeClient,
    *,
    seed_sha: str,
) -> dict[str, Any]:
    seed_sha = require_sha(seed_sha, label="evidence ledger seed SHA", length=40)
    ref_path = LEDGER_REF.removeprefix("refs/")
    ref = client.get(f"/repos/{REPOSITORY}/git/ref/{ref_path}")
    if ref.get("ref") != LEDGER_REF or not isinstance(ref.get("object"), dict):
        raise PermitInputError("evidence ledger ref is malformed")
    head_sha = require_sha(
        ref["object"].get("sha"), label="evidence ledger head SHA", length=40
    )
    advanced = head_sha != seed_sha
    if advanced:
        comparison = client.get(f"/repos/{REPOSITORY}/compare/{seed_sha}...{head_sha}")
        if (
            comparison.get("status") != "ahead"
            or not isinstance(comparison.get("merge_base_commit"), dict)
            or comparison["merge_base_commit"].get("sha") != seed_sha
            or comparison.get("ahead_by", 0) <= 0
            or comparison.get("behind_by") != 0
        ):
            raise PermitInputError("evidence ledger head is not a seed descendant")
    return {
        "schema": "mindburn.authority-evidence-ledger-state/v1",
        "repository": REPOSITORY,
        "ref": LEDGER_REF,
        "seed_sha": seed_sha,
        "head_sha": head_sha,
        "advanced": advanced,
    }


def evidence_tree_inputs(root: Path, *, prefix: str) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise PermitInputError(f"evidence tree {prefix} is not a regular directory")
    resolved_root = root.resolve(strict=True)
    result: dict[str, bytes] = {}
    for path in sorted(resolved_root.rglob("*")):
        if path.is_symlink():
            raise PermitInputError(f"evidence tree {prefix} contains a symbolic link")
        if path.is_file():
            relative = path.relative_to(resolved_root).as_posix()
            result[f"{prefix}/{relative}"] = path.read_bytes()
    if not result:
        raise PermitInputError(f"evidence tree {prefix} is empty")
    return result


def verify_controller_baselines(
    args: argparse.Namespace,
    client: GitHubReadClient,
) -> dict[str, Any]:
    contract = validate_controller_contract(
        load_json_file(args.controller_contract, label="controller contract")
    )
    baseline = contract["evidence_ledger"]["baseline_main"][
        "Mindburn-Labs/helm-ai-kernel"
    ]
    kernel_ref = client.get_json(
        "/repos/Mindburn-Labs/helm-ai-kernel/git/ref/heads/main"
    )
    kernel_main = nested_string(kernel_ref, "object", "sha", label="Kernel main SHA")
    if kernel_main != baseline:
        raise PermitInputError(
            "Kernel main moved beyond the controller ledger baseline"
        )
    if contract["evidence_ledger"]["bootstrap_pr"] != args.candidate_pr:
        raise PermitInputError("controller bootstrap PR identity drifted")
    return {
        "schema": "mindburn.autonomous-release-controller-baselines/v1",
        "authority_repository": REPOSITORY,
        "authority_baseline": "active-workflow",
        "kernel_repository": "Mindburn-Labs/helm-ai-kernel",
        "kernel_main_sha": kernel_main,
    }


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
        or nested(
            current, "head", "repo", "full_name", label="pull request head repository"
        )
        != repository
    ):
        raise PermitInputError(
            f"{repository}#{pull_request} does not match the proof contract"
        )
    if (
        base_sha is not None
        and nested(current, "base", "sha", label="base SHA") != base_sha
    ):
        raise PermitInputError(
            f"{repository}#{pull_request} base moved before proof trigger"
        )
    if (
        head_ref is not None
        and nested(current, "head", "ref", label="head ref") != head_ref
    ):
        raise PermitInputError(f"{repository}#{pull_request} head ref drifted")
    if current.get("state") == "open":
        current = client.request("PATCH", path, payload={"state": "closed"})
        if current.get("state") != "closed":
            raise PermitInputError(f"GitHub did not close {repository}#{pull_request}")
    reopened = client.request("PATCH", path, payload={"state": "open"})
    if (
        reopened.get("state") != "open"
        or nested(reopened, "head", "sha", label="reopened head SHA") != head_sha
        or (
            base_sha is not None
            and nested(reopened, "base", "sha", label="reopened base SHA") != base_sha
        )
        or (
            head_ref is not None
            and nested(reopened, "head", "ref", label="reopened head ref") != head_ref
        )
    ):
        raise PermitInputError(
            f"GitHub did not reopen exact {repository}#{pull_request}"
        )
    return reopened


def trigger_suite(
    contract: dict[str, Any],
    client: GitHubMergeClient,
    *,
    workflow_sha: str,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
        seconds=2
    )
    main_ref = client.get(f"/repos/{LAB_REPOSITORY}/git/ref/heads/main")
    if (
        main_ref.get("ref") != "refs/heads/main"
        or nested(main_ref, "object", "sha", label="lab main SHA")
        != contract["adversarial_suite"]["cases"][0]["base_sha"]
    ):
        raise PermitInputError("proof-lab main drifted before suite trigger")
    for case in contract["adversarial_suite"]["cases"]:
        reopen_pull_request(
            client,
            repository=LAB_REPOSITORY,
            pull_request=case["pull_request"],
            head_sha=case["head_sha"],
            base_sha=case["base_sha"],
            head_ref=case["head_ref"],
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
    kernel_verifier: Path,
) -> argparse.Namespace:
    return argparse.Namespace(
        contract=args.control_contract,
        adversarial_corpus=args.adversarial_corpus,
        trigger=trigger,
        expected_workflow_sha=args.candidate_sha,
        expected_authority=args.candidate_authority,
        kernel_verifier=kernel_verifier,
        output_dir=output_dir,
        timeout_seconds=args.timeout_seconds,
        poll_seconds=args.poll_seconds,
    )


def verify_ratification(
    args: argparse.Namespace,
    *,
    attestation_token: str,
    kernel_verifier: Path,
    replay_dir: Path,
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
    observer = GitHubReadClient(attestation_token)
    run_id = permit.get("run_id")
    run_attempt = permit.get("run_attempt")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value <= 0
        for value in (run_id, run_attempt)
    ):
        raise PermitInputError("bootstrap ratification run identity is invalid")
    run = observer.get_json(f"/repos/{REPOSITORY}/actions/runs/{run_id}")
    if (
        run.get("name") != WORKFLOW_NAME
        or run.get("path") != WORKFLOW_PATH
        or run.get("event") != "pull_request"
        or run.get("head_sha") != args.candidate_sha
        or run.get("run_attempt") != run_attempt
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise PermitInputError(
            "bootstrap ratification is not the exact successful parent workflow run"
        )
    permit_artifact_id = artifact_for_run(observer, REPOSITORY, run_id)
    context_artifact_id = artifact_for_run(
        observer,
        REPOSITORY,
        run_id,
        "release-permit-input",
    )
    if permit_artifact_id is None or context_artifact_id is None:
        raise PermitInputError(
            "bootstrap ratification run lacks permit or context evidence"
        )
    live_permit, live_bundle = extract_attested_permit(
        observer.get_bytes(
            f"/repos/{REPOSITORY}/actions/artifacts/{permit_artifact_id}/zip",
            accept="application/vnd.github+json",
        )
    )
    live_context = extract_trusted_context(
        observer.get_bytes(
            f"/repos/{REPOSITORY}/actions/artifacts/{context_artifact_id}/zip",
            accept="application/vnd.github+json",
        )
    )
    if (
        live_permit != args.permit.read_bytes()
        or live_bundle != args.permit_bundle.read_bytes()
        or live_context != args.trusted_context.read_bytes()
    ):
        raise PermitInputError(
            "bootstrap ratification inputs are not the exact run artifacts"
        )
    live_reviews = replay_dir / "live-review-evidence"
    write_raw_model_review_evidence(
        observer,
        REPOSITORY,
        run_id,
        live_reviews,
    )
    supplied_reviews = args.review_evidence_dir.resolve()
    try:
        supplied_entries = list(supplied_reviews.iterdir())
    except OSError as exc:
        raise PermitInputError(f"cannot read supplied review evidence: {exc}") from exc
    if (
        {entry.name for entry in supplied_entries} != REVIEW_EVIDENCE_FILENAMES
        or any(not entry.is_file() or entry.is_symlink() for entry in supplied_entries)
        or any(
            (supplied_reviews / name).read_bytes() != (live_reviews / name).read_bytes()
            for name in REVIEW_EVIDENCE_FILENAMES
        )
    ):
        raise PermitInputError(
            "supplied raw review evidence is not the exact ratification-run artifact"
        )
    promotion = verify_promotion(
        argparse.Namespace(
            permit_verifier=kernel_verifier,
            permit=args.permit,
            trusted_context=args.trusted_context,
            review_evidence_dir=live_reviews,
            recomputed_permit=replay_dir / "parent-recomputed-permit.json",
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


def verify_control(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    deployment_disabled: bool = False,
    deployment_transition: bool = False,
    expected_control_sha: str | None = None,
    effective_only: bool = False,
) -> dict[str, Any]:
    contract = validate_contract(
        load_json(args.control_contract, label="control contract"),
        load_json(args.adversarial_corpus, label="adversarial corpus"),
    )
    return {
        "contract": contract,
        "repository_settings": verify_live_repository_settings(contract, client),
        "control_workflow": (
            verify_live_control_workflow(
                contract,
                client,
                expected_sha=expected_control_sha,
                effective_only=effective_only,
            )
            if expected_control_sha is not None
            else {}
        ),
        "environments": verify_live_environments(
            contract,
            client,
            deployment_disabled=deployment_disabled,
            deployment_transition=deployment_transition,
        ),
    }


def verify_finalization_control_prestate(
    args: argparse.Namespace,
    executor_client: GitHubReadClient,
    observer_client: GitHubReadClient,
    *,
    expected_control_sha: str,
) -> dict[str, Any]:
    contract = validate_contract(
        load_json(args.control_contract, label="control contract"),
        load_json(args.adversarial_corpus, label="adversarial corpus"),
    )
    executor_settings = verify_live_repository_settings(contract, executor_client)
    observer_settings = verify_live_repository_settings(contract, observer_client)
    if executor_settings != observer_settings:
        raise PermitInputError("independent repository-setting reads do not match")
    try:
        executor_lock = verify_live_control_workflow(
            contract,
            executor_client,
            expected_sha=expected_control_sha,
            effective_only=True,
        )
        observer_lock = verify_live_control_workflow(
            contract,
            observer_client,
            expected_sha=expected_control_sha,
            effective_only=True,
        )
    except ValueError:
        try:
            executor_environments = verify_live_environments(
                contract,
                executor_client,
                deployment_disabled=True,
            )
            observer_environments = verify_live_environments(
                contract,
                observer_client,
                deployment_disabled=True,
            )
        except ValueError as exc:
            raise PermitInputError(str(exc)) from exc
        state = "lock-pending-environments-disabled"
        control_workflow: dict[str, Any] = {}
    else:
        if executor_lock != observer_lock:
            raise PermitInputError("independent immutable-control reads do not match")
        executor_environments = verify_live_environments(
            contract,
            executor_client,
            deployment_transition=True,
        )
        observer_environments = verify_live_environments(
            contract,
            observer_client,
            deployment_transition=True,
        )
        state = "lock-proven-environments-transitioning"
        control_workflow = executor_lock
    if executor_environments != observer_environments:
        raise PermitInputError("independent environment reads do not match")
    return {
        "contract": contract,
        "state": state,
        "repository_settings": executor_settings,
        "control_workflow": control_workflow,
        "environments": executor_environments,
    }


def control_ruleset_payload(
    contract: dict[str, Any],
    *,
    staged: bool,
) -> dict[str, Any]:
    final = contract["control_workflow"]["ruleset"]
    if not staged:
        return final
    return {
        **final,
        "rules": [rule for rule in final["rules"] if rule.get("type") != "creation"],
    }


def install_control_workflow(
    contract: dict[str, Any],
    client: GitHubAdminClient,
    observer_client: GitHubReadClient,
    *,
    expected_sha: str,
) -> dict[str, Any]:
    expected_sha = require_sha(
        expected_sha,
        label="immutable control workflow SHA",
        length=40,
    )
    staged = control_ruleset_payload(contract, staged=True)
    final = control_ruleset_payload(contract, staged=False)
    listed = client.request("GET", "/orgs/Mindburn-Labs/rulesets?per_page=100")
    if not isinstance(listed.body, list):
        raise PermitInputError("GitHub control-ruleset list is malformed")
    matches = [
        item
        for item in listed.body
        if isinstance(item, dict) and item.get("name") == CONTROL_RULESET_NAME
    ]
    if len(matches) > 1:
        raise PermitInputError("multiple immutable control rulesets exist")
    if matches:
        ruleset_id = matches[0].get("id")
    else:
        created = require_object(
            client.request(
                "POST",
                "/orgs/Mindburn-Labs/rulesets",
                payload=staged,
            ),
            label="created immutable control ruleset",
        )
        ruleset_id = created.get("id")
    if not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise PermitInputError("immutable control ruleset ID is invalid")

    ruleset_path = f"/orgs/Mindburn-Labs/rulesets/{ruleset_id}"
    current_response = client.request("GET", ruleset_path)
    current = require_object(current_response, label="immutable control ruleset")
    state = controlled_ruleset(current)
    if state not in (staged, final):
        raise PermitInputError("immutable control ruleset is outside resumable states")

    refs_response = client.request(
        "GET",
        f"/repos/{AUTHORITY_REPOSITORY}/git/matching-refs/heads/{CONTROL_BRANCH}",
    )
    if not isinstance(refs_response.body, list):
        raise PermitInputError("GitHub control-ref list is malformed")
    exact_refs = [
        ref
        for ref in refs_response.body
        if isinstance(ref, dict) and ref.get("ref") == CONTROL_REF
    ]
    if len(exact_refs) > 1:
        raise PermitInputError("GitHub returned duplicate immutable control refs")
    if not exact_refs:
        if state == final:
            raise PermitInputError(
                "immutable control ref is absent behind a final ruleset"
            )
        created_ref = require_object(
            client.request(
                "POST",
                f"/repos/{AUTHORITY_REPOSITORY}/git/refs",
                payload={"ref": CONTROL_REF, "sha": expected_sha},
            ),
            label="created immutable control ref",
        )
        exact_refs = [created_ref]
    control_sha = nested(
        exact_refs[0],
        "object",
        "sha",
        label="immutable control ref SHA",
    )
    if control_sha != expected_sha:
        raise PermitInputError("immutable control ref names the wrong reviewed SHA")

    if state == staged:
        if not current_response.etag:
            raise PermitInputError("immutable control ruleset GET returned no ETag")
        refetched = client.request("GET", ruleset_path)
        if (
            refetched.body != current
            or refetched.etag != current_response.etag
            or controlled_ruleset(require_object(refetched, label="control ruleset"))
            != staged
        ):
            raise PermitInputError("immutable control ruleset changed before lock")
        client.request(
            "PUT",
            ruleset_path,
            payload=final,
            if_match=current_response.etag,
        )
    confirmed = require_object(
        client.request("GET", ruleset_path),
        label="confirmed immutable control ruleset",
    )
    if controlled_ruleset(confirmed) != final:
        raise PermitInputError("immutable control ruleset did not lock exactly")
    observed = verify_live_control_workflow(
        contract,
        observer_client,
        expected_sha=expected_sha,
        effective_only=True,
    )
    return {
        "schema": "mindburn.release-authority-control-installation/v1",
        "ruleset_id": ruleset_id,
        "ruleset_name": CONTROL_RULESET_NAME,
        "ref": CONTROL_REF,
        "sha": expected_sha,
        "observer": observed,
    }


def enable_control_environments(
    contract: dict[str, Any],
    client: GitHubAdminClient,
    observer_client: GitHubReadClient,
    *,
    expected_sha: str,
) -> list[dict[str, Any]]:
    verify_live_control_workflow(
        contract,
        observer_client,
        expected_sha=expected_sha,
        effective_only=True,
    )
    for environment in contract["environments"]:
        name = environment["name"]
        path = (
            f"/repos/{AUTHORITY_REPOSITORY}/environments/{name}"
            "/deployment-branch-policies"
        )
        listed = client.request("GET", path)
        if not isinstance(listed.body, dict):
            raise PermitInputError(
                f"environment {name} branch-policy list is malformed"
            )
        policies = [
            policy
            for policy in listed.body.get("branch_policies", [])
            if isinstance(policy, dict)
        ]
        normalized = sorted(
            (
                {"name": policy.get("name"), "type": policy.get("type")}
                for policy in policies
            ),
            key=lambda policy: (str(policy["type"]), str(policy["name"])),
        )
        expected = environment["branch_policies"]
        if normalized == expected and listed.body.get("total_count") == 1:
            continue
        if policies or listed.body.get("total_count") != 0:
            raise PermitInputError(
                f"environment {name} is not disabled or already controller-only"
            )
        created = require_object(
            client.request(
                "POST",
                path,
                payload=expected[0],
            ),
            label=f"environment {name} control branch policy",
        )
        if {"name": created.get("name"), "type": created.get("type")} != expected[0]:
            raise PermitInputError(f"environment {name} admitted the wrong branch")
    verify_live_control_workflow(
        contract,
        observer_client,
        expected_sha=expected_sha,
        effective_only=True,
    )
    return verify_live_environments(contract, observer_client)


def ensure_control_environments_disabled(
    contract: dict[str, Any],
    client: GitHubAdminClient,
    observer_client: GitHubReadClient,
) -> list[dict[str, Any]]:
    """Create or normalize every control environment before its first read.

    A missing environment is a normal first-install state.  The environment is
    deliberately left with no admitted branch until the immutable control ref
    and its creation lock have both been independently observed.
    """
    for expected in contract["environments"]:
        name = expected["name"]
        path = f"/repos/{AUTHORITY_REPOSITORY}/environments/{name}"
        configured = require_object(
            client.request(
                "PUT",
                path,
                payload=DISABLED_ENVIRONMENT_PAYLOAD,
            ),
            label=f"disabled environment {name}",
        )
        rule_types = sorted(
            rule.get("type")
            for rule in configured.get("protection_rules", [])
            if isinstance(rule, dict) and isinstance(rule.get("type"), str)
        )
        if rule_types != expected["protection_rule_types"]:
            raise PermitInputError(
                f"environment {name} retained a deployment protection rule"
            )
        if configured.get("can_admins_bypass") is not False:
            raise PermitInputError(
                f"environment {name} still permits administrator bypass"
            )
        if (
            configured.get("deployment_branch_policy")
            != expected["deployment_branch_policy"]
        ):
            raise PermitInputError(
                f"environment {name} did not accept the disabled branch policy"
            )

        policy_path = f"{path}/deployment-branch-policies"
        policies = require_object(
            client.request("GET", policy_path),
            label=f"disabled environment {name} branch policies",
        )
        branch_policies = policies.get("branch_policies")
        if not isinstance(branch_policies, list) or policies.get("total_count") != len(
            branch_policies
        ):
            raise PermitInputError(
                f"environment {name} returned malformed branch policies"
            )
        if branch_policies:
            expected_policy = expected["branch_policies"][0]
            if len(branch_policies) != 1:
                raise PermitInputError(
                    f"environment {name} has multiple admitted branches"
                )
            policy = branch_policies[0]
            if (
                not isinstance(policy, dict)
                or {"name": policy.get("name"), "type": policy.get("type")}
                != expected_policy
                or not isinstance(policy.get("id"), int)
                or isinstance(policy.get("id"), bool)
                or policy["id"] <= 0
            ):
                raise PermitInputError(f"environment {name} admits an unknown branch")
            client.request("DELETE", f"{policy_path}/{policy['id']}")
            policies = require_object(
                client.request("GET", policy_path),
                label=f"disabled environment {name} branch policies after disable",
            )
        if policies.get("total_count") != 0 or policies.get("branch_policies") != []:
            raise PermitInputError(
                f"environment {name} was not empty before controller lock"
            )

    return verify_live_environments(
        contract,
        observer_client,
        deployment_disabled=True,
    )


def ensure_recovery_head_ref_policy(client: GitHubMergeClient) -> dict[str, Any]:
    path = f"/repos/{REPOSITORY}"
    before = client.get(path).get("delete_branch_on_merge")
    if not isinstance(before, bool):
        raise PermitInputError(
            "GitHub did not return the authority branch-deletion setting"
        )
    if before:
        updated = client.request(
            "PATCH",
            path,
            payload={"delete_branch_on_merge": False},
        )
        if updated.get("delete_branch_on_merge") is not False:
            raise PermitInputError(
                "GitHub did not preserve authority heads for fail-closed recovery"
            )
    after = client.get(path).get("delete_branch_on_merge")
    if after is not False:
        raise PermitInputError(
            "authority head refs are not preserved for incomplete promotion"
        )
    return {
        "schema": "mindburn.release-authority-repository-settings/v1",
        "repository": REPOSITORY,
        "delete_branch_on_merge_before": before,
        "delete_branch_on_merge_after": after,
    }


def preflight_credentials(
    args: argparse.Namespace,
    executor_client: GitHubAdminClient,
    observer_client: GitHubReadClient,
    approval_client: GitHubApprovalClient,
    merger_client: GitHubMergeClient,
) -> dict[str, Any]:
    """Prove all bootstrap identities and read scopes before the first mutation."""
    executor = require_object(
        executor_client.request("GET", "/user"),
        label="bootstrap executor identity",
    )
    executor_login = executor.get("login")
    if not isinstance(executor_login, str) or not executor_login:
        raise PermitInputError("bootstrap executor identity has no login")
    membership = require_object(
        executor_client.request(
            "GET",
            "/user/memberships/orgs/Mindburn-Labs",
        ),
        label="bootstrap executor organization membership",
    )
    if membership.get("state") != "active" or membership.get("role") != "admin":
        raise PermitInputError(
            "bootstrap executor must be an active organization owner"
        )
    authority_repository = require_object(
        executor_client.request("GET", f"/repos/{REPOSITORY}"),
        label="bootstrap executor authority repository",
    )
    repository_permissions = authority_repository.get("permissions")
    if (
        not isinstance(repository_permissions, dict)
        or repository_permissions.get("admin") is not True
        or repository_permissions.get("push") is not True
    ):
        raise PermitInputError(
            "bootstrap executor lacks authority repository administration"
        )
    candidate = require_object(
        executor_client.request(
            "GET",
            f"/repos/{REPOSITORY}/pulls/{args.candidate_pr}",
        ),
        label="bootstrap candidate pull request",
    )
    if candidate.get("number") != args.candidate_pr:
        raise PermitInputError(
            "bootstrap executor read the wrong candidate pull request"
        )
    for ruleset_id in (STABLE_RULESET_ID, CANDIDATE_RULESET_ID):
        ruleset = require_object(
            executor_client.request(
                "GET",
                f"/orgs/Mindburn-Labs/rulesets/{ruleset_id}",
            ),
            label=f"bootstrap executor ruleset {ruleset_id}",
        )
        if ruleset.get("id") != ruleset_id:
            raise PermitInputError(
                "bootstrap executor read the wrong organization ruleset"
            )

    observer_installation = observer_client.get_json("/installation")
    observer_account = observer_installation.get("account")
    if (
        observer_installation.get("app_id") != OBSERVER_APP_ID
        or observer_installation.get("id") != OBSERVER_INSTALLATION_ID
        or not isinstance(observer_account, dict)
        or observer_account.get("login") != "Mindburn-Labs"
        or observer_installation.get("permissions") != OBSERVER_PERMISSIONS
    ):
        raise PermitInputError("bootstrap observer App identity or permissions drifted")
    observer_repositories = observer_client.get_json(
        "/installation/repositories?per_page=100"
    )
    repository_items = observer_repositories.get("repositories")
    if not isinstance(repository_items, list):
        raise PermitInputError("bootstrap observer repository scope is malformed")
    observer_names = {
        item.get("full_name") for item in repository_items if isinstance(item, dict)
    }
    if observer_names != OBSERVER_REPOSITORIES:
        raise PermitInputError("bootstrap observer repository scope is not exact")
    observer_ruleset = observer_client.get_json(
        f"/orgs/Mindburn-Labs/rulesets/{STABLE_RULESET_ID}"
    )
    if observer_ruleset.get("id") != STABLE_RULESET_ID:
        raise PermitInputError("bootstrap observer read the wrong organization ruleset")

    approver_installation = approval_client.request("GET", "/installation")
    approver_account = (
        approver_installation.get("account")
        if isinstance(approver_installation, dict)
        else None
    )
    if (
        not isinstance(approver_installation, dict)
        or approver_installation.get("app_id") != APPROVER_APP_ID
        or approver_installation.get("id") != APPROVER_INSTALLATION_ID
        or not isinstance(approver_account, dict)
        or approver_account.get("login") != "Mindburn-Labs"
        or approver_installation.get("permissions") != {"pull_requests": "write"}
    ):
        raise PermitInputError("bootstrap approver App identity or permissions drifted")
    approver = verify_installation(
        approval_client,
        repository=REPOSITORY,
        app_slug=APPROVER_SLUG,
        installation_id=APPROVER_INSTALLATION_ID,
    )
    bootstrap_contract = load_json(args.bootstrap_contract, label="bootstrap contract")
    merger_app_id = validate_merger(bootstrap_contract["merger"])
    if merger_app_id is None:
        raise PermitInputError("bootstrap merger App is disabled")
    merger_installation_id = bootstrap_contract["merger"]["installation_id"]
    verify_merger_installation(
        merger_client,
        app_slug="helm-authority-merger",
        installation_id=merger_installation_id,
        app_id=merger_app_id,
    )
    return {
        "schema": "mindburn.release-authority-bootstrap-credential-preflight/v1",
        "executor": {
            "login": executor_login,
            "organization": "Mindburn-Labs",
            "organization_role": membership["role"],
            "repository": REPOSITORY,
            "repository_admin": True,
        },
        "observer": {
            "app_id": OBSERVER_APP_ID,
            "app_slug": OBSERVER_SLUG,
            "installation_id": OBSERVER_INSTALLATION_ID,
            "permissions": OBSERVER_PERMISSIONS,
            "repositories": sorted(observer_names),
            "ruleset_read_scope": "GET-only client over provider write entitlement",
        },
        "approver": {
            "app_id": approver["app_id"],
            "app_slug": approver["app_slug"],
            "installation_id": approver["id"],
            "permissions": {"pull_requests": "write"},
            "repositories": [REPOSITORY],
        },
        "merger": {
            "app_id": merger_app_id,
            "app_slug": "helm-authority-merger",
            "installation_id": merger_installation_id,
            "permissions": {"contents": "write", "pull_requests": "read"},
            "repositories": [REPOSITORY],
        },
    }


def prepare(
    args: argparse.Namespace,
    token: str,
    observer_token: str,
    approver_token: str,
    merger_token: str,
) -> dict[str, Any]:
    args.candidate_sha = require_sha(
        args.candidate_sha, label="candidate_sha", length=40
    )
    args.candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    if args.candidate_pr <= 0:
        raise PermitInputError("candidate_pr must be positive")
    if args.output_dir.exists():
        raise PermitInputError("bootstrap output directory already exists")
    source_input_receipt = {
        "schema": "mindburn.release-authority-bootstrap-source-inputs/v1",
        "candidate_sha": args.candidate_sha,
        "sha256": verify_candidate_source_inputs(args),
    }
    parent_kernel_sha, _candidate_kernel_sha = authority_kernel_shas(args)

    read_client = GitHubReadClient(token)
    observer_client = GitHubReadClient(observer_token)
    merge_client = GitHubMergeClient(token)
    ruleset_client = GitHubRulesetClient(token)
    admin_client = GitHubAdminClient(token)
    approval_client = GitHubApprovalClient(approver_token)
    merger_client = GitHubMergeClient(merger_token)
    credential_preflight = preflight_credentials(
        args,
        admin_client,
        observer_client,
        approval_client,
        merger_client,
    )
    controller_baselines = verify_controller_baselines(args, observer_client)
    args.output_dir.mkdir(parents=True)
    source_input_path = args.output_dir / "source-inputs.json"
    write_json(source_input_path, source_input_receipt)
    credential_preflight_path = args.output_dir / "credential-preflight.json"
    write_json(credential_preflight_path, credential_preflight)
    controller_baselines_path = args.output_dir / "controller-baselines.json"
    write_json(controller_baselines_path, controller_baselines)
    verifier_root = args.output_dir / "verifiers"
    parent_verifier = build_exact_kernel_verifier(
        args.kernel_repository,
        parent_kernel_sha,
        verifier_root / "parent",
    )
    staged = False
    enforced = False
    enforcement_started = False
    try:
        ratification, promotion = verify_ratification(
            args,
            attestation_token=observer_token,
            kernel_verifier=parent_verifier["binary"],
            replay_dir=args.output_dir / "ratification-replay",
        )
        repository_settings = ensure_recovery_head_ref_policy(merge_client)
        write_json(
            args.output_dir / "repository-settings.json",
            repository_settings,
        )
        control_environments_disabled = ensure_control_environments_disabled(
            validate_contract(
                load_json(args.control_contract, label="control contract"),
                load_json(args.adversarial_corpus, label="adversarial corpus"),
            ),
            admin_client,
            observer_client,
        )
        write_json(
            args.output_dir / "control-environments-disabled.json",
            {"environments": control_environments_disabled},
        )
        control = verify_control(args, read_client, deployment_disabled=True)
        observer_control = verify_control(
            args,
            observer_client,
            deployment_disabled=True,
        )
        if control != observer_control:
            raise PermitInputError("independent live control-plane reads did not match")
        write_json(args.output_dir / "control-plane-before.json", control)
        write_json(args.output_dir / "control-plane-observer.json", observer_control)
        head_ref = args.candidate_ref.removeprefix("refs/heads/")
        reopen_candidate = merge_client.get(
            f"/repos/{REPOSITORY}/pulls/{args.candidate_pr}"
        )
        if (
            nested(reopen_candidate, "base", "sha", label="candidate base SHA")
            != ratification["base_sha"]
            or nested(reopen_candidate, "head", "sha", label="candidate head SHA")
            != args.candidate_sha
            or nested(reopen_candidate, "head", "ref", label="candidate head ref")
            != head_ref
            or reopen_candidate.get("state") != "open"
            or reopen_candidate.get("draft") is True
        ):
            raise PermitInputError(
                "candidate pull request drifted from the ratification"
            )

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
                "schema": "mindburn.release-authority-bootstrap-resume/v1",
                "operation": "bootstrap-stage-resumed-after-enforcement",
                "candidate_workflow_sha": args.candidate_sha,
                "candidate_workflow_ref": args.candidate_ref,
            }
            staged = True
            enforced = True
        write_json(args.output_dir / "ruleset-stage.json", stage_receipt)

        trigger = trigger_suite(
            control["contract"], merge_client, workflow_sha=args.candidate_sha
        )
        trigger_path = args.output_dir / "suite-trigger.json"
        write_json(trigger_path, trigger)
        promoter_suite = wait_for_suite(
            suite_args(
                args,
                trigger=trigger_path,
                output_dir=args.output_dir / "suite-promoter",
                kernel_verifier=parent_verifier["binary"],
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
                kernel_verifier=parent_verifier["binary"],
            ),
            observer_client,
        )
        observer_path = args.output_dir / "authority-suite-observer.json"
        write_json(observer_path, observer_suite)
        if promoter_path.read_bytes() != observer_path.read_bytes():
            raise PermitInputError("independent suite reverification did not match")
        promoter_evidence_path = args.output_dir / "suite-promoter-evidence.json"
        observer_evidence_path = args.output_dir / "suite-observer-evidence.json"
        write_json(
            promoter_evidence_path,
            evidence_tree_receipt(args.output_dir / "suite-promoter"),
        )
        write_json(
            observer_evidence_path,
            evidence_tree_receipt(args.output_dir / "suite-observer"),
        )
        if promoter_evidence_path.read_bytes() != observer_evidence_path.read_bytes():
            raise PermitInputError("independent detailed suite evidence did not match")

        if enforced:
            enforce_receipt = {
                "schema": "mindburn.release-authority-bootstrap-resume/v1",
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

        liveness_started = datetime.now(timezone.utc).replace(
            microsecond=0
        ) - timedelta(seconds=2)
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
            kernel_verifier=parent_verifier["binary"],
            output=liveness_dir / "release-permit.json",
            bundle=liveness_dir / "release-permit.attestation.json",
            context=liveness_dir / "context.json",
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
        liveness = wait_for_canary(liveness_args, observer_client)
        write_json(liveness_dir / "receipt.json", liveness)
        liveness_evidence_path = args.output_dir / "liveness-evidence.json"
        write_json(liveness_evidence_path, evidence_tree_receipt(liveness_dir))

        ratification_evidence_path = args.output_dir / "ratification-evidence.json"
        write_json(
            ratification_evidence_path,
            evidence_tree_receipt(args.output_dir / "ratification-replay"),
        )

        approval_path = args.output_dir / "machine-approval.json"
        approval_receipt = submit_machine_approval(
            argparse.Namespace(
                permit=liveness_args.output,
                permit_bundle=liveness_args.bundle,
                trusted_context=liveness_args.context,
                kernel_verifier=parent_verifier["binary"],
                repository=REPOSITORY,
                pull_request=args.candidate_pr,
                head_sha=args.candidate_sha,
                workflow_sha=args.candidate_sha,
                approver_app_slug=APPROVER_SLUG,
                approver_installation_id=APPROVER_INSTALLATION_ID,
            ),
            approval_client,
            attestation_token=observer_token,
        )
        write_json(approval_path, approval_receipt)

        ledger_seed_path = args.output_dir / "evidence-ledger-seed.json"
        ledger_seed = ensure_evidence_ledger_seed(
            merge_client,
            expected_sha=args.candidate_sha,
        )
        write_json(ledger_seed_path, ledger_seed)

        gate_receipt = configure_machine_approval_gates(
            argparse.Namespace(
                candidate_sha=args.candidate_sha,
                candidate_ref=args.candidate_ref,
                approved_head_sha=args.candidate_sha,
                pull_request=args.candidate_pr,
                approval_receipt=approval_path,
                contract=args.bootstrap_contract,
            ),
            admin_client,
        )
        gate_path = args.output_dir / "machine-gates.json"
        write_json(gate_path, gate_receipt)

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
                "authority_suite_observer": sha256_file(observer_path),
                "suite_evidence": sha256_file(promoter_evidence_path),
                "suite_evidence_observer": sha256_file(observer_evidence_path),
                "credential_preflight": sha256_file(credential_preflight_path),
                "source_inputs": sha256_file(source_input_path),
                "parent_verifier": sha256_file(
                    verifier_root / "parent" / "receipt.json"
                ),
                "control_plane": sha256_file(
                    args.output_dir / "control-plane-before.json"
                ),
                "control_plane_observer": sha256_file(
                    args.output_dir / "control-plane-observer.json",
                ),
                "control_environments_disabled": sha256_file(
                    args.output_dir / "control-environments-disabled.json",
                ),
                "controller_baselines": sha256_file(controller_baselines_path),
                "repository_settings": sha256_file(
                    args.output_dir / "repository-settings.json",
                ),
                "machine_approval": sha256_file(approval_path),
                "machine_gates": sha256_file(gate_path),
                "evidence_ledger_seed": sha256_file(ledger_seed_path),
                "liveness_bundle": sha256_file(liveness_args.bundle),
                "liveness_context": sha256_file(liveness_args.context),
                "liveness_permit": sha256_file(liveness_args.output),
                "liveness_evidence": sha256_file(liveness_evidence_path),
                "ratification_bundle": sha256_file(args.permit_bundle),
                "ratification_context": sha256_file(args.trusted_context),
                "ratification_permit": sha256_file(args.permit),
                "ratification_evidence": sha256_file(ratification_evidence_path),
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
    for field in (
        "base_sha",
        "candidate_sha",
        "candidate_tree_sha",
        "merge_sha",
        "merge_tree_sha",
    ):
        require_sha(ready[field], label=f"bootstrap-ready {field}", length=40)
    if (
        ready["candidate_sha"] != args.candidate_sha
        or ready["pull_request"] != args.candidate_pr
    ):
        raise PermitInputError("bootstrap-ready receipt names the wrong candidate")
    validate_ref(ready["candidate_ref"], label="bootstrap-ready candidate_ref")
    for field in (
        "pull_request",
        "ratification_run_id",
        "liveness_run_id",
        "liveness_run_attempt",
    ):
        value = ready[field]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PermitInputError(f"bootstrap-ready {field} must be positive")
    for field in ("ratification_permit_id", "liveness_permit_id"):
        value = ready[field]
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise PermitInputError(f"bootstrap-ready {field} is invalid")
        require_sha(
            value.removeprefix("sha256:"),
            label=f"bootstrap-ready {field}",
            length=64,
        )
    evidence = ready["evidence_sha256"]
    if not isinstance(evidence, dict):
        raise PermitInputError("bootstrap-ready evidence_sha256 must be an object")
    require_exact_keys(
        evidence,
        required=READY_EVIDENCE_NAMES,
        label="bootstrap-ready evidence_sha256",
    )
    for name, digest in evidence.items():
        require_sha(
            digest,
            label=f"bootstrap-ready evidence_sha256.{name}",
            length=64,
        )
    return ready


def confirmed_or_atomic_merge(
    ready: dict[str, Any],
    client: GitHubMergeClient,
    *,
    merger: dict[str, Any],
) -> dict[str, Any]:
    main = client.get(f"/repos/{REPOSITORY}/git/ref/heads/main")
    main_sha = nested_string(main, "object", "sha", label="main SHA")
    merge_args = argparse.Namespace(
        pull_request=ready["pull_request"],
        base_sha=ready["base_sha"],
        head_sha=ready["candidate_sha"],
        merge_sha=ready["merge_sha"],
        tree_sha=ready["merge_tree_sha"],
        merger_app_slug=merger["slug"],
        merger_installation_id=merger["installation_id"],
        merger_app_id=merger["app_id"],
        approval_receipt=None,
        permit=None,
    )
    if main_sha == ready["base_sha"]:
        return atomic_merge(merge_args, client)
    if main_sha != ready["merge_sha"]:
        raise PermitInputError(
            "authority main is outside the resumable bootstrap states"
        )
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


def finalize(
    args: argparse.Namespace,
    token: str,
    observer_token: str,
    approver_token: str,
    merger_token: str,
) -> dict[str, Any]:
    args.candidate_sha = require_sha(
        args.candidate_sha, label="candidate_sha", length=40
    )
    args.candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    ready = validate_ready(args)
    if ready["candidate_ref"] != args.candidate_ref:
        raise PermitInputError("bootstrap-ready receipt names the wrong candidate ref")
    current_source_inputs = {
        "schema": "mindburn.release-authority-bootstrap-source-inputs/v1",
        "candidate_sha": args.candidate_sha,
        "sha256": verify_candidate_source_inputs(args),
    }
    parent_kernel_sha, _candidate_kernel_sha = authority_kernel_shas(args)
    verifier_workspace = tempfile.TemporaryDirectory(
        prefix="helm-authority-finalize-verifiers-"
    )
    verifier_root = Path(verifier_workspace.name)
    parent_verifier = build_exact_kernel_verifier(
        args.kernel_repository,
        parent_kernel_sha,
        verifier_root / "parent",
    )

    executor_read_client = GitHubReadClient(token)
    read_client = GitHubReadClient(observer_token)
    merge_client = GitHubMergeClient(merger_token)
    ruleset_client = GitHubRulesetClient(token)
    admin_client = GitHubAdminClient(token)
    approval_client = GitHubApprovalClient(approver_token)
    bootstrap_contract = load_json(args.bootstrap_contract, label="bootstrap contract")
    validate_merger(bootstrap_contract["merger"])
    current_credential_preflight = preflight_credentials(
        args,
        admin_client,
        read_client,
        approval_client,
        merge_client,
    )
    current_controller_baselines = verify_controller_baselines(args, read_client)
    ratification, promotion = verify_ratification(
        args,
        attestation_token=observer_token,
        kernel_verifier=parent_verifier["binary"],
        replay_dir=verifier_root / "ratification-replay",
    )
    if promotion["candidate_tree_sha"] != ready["candidate_tree_sha"]:
        raise PermitInputError(
            "ratification tree does not match bootstrap-ready receipt"
        )
    transition_control = verify_finalization_control_prestate(
        args,
        executor_read_client,
        read_client,
        expected_control_sha=ready["merge_sha"],
    )

    liveness_dir = args.ready.parent / "authority-liveness"
    liveness_permit_path = liveness_dir / "release-permit.json"
    liveness_bundle_path = liveness_dir / "release-permit.attestation.json"
    liveness_context_path = liveness_dir / "context.json"
    paths = {
        "authority_suite": args.ready.parent / "authority-suite.json",
        "authority_suite_observer": args.ready.parent / "authority-suite-observer.json",
        "suite_evidence": args.ready.parent / "suite-promoter-evidence.json",
        "suite_evidence_observer": args.ready.parent / "suite-observer-evidence.json",
        "credential_preflight": args.ready.parent / "credential-preflight.json",
        "source_inputs": args.ready.parent / "source-inputs.json",
        "parent_verifier": args.ready.parent / "verifiers/parent/receipt.json",
        "control_plane": args.ready.parent / "control-plane-before.json",
        "control_plane_observer": args.ready.parent / "control-plane-observer.json",
        "control_environments_disabled": (
            args.ready.parent / "control-environments-disabled.json"
        ),
        "controller_baselines": args.ready.parent / "controller-baselines.json",
        "repository_settings": args.ready.parent / "repository-settings.json",
        "machine_approval": args.ready.parent / "machine-approval.json",
        "machine_gates": args.ready.parent / "machine-gates.json",
        "evidence_ledger_seed": args.ready.parent / "evidence-ledger-seed.json",
        "liveness_bundle": liveness_bundle_path,
        "liveness_context": liveness_context_path,
        "liveness_permit": liveness_permit_path,
        "liveness_evidence": args.ready.parent / "liveness-evidence.json",
        "ratification_bundle": args.permit_bundle,
        "ratification_context": args.trusted_context,
        "ratification_permit": args.permit,
        "ratification_evidence": args.ready.parent / "ratification-evidence.json",
        "suite_trigger": args.ready.parent / "suite-trigger.json",
    }
    if {name: sha256_file(path) for name, path in paths.items()} != ready[
        "evidence_sha256"
    ]:
        raise PermitInputError("bootstrap evidence digest mismatch")
    if (
        load_json_file(
            paths["credential_preflight"],
            label="recorded credential preflight",
        )
        != current_credential_preflight
    ):
        raise PermitInputError(
            "bootstrap credential identities changed before finalization"
        )
    if (
        load_json_file(
            paths["controller_baselines"],
            label="recorded controller baselines",
        )
        != current_controller_baselines
    ):
        raise PermitInputError("controller repository baselines changed")
    if (
        load_json_file(paths["source_inputs"], label="recorded source inputs")
        != current_source_inputs
        or load_json_file(
            paths["parent_verifier"], label="recorded parent verifier build"
        )
        != parent_verifier["receipt"]
    ):
        raise PermitInputError("bootstrap source or verifier build changed")

    final_suite_dir = verifier_root / "suite-final-observer"
    final_suite = wait_for_suite(
        suite_args(
            args,
            trigger=paths["suite_trigger"],
            output_dir=final_suite_dir,
            kernel_verifier=parent_verifier["binary"],
        ),
        read_client,
    )
    recorded_suite = paths["authority_suite"].read_bytes()
    if (
        canonical_json(final_suite) != recorded_suite
        or paths["authority_suite_observer"].read_bytes() != recorded_suite
        or canonical_json(evidence_tree_receipt(final_suite_dir))
        != paths["suite_evidence"].read_bytes()
        or paths["suite_evidence_observer"].read_bytes()
        != paths["suite_evidence"].read_bytes()
    ):
        raise PermitInputError(
            "final observer replay does not reproduce the complete bootstrap suite"
        )

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
        expected_authority=load_json_file(
            args.candidate_authority, label="candidate authority"
        ),
        kernel_verifier=parent_verifier["binary"],
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
    recorded_approval = load_json_file(
        paths["machine_approval"],
        label="recorded machine approval",
    )
    current_approval = submit_machine_approval(
        argparse.Namespace(
            permit=liveness_permit_path,
            permit_bundle=liveness_bundle_path,
            trusted_context=liveness_context_path,
            kernel_verifier=parent_verifier["binary"],
            repository=REPOSITORY,
            pull_request=args.candidate_pr,
            head_sha=args.candidate_sha,
            workflow_sha=args.candidate_sha,
            approver_app_slug=APPROVER_SLUG,
            approver_installation_id=APPROVER_INSTALLATION_ID,
            allow_merged_resume=True,
        ),
        approval_client,
        attestation_token=observer_token,
    )
    if current_approval != recorded_approval:
        raise PermitInputError("machine approval changed after bootstrap prepare")
    recorded_ledger_seed = load_json_file(
        paths["evidence_ledger_seed"],
        label="recorded evidence ledger seed",
    )
    if (
        recorded_ledger_seed.get("schema")
        != "mindburn.authority-evidence-ledger-seed/v1"
        or recorded_ledger_seed.get("repository") != REPOSITORY
        or recorded_ledger_seed.get("ref") != LEDGER_REF
        or recorded_ledger_seed.get("sha") != args.candidate_sha
        or not isinstance(recorded_ledger_seed.get("created"), bool)
    ):
        raise PermitInputError("evidence ledger seed changed after bootstrap prepare")
    ledger_state = verify_evidence_ledger_descendant(
        merge_client,
        seed_sha=args.candidate_sha,
    )
    gate_receipt = configure_machine_approval_gates(
        argparse.Namespace(
            candidate_sha=machine_sha,
            candidate_ref=machine_ref,
            approved_head_sha=args.candidate_sha,
            pull_request=args.candidate_pr,
            approval_receipt=paths["machine_approval"],
            contract=args.bootstrap_contract,
            allow_merged_resume=True,
        ),
        admin_client,
    )
    recorded_gate_receipt = load_json_file(
        paths["machine_gates"],
        label="recorded machine approval gates",
    )
    expected_gate_receipt = {
        **recorded_gate_receipt,
        "machine_workflow_sha": machine_sha,
        "machine_workflow_ref": machine_ref,
        "evidence_ledger": {
            **recorded_gate_receipt["evidence_ledger"],
            "head_sha": ledger_state["head_sha"],
        },
    }
    if gate_receipt != expected_gate_receipt:
        raise PermitInputError(
            "machine approval gate state changed after bootstrap prepare"
        )
    control_installation = install_control_workflow(
        transition_control["contract"],
        admin_client,
        read_client,
        expected_sha=ready["merge_sha"],
    )
    control_environments = enable_control_environments(
        transition_control["contract"],
        admin_client,
        read_client,
        expected_sha=ready["merge_sha"],
    )
    control = verify_control(
        args,
        executor_read_client,
        expected_control_sha=ready["merge_sha"],
        effective_only=True,
    )
    observer_control = verify_control(
        args,
        read_client,
        expected_control_sha=ready["merge_sha"],
        effective_only=True,
    )
    if control != observer_control:
        raise PermitInputError("independent final control-plane reads did not match")
    if verify_controller_baselines(args, read_client) != current_controller_baselines:
        raise PermitInputError("controller repository baselines moved before intent")
    intent_inputs = {
        f"prepare/{name}/{path.name}": path.read_bytes() for name, path in paths.items()
    }
    intent_inputs.update(evidence_tree_inputs(liveness_dir, prefix="liveness"))
    intent_inputs.update(
        evidence_tree_inputs(args.review_evidence_dir, prefix="ratification/reviews")
    )
    intent_inputs.update(
        evidence_tree_inputs(
            args.ready.parent / "suite-promoter",
            prefix="suite/promoter",
        )
    )
    intent_inputs.update(
        {
            "final/control-workflow-installation.json": canonical_json(
                control_installation
            ),
            "final/control-environments.json": canonical_json(
                {"environments": control_environments}
            ),
            "final/control-plane.json": canonical_json(control),
            "final/control-plane-observer.json": canonical_json(observer_control),
        }
    )
    ledger_client = GitHubLedgerClient(
        merger_token,
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    ledger_namespace = f"bootstrap/pr-{ready['pull_request']}/{ready['merge_sha']}"
    intent_receipt = append_record(
        ledger_client,
        namespace=f"{ledger_namespace}/intent",
        record_type="bootstrap",
        phase="intent",
        workflow_sha=args.candidate_sha,
        run_id=ready["liveness_run_id"],
        run_attempt=ready["liveness_run_attempt"],
        inputs=intent_inputs,
        expected_parent_sha=ledger_state["head_sha"],
    )
    write_json(args.ready.parent / "evidence-ledger-intent.json", intent_receipt)
    merge_receipt = confirmed_or_atomic_merge(
        ready,
        merge_client,
        merger=bootstrap_contract["merger"],
    )
    closure_receipt = append_record(
        ledger_client,
        namespace=f"{ledger_namespace}/closure",
        record_type="bootstrap",
        phase="closure",
        workflow_sha=args.candidate_sha,
        run_id=ready["liveness_run_id"],
        run_attempt=ready["liveness_run_attempt"],
        inputs={
            "intent-descriptor.json": canonical_json(
                stable_record_descriptor(intent_receipt)
            ),
            "atomic-merge.json": canonical_json(merge_receipt),
            "final-control-plane.json": canonical_json(control),
            "final-control-plane-observer.json": canonical_json(observer_control),
        },
        expected_parent_sha=intent_receipt["ledger_head_sha"],
    )
    write_json(args.ready.parent / "evidence-ledger-closure.json", closure_receipt)
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
    final_ledger_receipt = append_record(
        ledger_client,
        namespace=f"{ledger_namespace}/final",
        record_type="bootstrap",
        phase="final",
        workflow_sha=args.candidate_sha,
        run_id=ready["liveness_run_id"],
        run_attempt=ready["liveness_run_attempt"],
        inputs={
            "closure-descriptor.json": canonical_json(
                stable_record_descriptor(closure_receipt)
            ),
            "ruleset-finalization.json": canonical_json(ruleset_receipt),
            "final-control-plane.json": canonical_json(control),
            "final-control-plane-observer.json": canonical_json(observer_control),
        },
        expected_parent_sha=closure_receipt["ledger_head_sha"],
    )
    write_json(
        args.ready.parent / "evidence-ledger-final.json",
        final_ledger_receipt,
    )
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
        "machine_approval": current_approval,
        "machine_approval_gates": gate_receipt,
        "control_workflow_installation": control_installation,
        "control_environments": control_environments,
        "control_plane": control,
        "atomic_merge": merge_receipt,
        "evidence_ledger": {
            "intent": intent_receipt,
            "closure": closure_receipt,
            "final": final_ledger_receipt,
        },
        "ruleset_finalization": ruleset_receipt,
    }


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--permit", type=Path, required=True)
    parser.add_argument("--permit-bundle", type=Path, required=True)
    parser.add_argument("--trusted-context", type=Path, required=True)
    parser.add_argument("--review-evidence-dir", type=Path, required=True)
    parser.add_argument("--kernel-repository", type=Path, required=True)
    parser.add_argument("--candidate-repository", type=Path, required=True)
    parser.add_argument("--candidate-authority", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--candidate-pr", type=int, required=True)
    parser.add_argument("--control-contract", type=Path, required=True)
    parser.add_argument("--adversarial-corpus", type=Path, required=True)
    parser.add_argument("--bootstrap-contract", type=Path, required=True)
    parser.add_argument("--controller-contract", type=Path, required=True)


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
    finalize_parser.add_argument("--timeout-seconds", type=int, default=1800)
    finalize_parser.add_argument("--poll-seconds", type=int, default=15)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        token = os.environ.get("GH_TOKEN", "")
        observer_token = os.environ.get("HELM_AUTHORITY_BOOTSTRAP_OBSERVER_TOKEN", "")
        approver_token = os.environ.get("HELM_AUTHORITY_APPROVER_TOKEN", "")
        merger_token = os.environ.get("HELM_AUTHORITY_MERGER_TOKEN", "")
        if not token:
            raise PermitInputError("GH_TOKEN is required")
        if not observer_token:
            raise PermitInputError(
                "HELM_AUTHORITY_BOOTSTRAP_OBSERVER_TOKEN is required"
            )
        if not approver_token:
            raise PermitInputError("HELM_AUTHORITY_APPROVER_TOKEN is required")
        if not merger_token:
            raise PermitInputError("HELM_AUTHORITY_MERGER_TOKEN is required")
        if len({token, observer_token, approver_token, merger_token}) != 4:
            raise PermitInputError(
                "bootstrap executor, observer, approver, and merger tokens must be distinct"
            )
        if not 60 <= args.timeout_seconds <= 3600:
            raise PermitInputError("timeout_seconds must be between 60 and 3600")
        if not 5 <= args.poll_seconds <= 60:
            raise PermitInputError("poll_seconds must be between 5 and 60")
        if args.command == "prepare":
            result = prepare(
                args,
                token,
                observer_token,
                approver_token,
                merger_token,
            )
        else:
            result = finalize(
                args,
                token,
                observer_token,
                approver_token,
                merger_token,
            )
            write_json(args.output, result)
        sys.stdout.buffer.write(canonical_json(result))
    except (KeyError, OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"bootstrap-authority: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
