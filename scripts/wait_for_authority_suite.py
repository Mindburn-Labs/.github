#!/usr/bin/env python3
"""Require the exact candidate authority to pass every permanent proof case."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any
import urllib.parse

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from verify_authority_promotion import (
    PERMIT_KEYS,
    PERMIT_SCHEMA,
    validate_authority_shape,
)
from verify_control_plane import load_json, validate_contract
from wait_for_authority_canary import (
    GitHubReadClient,
    PROVENANCE_ARTIFACT as CANARY_PROVENANCE_ARTIFACT,
    PROVENANCE_SCHEMA as CANARY_PROVENANCE_SCHEMA,
    WORKFLOW_NAME,
    WORKFLOW_PATH,
    artifact_for_run,
    extract_attested_permit,
    extract_trusted_context,
    load_json_file,
    parse_time,
    run_sort_key,
    verify_attestation,
    verify_candidate_permit,
    verify_permit_reduction,
    verify_run_workflow_provenance,
    write_model_reviews,
)


TRIGGER_SCHEMA = "mindburn.release-authority-suite-trigger/v1"
SUITE_SCHEMA = "mindburn.release-authority-suite/v1"
REVIEWERS = {
    ("anthropic", "claude-fable-5"),
    ("openai", "gpt-5.6-sol"),
}
PRE_MODEL_GATES = {"Deterministic repository gates", "Bind immutable review input"}
PROVENANCE_ARTIFACT = CANARY_PROVENANCE_ARTIFACT
PROVENANCE_SCHEMA = CANARY_PROVENANCE_SCHEMA


def validate_trigger(
    trigger: dict[str, Any], contract: dict[str, Any]
) -> dict[str, Any]:
    require_exact_keys(
        trigger,
        required={"schema", "repository", "workflow_sha", "started_at", "cases"},
        label="suite trigger",
    )
    if trigger["schema"] != TRIGGER_SCHEMA:
        raise PermitInputError("unsupported suite trigger schema")
    if trigger["repository"] != contract["adversarial_suite"]["repository"]:
        raise PermitInputError("suite trigger repository does not match the contract")
    require_sha(trigger["workflow_sha"], label="suite trigger workflow_sha", length=40)
    parse_time(trigger["started_at"], label="suite trigger started_at")
    if trigger["cases"] != contract["adversarial_suite"]["cases"]:
        raise PermitInputError("suite trigger cases do not exactly match the contract")
    return trigger


def artifact_names(client: GitHubReadClient, repository: str, run_id: int) -> set[str]:
    payload = client.get_json(f"/repos/{repository}/actions/runs/{run_id}/artifacts")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise PermitInputError("GitHub artifacts response is malformed")
    names: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("name"), str):
            raise PermitInputError("GitHub artifact entry is malformed")
        if artifact.get("expired") is False:
            names.add(artifact["name"])
    return names


def validate_deny_permit(
    permit_path: Path,
    bundle_path: Path,
    context_path: Path,
    *,
    run: dict[str, Any],
    repository: str,
    case: dict[str, Any],
    workflow_sha: str,
    authority: dict[str, Any],
    attestation_token: str,
) -> dict[str, Any]:
    permit = load_json_file(permit_path, label=f"{case['id']} DENY permit")
    require_exact_keys(permit, required=set(PERMIT_KEYS), label="DENY permit")
    if permit["schema"] != PERMIT_SCHEMA or permit["decision"] != "DENY":
        raise PermitInputError("adversarial permit is not a schema-valid DENY")
    permit_id = permit.get("permit_id")
    if not isinstance(permit_id, str) or not permit_id.startswith("sha256:"):
        raise PermitInputError("DENY permit_id is invalid")
    require_sha(permit_id.removeprefix("sha256:"), label="DENY permit_id", length=64)
    expected = {
        "repository": repository,
        "pull_request": case["pull_request"],
        "head_sha": case["head_sha"],
        "workflow_sha": workflow_sha,
        "run_id": run.get("id"),
        "run_attempt": run.get("run_attempt"),
    }
    for field, value in expected.items():
        if permit.get(field) != value:
            raise PermitInputError(f"DENY permit {field} does not match the proof run")
    if (
        validate_authority_shape(permit.get("authority"), label="DENY authority")
        != authority
    ):
        raise PermitInputError("DENY permit authority does not match the candidate")
    reasons = permit.get("reasons")
    if not isinstance(reasons, list) or not reasons:
        raise PermitInputError("DENY permit must contain at least one reason")
    if not any(
        isinstance(reason, dict)
        and reason.get("code") in {"BLOCKING_FINDING", "REVIEW_DENIED"}
        for reason in reasons
    ):
        raise PermitInputError("DENY permit lacks a blocking review reason")
    reviews = permit.get("reviews")
    if not isinstance(reviews, list) or len(reviews) != 2:
        raise PermitInputError("DENY permit must contain exactly two reviews")
    identities: set[tuple[str, str]] = set()
    blocking_reviews = 0
    for index, review in enumerate(reviews):
        if not isinstance(review, dict):
            raise PermitInputError(f"DENY review {index} must be an object")
        require_exact_keys(
            review,
            required={
                "reviewer",
                "verdict",
                "response_sha256",
                "blocking_findings",
                "advisory_findings",
            },
            label=f"DENY review {index}",
        )
        reviewer = review["reviewer"]
        if not isinstance(reviewer, dict):
            raise PermitInputError(f"DENY review {index} reviewer is invalid")
        require_exact_keys(
            reviewer,
            required={"provider", "model"},
            label=f"DENY review {index} reviewer",
        )
        identities.add((reviewer["provider"], reviewer["model"]))
        require_sha(
            review["response_sha256"],
            label=f"DENY review {index} response_sha256",
            length=64,
        )
        if review["verdict"] not in {"ALLOW", "DENY"}:
            raise PermitInputError(f"DENY review {index} verdict is invalid")
        for finding_type in ("blocking_findings", "advisory_findings"):
            count = review[finding_type]
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise PermitInputError(
                    f"DENY review {index} {finding_type} must be non-negative",
                )
        if review["verdict"] == "DENY" and review["blocking_findings"] > 0:
            blocking_reviews += 1
    if identities != REVIEWERS or blocking_reviews == 0:
        raise PermitInputError("DENY permit lacks the exact blocking reviewer quorum")

    context_bytes = context_path.read_bytes()
    context = parse_json_strict(context_bytes.decode("utf-8"), label="DENY context")
    if not isinstance(context, dict):
        raise PermitInputError("DENY context must be an object")
    if hashlib.sha256(context_bytes).hexdigest() != permit.get("context_sha256"):
        raise PermitInputError("DENY context digest does not match the permit")
    for field, value in expected.items():
        if context.get(field) != value:
            raise PermitInputError(f"DENY context {field} does not match the proof run")
    if context.get("authority") != authority:
        raise PermitInputError("DENY context authority does not match the candidate")
    verify_attestation(
        permit_path,
        bundle_path,
        repository=repository,
        workflow_sha=workflow_sha,
        source_sha=permit["merge_sha"],
        github_token=attestation_token,
    )
    return permit


def validate_pre_model_reject(
    client: GitHubReadClient,
    repository: str,
    run: dict[str, Any],
    *,
    head_sha: str,
    workflow_sha: str,
    attestation_token: str,
    directory: Path,
) -> dict[str, Any]:
    run_id = run["id"]
    names = artifact_names(client, repository, run_id)
    forbidden = {
        name
        for name in names
        if name == "helm-autonomous-release-permit"
        or name == "release-permit-input"
        or name.startswith("release-review-")
    }
    if forbidden:
        raise PermitInputError(
            f"pre-model rejection emitted forbidden review evidence: {sorted(forbidden)}",
        )
    payload = client.get_json(
        f"/repos/{repository}/actions/runs/{run_id}/jobs?per_page=100"
    )
    jobs = payload.get("jobs")
    if not isinstance(jobs, list):
        raise PermitInputError("GitHub jobs response is malformed")
    failed_gates = {
        job.get("name")
        for job in jobs
        if isinstance(job, dict)
        and job.get("name") in PRE_MODEL_GATES
        and job.get("conclusion") == "failure"
    }
    if not failed_gates:
        raise PermitInputError("pre-model rejection did not fail an admissibility gate")
    model_jobs = [
        job
        for job in jobs
        if isinstance(job, dict)
        and job.get("name") in {"anthropic / claude-fable-5", "openai / gpt-5.6-sol"}
    ]
    if any(job.get("conclusion") != "skipped" for job in model_jobs):
        raise PermitInputError("pre-model rejection executed a model reviewer")

    del attestation_token
    provenance = verify_run_workflow_provenance(
        client,
        repository,
        run,
        head_sha=head_sha,
        expected_workflow_sha=workflow_sha,
        directory=directory,
    )
    if provenance is None:
        raise PermitInputError(
            "pre-model rejection lacks candidate workflow provenance"
        )
    if not provenance["is_expected_workflow"]:
        raise PermitInputError(
            "pre-model rejection workflow_sha does not match the proof run"
        )
    return {
        "failed_gates": sorted(failed_gates),
        "merge_sha": provenance["merge_sha"],
        "workflow_provenance_sha256": provenance["workflow_provenance_sha256"],
    }


def write_attested_case(
    client: GitHubReadClient,
    repository: str,
    run_id: int,
    directory: Path,
) -> tuple[Path, Path, Path, dict[str, Path]]:
    permit_id = artifact_for_run(client, repository, run_id)
    context_id = artifact_for_run(client, repository, run_id, "release-permit-input")
    if permit_id is None or context_id is None:
        raise PermitInputError("proof run is missing permit or context evidence")
    permit_bytes, bundle_bytes = extract_attested_permit(
        client.get_bytes(
            f"/repos/{repository}/actions/artifacts/{permit_id}/zip",
            accept="application/vnd.github+json",
        ),
    )
    context_bytes = extract_trusted_context(
        client.get_bytes(
            f"/repos/{repository}/actions/artifacts/{context_id}/zip",
            accept="application/vnd.github+json",
        ),
    )
    directory.mkdir(parents=True, exist_ok=False)
    permit_path = directory / "release-permit.json"
    bundle_path = directory / "release-permit.attestation.json"
    context_path = directory / "context.json"
    permit_path.write_bytes(permit_bytes)
    bundle_path.write_bytes(bundle_bytes)
    context_path.write_bytes(context_bytes)
    review_paths = write_model_reviews(
        client,
        repository,
        run_id,
        directory,
        context_path=context_path,
    )
    return permit_path, bundle_path, context_path, review_paths


def candidate_runs(
    client: GitHubReadClient,
    repository: str,
    head_sha: str,
    started_at: Any,
) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"event": "pull_request", "head_sha": head_sha, "per_page": 100},
    )
    payload = client.get_json(f"/repos/{repository}/actions/runs?{query}")
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise PermitInputError("GitHub Actions runs response is malformed")
    result = []
    for run in runs:
        if (
            isinstance(run, dict)
            and isinstance(run.get("id"), int)
            and run.get("name") == WORKFLOW_NAME
            and run.get("path") == WORKFLOW_PATH
            and run.get("head_sha") == head_sha
            and parse_time(run.get("created_at"), label="run created_at") >= started_at
        ):
            result.append(run)
    result.sort(key=run_sort_key, reverse=True)
    return result


def verify_case(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    case: dict[str, Any],
    run: dict[str, Any],
    repository: str,
    authority: dict[str, Any],
    workflow_sha: str,
) -> dict[str, Any]:
    expected = case["expected"]
    if expected == "PRE_MODEL_REJECT":
        if run.get("conclusion") != "failure":
            raise PermitInputError("pre-model proof run did not fail closed")
        detail = validate_pre_model_reject(
            client,
            repository,
            run,
            head_sha=case["head_sha"],
            workflow_sha=workflow_sha,
            attestation_token=client.token,
            directory=args.output_dir / "cases" / case["id"],
        )
        return {
            "id": case["id"],
            "expected": expected,
            "run_id": run["id"],
            "run_attempt": run["run_attempt"],
            **detail,
        }

    expected_conclusion = "success" if expected == "ALLOW" else "failure"
    if run.get("conclusion") != expected_conclusion:
        raise PermitInputError(f"{case['id']} run has the wrong conclusion")
    directory = args.output_dir / "cases" / case["id"]
    permit_path, bundle_path, context_path, review_paths = write_attested_case(
        client,
        repository,
        run["id"],
        directory,
    )
    if expected == "ALLOW":
        permit = verify_candidate_permit(
            permit_path,
            bundle_path,
            context_path,
            run=run,
            repository=repository,
            pull_request=case["pull_request"],
            head_sha=case["head_sha"],
            expected_workflow_sha=workflow_sha,
            expected_authority=authority,
            kernel_verifier=args.kernel_verifier,
            attestation_token=client.token,
        )
        for source, name in (
            (permit_path, "canary-permit.json"),
            (bundle_path, "canary-permit.attestation.json"),
            (context_path, "canary-context.json"),
        ):
            (args.output_dir / name).write_bytes(source.read_bytes())
    else:
        permit = validate_deny_permit(
            permit_path,
            bundle_path,
            context_path,
            run=run,
            repository=repository,
            case=case,
            workflow_sha=workflow_sha,
            authority=authority,
            attestation_token=client.token,
        )
    verify_permit_reduction(
        args.kernel_verifier,
        permit_path,
        context_path,
        review_paths,
        directory / "parent-kernel-permit.json",
    )
    return {
        "id": case["id"],
        "expected": expected,
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "permit_id": permit["permit_id"],
        "merge_sha": permit["merge_sha"],
        "merge_tree_sha": permit["merge_tree_sha"],
    }


def wait_for_suite(
    args: argparse.Namespace, client: GitHubReadClient
) -> dict[str, Any]:
    contract = validate_contract(
        load_json(args.contract, label="control contract"),
        load_json(args.adversarial_corpus, label="adversarial corpus"),
    )
    trigger = validate_trigger(load_json(args.trigger, label="suite trigger"), contract)
    workflow_sha = require_sha(
        args.expected_workflow_sha,
        label="expected_workflow_sha",
        length=40,
    )
    if trigger["workflow_sha"] != workflow_sha:
        raise PermitInputError(
            "suite trigger workflow SHA does not match the candidate"
        )
    authority = load_json_file(args.expected_authority, label="expected authority")
    started_at = parse_time(trigger["started_at"], label="suite trigger started_at")
    repository = trigger["repository"]
    pending = {case["id"]: case for case in trigger["cases"]}
    receipts: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + args.timeout_seconds
    args.output_dir.mkdir(parents=True, exist_ok=False)
    while pending and time.monotonic() < deadline:
        for case_id, case in list(pending.items()):
            runs = candidate_runs(
                client,
                repository,
                case["head_sha"],
                started_at,
            )
            exact_run = None
            unclassified_newer_run = False
            for run in runs:
                provenance = verify_run_workflow_provenance(
                    client,
                    repository,
                    run,
                    head_sha=case["head_sha"],
                    expected_workflow_sha=workflow_sha,
                )
                if provenance is None:
                    unclassified_newer_run = True
                    break
                if provenance["is_expected_workflow"]:
                    exact_run = run
                    break
            if unclassified_newer_run or exact_run is None:
                continue
            run = exact_run
            if run.get("status") != "completed":
                continue
            try:
                receipts[case_id] = verify_case(
                    args,
                    client,
                    case=case,
                    run=run,
                    repository=repository,
                    authority=authority,
                    workflow_sha=workflow_sha,
                )
            except (OSError, PermitInputError) as exc:
                case_dir = args.output_dir / "cases" / case_id
                if case_dir.exists():
                    shutil.rmtree(case_dir)
                raise PermitInputError(
                    f"newest exact candidate proof case {case_id} run {run['id']} failed validation: {exc}"
                ) from exc
            del pending[case_id]
        if pending:
            time.sleep(args.poll_seconds)
    if pending:
        raise PermitInputError(
            f"timed out waiting for candidate authority proof cases: {sorted(pending)}",
        )
    ordered = [receipts[case["id"]] for case in trigger["cases"]]
    allow = next(receipt for receipt in ordered if receipt["expected"] == "ALLOW")
    canary_receipt = {
        "schema": "mindburn.release-authority-canary/v1",
        "repository": repository,
        "pull_request": next(
            case["pull_request"]
            for case in trigger["cases"]
            if case["expected"] == "ALLOW"
        ),
        "head_sha": next(
            case["head_sha"] for case in trigger["cases"] if case["expected"] == "ALLOW"
        ),
        "workflow_sha": workflow_sha,
        "run_id": allow["run_id"],
        "run_attempt": allow["run_attempt"],
        "permit_id": allow["permit_id"],
        "merge_sha": allow["merge_sha"],
        "merge_tree_sha": allow["merge_tree_sha"],
    }
    (args.output_dir / "canary-receipt.json").write_text(
        json.dumps(canary_receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "schema": SUITE_SCHEMA,
        "repository": repository,
        "workflow_sha": workflow_sha,
        "cases": ordered,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--adversarial-corpus", type=Path, required=True)
    parser.add_argument("--trigger", type=Path, required=True)
    parser.add_argument("--expected-workflow-sha", required=True)
    parser.add_argument("--expected-authority", type=Path, required=True)
    parser.add_argument("--kernel-verifier", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--poll-seconds", type=int, default=15)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        if not 60 <= args.timeout_seconds <= 3600:
            raise PermitInputError("timeout_seconds must be between 60 and 3600")
        if not 5 <= args.poll_seconds <= 60:
            raise PermitInputError("poll_seconds must be between 5 and 60")
        receipt = wait_for_suite(
            args,
            GitHubReadClient(
                os.environ.get("GH_TOKEN", ""),
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            ),
        )
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.receipt.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError, UnicodeDecodeError) as exc:
        print(f"wait-for-authority-suite: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
