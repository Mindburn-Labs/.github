#!/usr/bin/env python3
"""Verify that a previous authority generation ratified its exact successor."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from autonomous_release_permit import (
    AUTHORITY_SCHEMA,
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)


PERMIT_SCHEMA = "mindburn.release-permit/v2"
PERMIT_KEYS = (
    "schema",
    "permit_id",
    "decision",
    "repository",
    "pull_request",
    "base_ref",
    "base_sha",
    "head_sha",
    "merge_sha",
    "merge_tree_sha",
    "workflow_repository",
    "workflow_path",
    "workflow_ref",
    "workflow_sha",
    "run_id",
    "run_attempt",
    "issued_at",
    "authority",
    "context_sha256",
    "reviews",
    "reasons",
)


def load_json_bytes(content: bytes, *, label: str) -> Any:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label}: invalid UTF-8: {exc}") from exc
    return parse_json_strict(text, label=label)


def run_git(repository: Path, *arguments: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout


def git_text(repository: Path, *arguments: str) -> str:
    return run_git(repository, *arguments).decode("utf-8").strip()


def git_blob(repository: Path, candidate_sha: str, path: str) -> bytes:
    return run_git(repository, "show", f"{candidate_sha}:{path}")


def validate_authority_shape(authority: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(authority, dict):
        raise PermitInputError(f"{label} must be an object")
    require_exact_keys(
        authority,
        required={
            "schema",
            "generation",
            "kernel_sha",
            "gate_profiles_sha256",
            "adversarial_corpus_sha256",
            "parent",
        },
        label=label,
    )
    if authority["schema"] != AUTHORITY_SCHEMA:
        raise PermitInputError(f"{label} has an unsupported schema")
    generation = authority["generation"]
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation <= 0
    ):
        raise PermitInputError(f"{label} generation must be a positive integer")
    require_sha(authority["kernel_sha"], label=f"{label} kernel_sha", length=40)
    require_sha(
        authority["gate_profiles_sha256"],
        label=f"{label} gate_profiles_sha256",
        length=64,
    )
    require_sha(
        authority["adversarial_corpus_sha256"],
        label=f"{label} adversarial_corpus_sha256",
        length=64,
    )
    parent = authority["parent"]
    if generation == 1:
        if parent is not None:
            raise PermitInputError(f"{label} generation 1 cannot declare a parent")
    else:
        if not isinstance(parent, dict):
            raise PermitInputError(f"{label} requires a parent")
        require_exact_keys(
            parent,
            required={"generation", "workflow_sha"},
            label=f"{label} parent",
        )
        require_sha(
            parent["workflow_sha"],
            label=f"{label} parent workflow_sha",
            length=40,
        )
    return authority


def verify_permit_with_kernel(
    verifier: Path,
    permit: Path,
    trusted_context: Path,
) -> None:
    verifier = verifier.resolve()
    permit = permit.resolve()
    trusted_context = trusted_context.resolve()
    process = subprocess.run(
        [
            str(verifier),
            "--verify-permit",
            str(permit),
            "--context",
            str(trusted_context),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(f"pinned Kernel rejected the permit: {detail}")


def validate_permit(permit: Any) -> dict[str, Any]:
    if not isinstance(permit, dict):
        raise PermitInputError("permit must be an object")
    require_exact_keys(permit, required=set(PERMIT_KEYS), label="permit")
    if permit["schema"] != PERMIT_SCHEMA:
        raise PermitInputError("unsupported permit schema")
    if permit["decision"] != "ALLOW" or permit["reasons"] != []:
        raise PermitInputError("promotion requires an ALLOW permit with no reasons")
    permit_id = permit["permit_id"]
    if not isinstance(permit_id, str) or not permit_id.startswith("sha256:"):
        raise PermitInputError("permit_id must be a sha256 digest")
    require_sha(permit_id.removeprefix("sha256:"), label="permit_id", length=64)
    authority = validate_authority_shape(permit["authority"], label="permit authority")
    if not isinstance(permit["reviews"], list) or len(permit["reviews"]) != 2:
        raise PermitInputError("permit must contain exactly two review summaries")
    providers: set[str] = set()
    for index, review in enumerate(permit["reviews"]):
        if not isinstance(review, dict):
            raise PermitInputError(f"permit reviews[{index}] must be an object")
        require_exact_keys(
            review,
            required={
                "reviewer",
                "verdict",
                "response_sha256",
                "blocking_findings",
                "advisory_findings",
            },
            label=f"permit reviews[{index}]",
        )
        reviewer = review["reviewer"]
        if not isinstance(reviewer, dict):
            raise PermitInputError(
                f"permit reviews[{index}] reviewer must be an object"
            )
        require_exact_keys(
            reviewer,
            required={"provider", "model"},
            label=f"permit reviews[{index}] reviewer",
        )
        if review["verdict"] != "ALLOW" or review["blocking_findings"] != 0:
            raise PermitInputError("every promotion review must be non-blocking ALLOW")
        require_sha(
            review["response_sha256"],
            label=f"permit reviews[{index}] response_sha256",
            length=64,
        )
        provider = reviewer["provider"]
        if not isinstance(provider, str) or not provider:
            raise PermitInputError("review provider must be non-empty")
        providers.add(provider)
    if providers != {"anthropic", "openai"}:
        raise PermitInputError(
            "promotion requires the exact Anthropic and OpenAI provider quorum"
        )
    return authority


def verify(args: argparse.Namespace) -> dict[str, Any]:
    candidate_repository = args.candidate_repository.resolve()
    candidate_sha = require_sha(args.candidate_sha, label="candidate_sha", length=40)
    parent_sha = require_sha(
        args.expected_parent_workflow_sha,
        label="expected_parent_workflow_sha",
        length=40,
    )
    verify_permit_with_kernel(
        args.permit_verifier,
        args.permit,
        args.trusted_context,
    )
    permit = load_json_bytes(args.permit.read_bytes(), label=str(args.permit))
    permit_authority = validate_permit(permit)

    if permit["repository"] != "Mindburn-Labs/.github":
        raise PermitInputError(
            "permit does not ratify the workflow authority repository"
        )
    if permit["pull_request"] != args.candidate_pr:
        raise PermitInputError("permit pull request does not match the candidate")
    if permit["run_id"] != args.expected_run_id:
        raise PermitInputError(
            "permit run_id does not match the triggering workflow run"
        )
    if permit["run_attempt"] != args.expected_run_attempt:
        raise PermitInputError(
            "permit run_attempt does not match the triggering workflow run"
        )
    if permit["head_sha"] != candidate_sha:
        raise PermitInputError("permit head_sha does not match the candidate commit")
    if permit["workflow_sha"] != parent_sha:
        raise PermitInputError("permit was not issued by the expected parent workflow")
    if permit_authority["generation"] != args.expected_parent_generation:
        raise PermitInputError(
            "permit authority generation does not match the expected parent"
        )

    candidate_tree = git_text(
        candidate_repository, "rev-parse", f"{candidate_sha}^{{tree}}"
    )
    if permit["merge_tree_sha"] != candidate_tree:
        raise PermitInputError(
            "permit merge tree does not match the candidate commit tree"
        )

    authority_path = "config/autonomous-release-authority.json"
    candidate_authority = validate_authority_shape(
        load_json_bytes(
            git_blob(candidate_repository, candidate_sha, authority_path),
            label=f"{candidate_sha}:{authority_path}",
        ),
        label="candidate authority",
    )
    if candidate_authority["generation"] != args.expected_parent_generation + 1:
        raise PermitInputError(
            "candidate authority generation is not the next generation"
        )
    parent = candidate_authority["parent"]
    if parent != {
        "generation": args.expected_parent_generation,
        "workflow_sha": parent_sha,
    }:
        raise PermitInputError(
            "candidate authority does not name the exact parent generation"
        )

    for field, path in (
        ("gate_profiles_sha256", "config/autonomous-release-gates.json"),
        (
            "adversarial_corpus_sha256",
            "tests/fixtures/autonomous-release-adversarial.json",
        ),
    ):
        observed = hashlib.sha256(
            git_blob(candidate_repository, candidate_sha, path)
        ).hexdigest()
        if candidate_authority[field] != observed:
            raise PermitInputError(f"candidate {field} does not match {path}")

    workflow = git_blob(
        candidate_repository,
        candidate_sha,
        ".github/workflows/ci.yml",
    ).decode("utf-8")
    kernel_ref = f"ref: {candidate_authority['kernel_sha']}"
    if workflow.count(kernel_ref) != 3:
        raise PermitInputError(
            "candidate workflow does not pin the declared Kernel exactly three times"
        )
    if (
        "--authority-manifest policy/config/autonomous-release-authority.json"
        not in workflow
    ):
        raise PermitInputError(
            "candidate workflow does not bind the authority manifest"
        )

    return {
        "schema": "mindburn.release-authority-promotion/v1",
        "candidate_generation": candidate_authority["generation"],
        "candidate_sha": candidate_sha,
        "candidate_tree_sha": candidate_tree,
        "kernel_sha": candidate_authority["kernel_sha"],
        "parent_generation": args.expected_parent_generation,
        "parent_workflow_sha": parent_sha,
        "ratification_permit_id": permit["permit_id"],
        "ratification_run_id": permit["run_id"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--permit", type=Path, required=True)
    parser.add_argument("--permit-verifier", type=Path, required=True)
    parser.add_argument("--trusted-context", type=Path, required=True)
    parser.add_argument("--candidate-repository", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-pr", type=int, required=True)
    parser.add_argument("--expected-run-id", type=int, required=True)
    parser.add_argument("--expected-run-attempt", type=int, required=True)
    parser.add_argument("--expected-parent-generation", type=int, required=True)
    parser.add_argument("--expected-parent-workflow-sha", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = verify(args)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (OSError, PermitInputError) as exc:
        print(f"verify-authority-promotion: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
