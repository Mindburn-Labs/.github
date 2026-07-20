#!/usr/bin/env python3
"""Verify that a previous authority generation ratified its exact successor."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from autonomous_release_permit import (
    AUTHORITY_SCHEMA,
    PermitInputError,
    parse_json_strict,
    rebuild_review_evidence,
    require_exact_keys,
    require_sha,
)


PERMIT_SCHEMA = "mindburn.release-permit/v2"
MODEL_REVIEWERS = {
    "anthropic": "claude-fable-5",
    "openai": "gpt-5.6-sol",
}
REVIEW_EVIDENCE_FILENAMES = {
    f"{prefix}-{provider}.{suffix}"
    for provider in MODEL_REVIEWERS
    for prefix, suffix in (
        ("raw", "txt"),
        ("normalized", "json"),
        ("review", "json"),
    )
}
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
WORKFLOW_TEMPLATE_MARKER = "__HELM_AUTHORITY_KERNEL_SHA__"
WORKFLOW_TEMPLATE_PIN_COUNT = 3
WORKFLOW_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "config"
    / "autonomous-release-ci-template.yml"
)

CHECKOUT_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
KERNEL_REPOSITORY = "Mindburn-Labs/helm-ai-kernel"
PREPARE_KERNEL_STEP = "Checkout pinned Kernel verifier source for isolated review"
PERMIT_KERNEL_STEP = "Checkout pinned Kernel verifier"
PREPARE_BUNDLE_STEP = "Prepare commit-bound review bundle"
PREPARE_KERNEL_PATH = "verifier-source"
PERMIT_KERNEL_PATH = "kernel"
PREPARE_KERNEL_SPARSE_PATHS = (
    "core/pkg/releasepermit",
    "core/cmd/release-permit-verify",
)
PERMIT_RUNTIME_COPY = (
    "cp policy/scripts/autonomous_release_permit.py "
    "autonomous-review-runtime/policy/scripts/autonomous_release_permit.py"
)
PREPARE_COMMAND = (
    "python3 policy/scripts/autonomous_release_permit.py prepare "
    '--repository "$REPOSITORY" --pull-request "$PULL_REQUEST" '
    '--base-ref "$BASE_REF" --base-sha "$BASE_SHA" --head-sha "$HEAD_SHA" '
    '--merge-sha "$MERGE_SHA" --workflow-repository "$WORKFLOW_REPOSITORY" '
    '--workflow-path "$WORKFLOW_PATH" --workflow-ref "$WORKFLOW_REF" '
    '--workflow-sha "$WORKFLOW_SHA" --run-id "$RUN_ID" '
    '--run-attempt "$RUN_ATTEMPT" '
    "--issued-at \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\" "
    '--anthropic-model "$ANTHROPIC_MODEL" --openai-model "$OPENAI_MODEL" '
    "--authority-manifest policy/config/autonomous-release-authority.json "
    '--kernel-sha "$KERNEL_SHA" '
    "--gate-profiles policy/config/autonomous-release-gates.json "
    "--adversarial-corpus policy/tests/fixtures/autonomous-release-adversarial.json "
    "--target-dir target --output-dir permit-input "
    '--max-patch-bytes "$MAX_PATCH_BYTES" '
    '--max-changed-blob-bytes "$MAX_CHANGED_BLOB_BYTES"'
)

# Psych is already a repository prerequisite. It is used here rather than a
# permissive YAML loader so comments, duplicate keys, aliases, and merge keys
# cannot manufacture a lexical-looking authority workflow.
STRICT_WORKFLOW_YAML_PARSER = r"""
require "json"
require "psych"

def reject_unsafe_yaml(node)
  if node.respond_to?(:anchor) && node.anchor
    raise "YAML aliases or anchors are not allowed"
  end

  case node
  when Psych::Nodes::Alias
    raise "YAML aliases or anchors are not allowed"
  when Psych::Nodes::Mapping
    unless node.children.length.even?
      raise "YAML mapping has an incomplete key/value pair"
    end
    keys = {}
    node.children.each_slice(2) do |key, value|
      unless key.is_a?(Psych::Nodes::Scalar)
        raise "YAML mapping keys must be scalars"
      end
      key_name = key.value
      if key_name == "<<"
        raise "YAML merge keys are not allowed"
      end
      if keys.key?(key_name)
        raise "duplicate YAML key: #{key_name}"
      end
      keys[key_name] = true
      reject_unsafe_yaml(key)
      reject_unsafe_yaml(value)
    end
  when Psych::Nodes::Sequence, Psych::Nodes::Document
    node.children.each { |child| reject_unsafe_yaml(child) }
  end
end

begin
  source = STDIN.read
  stream = Psych.parse_stream(source)
  unless stream.children.length == 1
    raise "YAML document must contain exactly one document"
  end
  reject_unsafe_yaml(stream.children.first)
  document = Psych.safe_load(source, permitted_classes: [], aliases: false)
  unless document.is_a?(Hash)
    raise "YAML document must be an object"
  end
  STDOUT.write(JSON.generate(document))
rescue StandardError => error
  warn error.message
  exit 1
end
"""


def load_json_bytes(content: bytes, *, label: str) -> Any:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label}: invalid UTF-8: {exc}") from exc
    return parse_json_strict(text, label=label)


def require_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def parse_strict_workflow_yaml(content: str) -> dict[str, Any]:
    try:
        process = subprocess.run(
            ["ruby", "-e", STRICT_WORKFLOW_YAML_PARSER],
            input=content.encode("utf-8"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise PermitInputError(
            f"candidate workflow YAML parser is unavailable: {exc}"
        ) from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(f"candidate workflow YAML rejected: {detail}")
    parsed = load_json_bytes(process.stdout, label="candidate workflow YAML")
    return require_mapping(parsed, label="candidate workflow")


def find_named_step(job: dict[str, Any], *, name: str, label: str) -> dict[str, Any]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise PermitInputError(f"candidate {label} steps must be an array")
    matches = [
        step for step in steps if isinstance(step, dict) and step.get("name") == name
    ]
    if len(matches) != 1:
        raise PermitInputError(
            f"candidate {label} must contain exactly one {name!r} step"
        )
    return matches[0]


def validate_kernel_checkout(
    step: dict[str, Any],
    *,
    label: str,
    kernel_sha: str,
    path: str,
    sparse_paths: tuple[str, ...] | None,
) -> None:
    if step.get("uses") != CHECKOUT_ACTION:
        raise PermitInputError(f"candidate {label} must use the pinned checkout action")
    checkout = require_mapping(step.get("with"), label=f"candidate {label} with")
    expected_keys = {"repository", "ref", "persist-credentials", "path"}
    if sparse_paths is not None:
        expected_keys.add("sparse-checkout")
    require_exact_keys(
        checkout,
        required=expected_keys,
        label=f"candidate {label} checkout",
    )
    if checkout["repository"] != KERNEL_REPOSITORY:
        raise PermitInputError(f"candidate {label} repository is not the Kernel")
    if checkout["ref"] != kernel_sha:
        raise PermitInputError(f"candidate {label} ref is not the authority Kernel SHA")
    if checkout["persist-credentials"] is not False:
        raise PermitInputError(f"candidate {label} must disable persisted credentials")
    if checkout["path"] != path:
        raise PermitInputError(f"candidate {label} path is not the expected path")
    if sparse_paths is not None:
        sparse_checkout = checkout["sparse-checkout"]
        if (
            not isinstance(sparse_checkout, str)
            or tuple(line for line in sparse_checkout.splitlines() if line)
            != sparse_paths
        ):
            raise PermitInputError(
                f"candidate {label} sparse checkout paths are not exact"
            )


def collect_shell_commands(run: Any, *, label: str) -> list[str]:
    if not isinstance(run, str):
        raise PermitInputError(f"candidate {label} must be a string")
    commands: list[str] = []
    current: list[str] = []
    for raw_line in run.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        continued = line.endswith("\\")
        if continued:
            line = line[:-1].rstrip()
            if not line:
                raise PermitInputError(f"candidate {label} has an empty continuation")
        current.append(line)
        if not continued:
            commands.append(" ".join(current))
            current = []
    if current:
        raise PermitInputError(f"candidate {label} has an unterminated continuation")
    return commands


def parse_restricted_prepare_command(run: Any) -> None:
    commands = collect_shell_commands(run, label="prepare command")
    if any(command.startswith("#") for command in commands):
        raise PermitInputError("candidate prepare command cannot contain comments")
    if len(commands) != 2 or commands[0] != "set -euo pipefail":
        raise PermitInputError(
            "candidate prepare command has an unexpected control shape"
        )
    if commands[1] != PREPARE_COMMAND:
        raise PermitInputError(
            "candidate prepare command has an unexpected semantic shape"
        )


def reject_alternate_authority_execution(
    job: dict[str, Any],
    *,
    label: str,
    kernel_step_name: str,
    prepare_step_name: str | None,
) -> None:
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise PermitInputError(f"candidate {label} steps must be an array")
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        checkout = step.get("with")
        if (
            isinstance(checkout, dict)
            and checkout.get("repository") == KERNEL_REPOSITORY
            and step.get("name") != kernel_step_name
        ):
            raise PermitInputError(
                f"candidate {label} has an alternate Kernel checkout at step {index}"
            )
        run = step.get("run")
        if (
            isinstance(run, str)
            and any(
                "autonomous_release_permit.py" in command
                and command != PERMIT_RUNTIME_COPY
                for command in collect_shell_commands(
                    run,
                    label=f"{label} step {index} run",
                )
            )
            and step.get("name") != prepare_step_name
        ):
            raise PermitInputError(
                f"candidate {label} has an alternate permit-builder command at step {index}"
            )


def validate_candidate_workflow(workflow: str, *, kernel_sha: str) -> None:
    kernel_sha = require_sha(
        kernel_sha, label="candidate workflow Kernel SHA", length=40
    )
    try:
        template = WORKFLOW_TEMPLATE_PATH.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError("parent workflow template is not UTF-8") from exc
    marker_count = template.count(WORKFLOW_TEMPLATE_MARKER)
    if marker_count != WORKFLOW_TEMPLATE_PIN_COUNT:
        raise PermitInputError(
            "parent workflow template does not contain the exact Kernel pin count"
        )
    if WORKFLOW_TEMPLATE_MARKER in workflow:
        raise PermitInputError("candidate workflow contains the template marker")
    expected = template.replace(WORKFLOW_TEMPLATE_MARKER, kernel_sha)
    if workflow != expected:
        expected_sha = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        observed_sha = hashlib.sha256(workflow.encode("utf-8")).hexdigest()
        raise PermitInputError(
            "candidate workflow is outside the parent-owned complete allowlist "
            f"(expected sha256:{expected_sha}, observed sha256:{observed_sha})"
        )
    parse_strict_workflow_yaml(workflow)


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
        env={
            key: value
            for key in (
                "HOME",
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "PATH",
                "TMPDIR",
            )
            if (value := os.environ.get(key))
        }
        | ({"PATH": os.defpath} if not os.environ.get("PATH") else {}),
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(f"pinned Kernel rejected the permit: {detail}")


def sanitized_subprocess_environment() -> dict[str, str]:
    """Return a minimal environment without ambient authority credentials."""
    environment = {
        key: value
        for key in (
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "PATH",
            "TMPDIR",
        )
        if (value := os.environ.get(key))
    }
    environment.setdefault("PATH", os.defpath)
    return environment


def rebuild_reviews_and_permit(
    *,
    verifier: Path,
    permit: Path,
    trusted_context: Path,
    review_evidence_dir: Path,
    recomputed_permit: Path,
) -> None:
    """Rebuild raw review evidence and the exact permit with parent-owned code."""
    evidence_dir = review_evidence_dir.resolve()
    try:
        entries = list(evidence_dir.iterdir())
    except OSError as exc:
        raise PermitInputError(f"cannot read review evidence directory: {exc}") from exc
    if {entry.name for entry in entries} != REVIEW_EVIDENCE_FILENAMES or any(
        not entry.is_file() or entry.is_symlink() for entry in entries
    ):
        raise PermitInputError(
            "review evidence directory must contain only the exact two-provider "
            "raw, normalized, and envelope files"
        )

    rebuilt_root = recomputed_permit.resolve().parent / "parent-rebuilt-reviews"
    try:
        rebuilt_root.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise PermitInputError(
            "parent-rebuilt review directory already exists"
        ) from exc
    rebuilt_reviews: list[Path] = []
    for provider, model in MODEL_REVIEWERS.items():
        rebuilt_reviews.append(
            rebuild_review_evidence(
                context=trusted_context.resolve(),
                raw_transport=evidence_dir / f"raw-{provider}.txt",
                normalized_response=evidence_dir / f"normalized-{provider}.json",
                review_envelope=evidence_dir / f"review-{provider}.json",
                provider=provider,
                model=model,
                output_dir=rebuilt_root / provider,
            )
        )

    command = [
        str(verifier.resolve()),
        "--context",
        str(trusted_context.resolve()),
    ]
    for review in rebuilt_reviews:
        command.extend(("--review", str(review.resolve())))
    command.extend(("--output", str(recomputed_permit.resolve())))
    process = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=sanitized_subprocess_environment(),
    )
    candidate = validate_permit(load_json_bytes(permit.read_bytes(), label=str(permit)))
    del candidate
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(
            "parent Kernel did not independently reproduce the ALLOW permit"
            + (f": {detail}" if detail else "")
        )
    try:
        recomputed = recomputed_permit.read_bytes()
    except FileNotFoundError as exc:
        raise PermitInputError(
            "parent Kernel did not emit a recomputed permit"
        ) from exc
    if recomputed != permit.read_bytes():
        raise PermitInputError(
            "candidate permit differs from the parent raw-evidence reduction"
        )


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
    rebuild_reviews_and_permit(
        verifier=args.permit_verifier,
        permit=args.permit,
        trusted_context=args.trusted_context,
        review_evidence_dir=args.review_evidence_dir,
        recomputed_permit=args.recomputed_permit,
    )

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
    if candidate_authority["kernel_sha"] != permit_authority["kernel_sha"]:
        raise PermitInputError(
            "candidate Kernel changes require a separately ratified full-source "
            "Kernel-upgrade protocol"
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

    workflow_bytes = git_blob(
        candidate_repository,
        candidate_sha,
        ".github/workflows/ci.yml",
    )
    try:
        workflow = workflow_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"candidate workflow is invalid UTF-8: {exc}") from exc
    validate_candidate_workflow(
        workflow,
        kernel_sha=candidate_authority["kernel_sha"],
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
    parser.add_argument("--review-evidence-dir", type=Path, required=True)
    parser.add_argument("--recomputed-permit", type=Path, required=True)
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
