#!/usr/bin/env python3
"""Verify that a previous authority generation ratified its exact successor."""

from __future__ import annotations

import argparse
import copy
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

PARENT_WORKFLOW_DIRECTORY = ".github/workflows"
PARENT_WORKFLOW_PATH = f"{PARENT_WORKFLOW_DIRECTORY}/ci.yml"
WORKFLOW_REGULAR_MODE = "100644"

# The parent checkout is the trusted authority. Its complete workflow is the
# allowlist: the candidate may differ only at the four bindings that move the
# Kernel verifier to the candidate authority generation. The following static
# shape makes the authority surface explicit and rejects a parent checkout that
# has drifted from the reviewed protocol without this verifier being updated.
AUTHORITY_TOP_LEVEL_KEYS = ("name", "on", "permissions", "jobs")
AUTHORITY_TRIGGERS: dict[str, Any] = {
    "pull_request": {
        "types": ["opened", "reopened", "synchronize", "ready_for_review", "edited"]
    },
    "push": {"branches": ["main"]},
}
AUTHORITY_JOB_IDS = (
    "local-validation",
    "workflow-provenance",
    "repository-gates",
    "prepare",
    "model-review",
    "permit",
    "machine-approval",
)
AUTHORITY_JOB_NEEDS: dict[str, Any] = {
    "local-validation": None,
    "workflow-provenance": None,
    "repository-gates": None,
    "prepare": "repository-gates",
    "model-review": "prepare",
    "permit": ["repository-gates", "prepare", "model-review"],
    "machine-approval": "permit",
}

CHECKOUT_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
KERNEL_REPOSITORY = "Mindburn-Labs/helm-ai-kernel"
PREPARE_KERNEL_STEP = "Checkout pinned Kernel verifier source for isolated review"
PERMIT_KERNEL_STEP = "Checkout pinned Kernel verifier"
MACHINE_APPROVAL_KERNEL_STEP = "Checkout pinned Kernel verifier"
PREPARE_BUNDLE_STEP = "Prepare commit-bound review bundle"
KERNEL_BINDINGS = (
    ("prepare", PREPARE_KERNEL_STEP, "with", "ref"),
    ("permit", PERMIT_KERNEL_STEP, "with", "ref"),
    ("machine-approval", MACHINE_APPROVAL_KERNEL_STEP, "with", "ref"),
    ("prepare", PREPARE_BUNDLE_STEP, "env", "KERNEL_SHA"),
)

APPROVER_TOKEN_STEP = "Mint isolated approval-only App token"
APPROVER_TOKEN_ACTION = (
    "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
)
APPROVER_TOKEN_ID = "approver-token"
APPROVER_TOKEN_REFERENCE = "${{ steps.approver-token.outputs.token }}"
APPROVAL_STEP = "Approve only the exact signed head"
IMMUTABLE_WORKFLOW_REF = "${{ github.workflow_sha }}"
MACHINE_APPROVAL_VERIFIER_BUILD = (
    'go build -trimpath -o "$GITHUB_WORKSPACE/release-permit-verify" '
    "./cmd/release-permit-verify"
)
MACHINE_APPROVAL_STEP_NAMES = (
    "Download signed ALLOW permit",
    "Download permit context",
    "Checkout immutable approval broker",
    "Checkout pinned Kernel verifier",
    "Set up pinned Kernel toolchain",
    "Build source-owned permit verifier",
    "Mint isolated approval-only App token",
    "Bind exact approval App identity",
    "Approve only the exact signed head",
    "Retain approval receipt",
)

# Psych is already a repository prerequisite. It is used here rather than a
# permissive YAML loader so comments, duplicate keys, aliases, merge keys, or
# YAML 1.1 coercion (notably on -> true) cannot manufacture an authority
# workflow that looks equivalent only after parsing. The AST projection keeps
# scalar spellings intact while rejecting non-standard tags.
STRICT_WORKFLOW_YAML_PARSER = r'''
require "json"
require "psych"

def reject_unsafe_yaml(node)
  if node.respond_to?(:anchor) && node.anchor
    raise "YAML aliases or anchors are not allowed"
  end

  if node.respond_to?(:tag) && node.tag
    raise "YAML tags are not allowed"
  end

  case node
  when Psych::Nodes::Scalar
    nil
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

def project_yaml(node)
  case node
  when Psych::Nodes::Scalar
    node.value
  when Psych::Nodes::Sequence
    node.children.map { |child| project_yaml(child) }
  when Psych::Nodes::Mapping
    object = {}
    node.children.each_slice(2) do |key, value|
      object[key.value] = project_yaml(value)
    end
    object
  else
    raise "unsupported YAML node: #{node.class}"
  end
end

begin
  source = STDIN.read
  stream = Psych.parse_stream(source)
  unless stream.children.length == 1
    raise "YAML document must contain exactly one document"
  end
  document_node = stream.children.first
  unless document_node.is_a?(Psych::Nodes::Document) && document_node.children.length == 1
    raise "YAML document must contain exactly one root node"
  end
  reject_unsafe_yaml(document_node)
  document = project_yaml(document_node.children.first)
  unless document.is_a?(Hash)
    raise "YAML document must be an object"
  end
  STDOUT.write(JSON.generate(document))
rescue StandardError => error
  warn error.message
  exit 1
end
'''


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


def parse_strict_workflow_yaml(
    content: str,
    *,
    label: str = "candidate workflow",
) -> dict[str, Any]:
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
            f"{label} YAML parser is unavailable: {exc}"
        ) from exc
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(f"{label} YAML rejected: {detail}")
    parsed = load_json_bytes(process.stdout, label=f"{label} YAML")
    return require_mapping(parsed, label=label)


def find_named_step(job: dict[str, Any], *, name: str, label: str) -> dict[str, Any]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise PermitInputError(f"{label} steps must be an array")
    matches = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("name") == name
    ]
    if len(matches) != 1:
        raise PermitInputError(
            f"{label} must contain exactly one {name!r} step"
        )
    return matches[0]


def require_ordered_keys(
    value: dict[str, Any],
    *,
    expected: tuple[str, ...],
    label: str,
) -> None:
    if tuple(value) != expected:
        raise PermitInputError(
            f"{label} keys must exactly match the parent-owned authority contract"
        )


def validate_authority_workflow_shape(
    workflow: dict[str, Any],
    *,
    label: str,
) -> None:
    require_ordered_keys(
        workflow,
        expected=AUTHORITY_TOP_LEVEL_KEYS,
        label=label,
    )
    if workflow["on"] != AUTHORITY_TRIGGERS:
        raise PermitInputError(f"{label} triggers differ from the authority contract")
    if workflow["permissions"] != {}:
        raise PermitInputError(
            f"{label} top-level permissions differ from the authority contract"
        )

    jobs = require_mapping(workflow["jobs"], label=f"{label} jobs")
    require_ordered_keys(jobs, expected=AUTHORITY_JOB_IDS, label=f"{label} jobs")
    for job_id, expected_needs in AUTHORITY_JOB_NEEDS.items():
        job = require_mapping(jobs[job_id], label=f"{label} {job_id} job")
        observed_needs = job.get("needs")
        if expected_needs is None:
            if "needs" in job:
                raise PermitInputError(
                    f"{label} {job_id} job must not declare dependencies"
                )
        elif observed_needs != expected_needs:
            raise PermitInputError(
                f"{label} {job_id} dependency graph differs from the authority contract"
            )


def find_value_paths(value: Any, *, target: str, path: str) -> list[str]:
    if isinstance(value, dict):
        paths: list[str] = []
        for key, child in value.items():
            paths.extend(find_value_paths(child, target=target, path=f"{path}.{key}"))
        return paths
    if isinstance(value, list):
        paths = []
        for index, child in enumerate(value):
            paths.extend(find_value_paths(child, target=target, path=f"{path}[{index}]"))
        return paths
    return [path] if value == target else []


def validate_machine_approval_chain(
    workflow: dict[str, Any],
    *,
    label: str,
) -> None:
    jobs = require_mapping(workflow.get("jobs"), label=f"{label} jobs")
    machine_approval = require_mapping(
        jobs.get("machine-approval"),
        label=f"{label} machine-approval job",
    )
    steps = machine_approval.get("steps")
    if not isinstance(steps, list):
        raise PermitInputError(f"{label} machine-approval steps must be an array")
    if tuple(
        step.get("name") if isinstance(step, dict) else None for step in steps
    ) != MACHINE_APPROVAL_STEP_NAMES:
        raise PermitInputError(
            f"{label} machine-approval steps differ from the authority contract"
        )

    broker_step = find_named_step(
        machine_approval,
        name="Checkout immutable approval broker",
        label=f"{label} machine-approval job",
    )
    broker_checkout = require_mapping(
        broker_step.get("with"),
        label=f"{label} immutable approval broker checkout",
    )
    if (
        broker_step.get("uses") != CHECKOUT_ACTION
        or broker_checkout.get("repository") != "Mindburn-Labs/.github"
        or broker_checkout.get("ref") != IMMUTABLE_WORKFLOW_REF
        or broker_checkout.get("persist-credentials") != "false"
        or broker_checkout.get("path") != "policy"
    ):
        raise PermitInputError(
            f"{label} immutable approval broker checkout differs from the authority contract"
        )

    kernel_step = find_named_step(
        machine_approval,
        name=MACHINE_APPROVAL_KERNEL_STEP,
        label=f"{label} machine-approval job",
    )
    kernel_checkout = require_mapping(
        kernel_step.get("with"),
        label=f"{label} machine-approval Kernel checkout",
    )
    if (
        kernel_step.get("uses") != CHECKOUT_ACTION
        or kernel_checkout.get("repository") != KERNEL_REPOSITORY
        or kernel_checkout.get("persist-credentials") != "false"
        or kernel_checkout.get("path") != "kernel"
    ):
        raise PermitInputError(
            f"{label} machine-approval Kernel checkout differs from the authority contract"
        )
    require_sha(
        kernel_checkout.get("ref"),
        label=f"{label} machine-approval Kernel checkout ref",
        length=40,
    )

    verifier_build = find_named_step(
        machine_approval,
        name="Build source-owned permit verifier",
        label=f"{label} machine-approval job",
    )
    if (
        verifier_build.get("working-directory") != "kernel/core"
        or verifier_build.get("run") != MACHINE_APPROVAL_VERIFIER_BUILD
    ):
        raise PermitInputError(
            f"{label} machine-approval verifier build differs from the authority contract"
        )

    token_step = find_named_step(
        machine_approval,
        name=APPROVER_TOKEN_STEP,
        label=f"{label} machine-approval job",
    )
    if token_step.get("id") != APPROVER_TOKEN_ID:
        raise PermitInputError(f"{label} approval token step ID is not exact")
    if token_step.get("uses") != APPROVER_TOKEN_ACTION:
        raise PermitInputError(f"{label} approval token action SHA is not exact")

    approval_step = find_named_step(
        machine_approval,
        name=APPROVAL_STEP,
        label=f"{label} machine-approval job",
    )
    approval_environment = require_mapping(
        approval_step.get("env"),
        label=f"{label} exact-head approval environment",
    )
    if (
        approval_environment.get("HELM_AUTHORITY_APPROVER_TOKEN")
        != APPROVER_TOKEN_REFERENCE
    ):
        raise PermitInputError(
            f"{label} exact-head approval does not consume the isolated App token"
        )
    token_paths = find_value_paths(
        workflow,
        target=APPROVER_TOKEN_REFERENCE,
        path="workflow",
    )
    expected_token_path = (
        "workflow.jobs.machine-approval.steps[8].env."
        "HELM_AUTHORITY_APPROVER_TOKEN"
    )
    if token_paths != [expected_token_path]:
        raise PermitInputError(
            f"{label} isolated App token must have exactly one approval-step consumer"
        )


def expected_candidate_workflow(kernel_sha: str) -> dict[str, Any]:
    require_sha(kernel_sha, label="candidate authority kernel_sha", length=40)
    try:
        parent_text = parent_workflow_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError(
            f"parent authority workflow is invalid UTF-8: {exc}"
        ) from exc
    parent = parse_strict_workflow_yaml(parent_text, label="parent authority workflow")
    validate_authority_workflow_shape(parent, label="parent authority workflow")
    validate_machine_approval_chain(parent, label="parent authority workflow")

    expected = copy.deepcopy(parent)
    jobs = require_mapping(expected["jobs"], label="parent authority workflow jobs")
    for job_id, step_name, section_name, field_name in KERNEL_BINDINGS:
        job = require_mapping(
            jobs[job_id],
            label=f"parent authority workflow {job_id} job",
        )
        step = find_named_step(
            job,
            name=step_name,
            label=f"parent authority workflow {job_id} job",
        )
        section = require_mapping(
            step.get(section_name),
            label=f"parent authority workflow {job_id} {step_name} {section_name}",
        )
        baseline_value = section.get(field_name)
        require_sha(
            baseline_value,
            label=(
                "parent authority workflow "
                f"{job_id} {step_name} {section_name}.{field_name}"
            ),
            length=40,
        )
        section[field_name] = kernel_sha
    return expected


def first_workflow_difference(
    expected: Any,
    candidate: Any,
    *,
    path: str = "workflow",
) -> str | None:
    if type(expected) is not type(candidate):
        return path
    if isinstance(expected, dict):
        if tuple(expected) != tuple(candidate):
            return f"{path} keys/order"
        for key, expected_value in expected.items():
            difference = first_workflow_difference(
                expected_value,
                candidate[key],
                path=f"{path}.{key}",
            )
            if difference is not None:
                return difference
        return None
    if isinstance(expected, list):
        if len(expected) != len(candidate):
            return f"{path} length"
        for index, (expected_value, candidate_value) in enumerate(
            zip(expected, candidate)
        ):
            difference = first_workflow_difference(
                expected_value,
                candidate_value,
                path=f"{path}[{index}]",
            )
            if difference is not None:
                return difference
        return None
    return None if expected == candidate else path


def validate_candidate_workflow(workflow: str, *, kernel_sha: str) -> None:
    candidate = parse_strict_workflow_yaml(workflow)
    validate_authority_workflow_shape(candidate, label="candidate workflow")
    validate_machine_approval_chain(candidate, label="candidate workflow")
    expected = expected_candidate_workflow(kernel_sha)
    difference = first_workflow_difference(expected, candidate)
    if difference is not None:
        raise PermitInputError(
            "candidate workflow differs from the complete parent-owned authority "
            f"contract at {difference}"
        )


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


def parent_repository() -> Path:
    return Path(__file__).resolve().parents[1]


def git_workflow_inventory(
    repository: Path,
    revision: str,
    *,
    label: str,
) -> dict[str, tuple[str, str, str]]:
    records = run_git(
        repository,
        "ls-tree",
        "-r",
        "-z",
        revision,
        "--",
        PARENT_WORKFLOW_DIRECTORY,
    ).split(b"\0")
    inventory: dict[str, tuple[str, str, str]] = {}
    prefix = f"{PARENT_WORKFLOW_DIRECTORY}/"
    for record in records:
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", maxsplit=1)
            mode, object_type, object_id = metadata.split(b" ", maxsplit=2)
            path = raw_path.decode("utf-8")
            parsed_mode = mode.decode("ascii")
            parsed_type = object_type.decode("ascii")
            parsed_object_id = object_id.decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise PermitInputError(f"{label} has an invalid Git workflow-tree entry") from exc
        if not path.startswith(prefix):
            raise PermitInputError(f"{label} escaped the workflow directory: {path!r}")
        if path in inventory:
            raise PermitInputError(f"{label} contains duplicate workflow path: {path}")
        require_sha(parsed_object_id, label=f"{label} object for {path}", length=40)
        inventory[path] = (parsed_mode, parsed_type, parsed_object_id)
    if not inventory:
        raise PermitInputError(f"{label} has no workflow files")
    return inventory


def parent_workflow_inventory() -> dict[str, tuple[str, str, str]]:
    inventory = git_workflow_inventory(
        parent_repository(),
        "HEAD",
        label="parent authority workflow inventory",
    )
    if PARENT_WORKFLOW_PATH not in inventory:
        raise PermitInputError("parent authority workflow inventory is missing ci.yml")
    for path, (mode, object_type, _) in inventory.items():
        if mode != WORKFLOW_REGULAR_MODE or object_type != "blob":
            raise PermitInputError(
                "parent authority workflow inventory contains a non-regular file: "
                f"{path}",
            )
    return inventory


def parent_workflow_bytes() -> bytes:
    parent_workflow_inventory()
    return git_blob(parent_repository(), "HEAD", PARENT_WORKFLOW_PATH)


def validate_candidate_workflow_inventory(
    candidate_repository: Path,
    candidate_sha: str,
    *,
    kernel_sha: str,
) -> None:
    parent_inventory = parent_workflow_inventory()
    candidate_inventory = git_workflow_inventory(
        candidate_repository,
        candidate_sha,
        label="candidate workflow inventory",
    )
    parent_paths = set(parent_inventory)
    candidate_paths = set(candidate_inventory)
    if candidate_paths != parent_paths:
        missing = sorted(parent_paths - candidate_paths)
        unexpected = sorted(candidate_paths - parent_paths)
        raise PermitInputError(
            "candidate workflow inventory differs from the immutable parent; "
            f"missing={missing}, unexpected={unexpected}",
        )

    parent_repository_path = parent_repository()
    for path in sorted(parent_paths):
        parent_mode, parent_type, _ = parent_inventory[path]
        candidate_mode, candidate_type, _ = candidate_inventory[path]
        if (candidate_mode, candidate_type) != (parent_mode, parent_type):
            raise PermitInputError(
                "candidate workflow inventory mode/type differs from the immutable "
                f"parent at {path}: expected {parent_mode} {parent_type}, "
                f"observed {candidate_mode} {candidate_type}",
            )
        if path == PARENT_WORKFLOW_PATH:
            continue
        if git_blob(candidate_repository, candidate_sha, path) != git_blob(
            parent_repository_path,
            "HEAD",
            path,
        ):
            raise PermitInputError(
                "candidate non-authority workflow differs from the immutable parent: "
                f"{path}",
            )

    workflow_bytes = git_blob(candidate_repository, candidate_sha, PARENT_WORKFLOW_PATH)
    try:
        workflow = workflow_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"candidate workflow is invalid UTF-8: {exc}") from exc
    validate_candidate_workflow(workflow, kernel_sha=kernel_sha)


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

    validate_candidate_workflow_inventory(
        candidate_repository,
        candidate_sha,
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
