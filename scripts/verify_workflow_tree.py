#!/usr/bin/env python3
"""Fail closed when a candidate workflow tree differs from its parent.

The trusted authority broker uses this in shadow mode before it ever requests
an environment, model capability, attestation capability, or App token. It
reads Git objects only; it never checks out or executes candidate content.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


WORKFLOW_DIRECTORY = ".github/workflows"
CI_WORKFLOW_PATH = f"{WORKFLOW_DIRECTORY}/ci.yml"
REGULAR_MODE = "100644"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_FILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$")
SAFE_ENVIRONMENT_KEYS = ("HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH", "SYSTEMROOT", "TMPDIR")
REPOSITORY_PATTERN = re.compile(r"^Mindburn-Labs/[A-Za-z0-9_.-]+$")
ADMISSION_SCHEMA = "mindburn.authority-pr-admission/v1"
OBJECT_RECEIPT_SCHEMA = "mindburn.authority-bare-git-input/v2"
MAX_OBJECT_RECEIPT_BYTES = 16 * 1024


class WorkflowTreeError(ValueError):
    """Raised when a workflow tree is not an exact safe shadow candidate."""


def git_environment() -> dict[str, str]:
    """Strip ambient Git state before reading trusted and bare repositories."""

    environment = {
        key: os.environ[key]
        for key in SAFE_ENVIRONMENT_KEYS
        if key in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        },
    )
    return environment


def run_git(repository: Path, *arguments: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    if process.returncode != 0:
        raise WorkflowTreeError(f"git {arguments[0]} failed while reading workflow objects")
    return process.stdout


def require_sha(value: str, *, label: str) -> str:
    if not SHA_PATTERN.fullmatch(value):
        raise WorkflowTreeError(f"{label} must be a lowercase 40-character SHA")
    return value


def require_repository(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not REPOSITORY_PATTERN.fullmatch(value):
        raise WorkflowTreeError(f"{label} must be a Mindburn-Labs owner/name pair")
    return value


def require_positive_integer(value: object, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise WorkflowTreeError(f"{label} must be a positive integer")
    return value


def require_exact_mapping(value: object, *, label: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise WorkflowTreeError(f"{label} must contain exactly {sorted(keys)}")
    return value


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkflowTreeError(f"object receipt JSON contains duplicate key: {key}")
        result[key] = value
    return result


def normalize_admission(value: object) -> dict[str, object]:
    admission = require_exact_mapping(
        value,
        label="object receipt admission",
        keys={
            "schema",
            "repository",
            "pr_number",
            "base",
            "head",
            "merge_sha",
            "workflow_run_head_sha",
        },
    )
    if admission["schema"] != ADMISSION_SCHEMA:
        raise WorkflowTreeError(f"object receipt admission.schema must equal {ADMISSION_SCHEMA}")
    repository = require_repository(admission["repository"], label="object receipt admission.repository")
    pr_number = require_positive_integer(
        admission["pr_number"],
        label="object receipt admission.pr_number",
    )
    base = require_exact_mapping(
        admission["base"],
        label="object receipt admission.base",
        keys={"ref", "sha"},
    )
    head = require_exact_mapping(
        admission["head"],
        label="object receipt admission.head",
        keys={"repository", "sha"},
    )
    if base["ref"] != "main":
        raise WorkflowTreeError("object receipt admission.base.ref must equal main")
    base_sha = require_sha(
        base["sha"] if isinstance(base["sha"], str) else "",
        label="object receipt admission.base.sha",
    )
    head_repository = require_repository(
        head["repository"],
        label="object receipt admission.head.repository",
    )
    if head_repository != repository:
        raise WorkflowTreeError(
            "object receipt admission.head.repository must equal admission.repository",
        )
    head_sha = require_sha(
        head["sha"] if isinstance(head["sha"], str) else "",
        label="object receipt admission.head.sha",
    )
    merge_sha = require_sha(
        admission["merge_sha"] if isinstance(admission["merge_sha"], str) else "",
        label="object receipt admission.merge_sha",
    )
    workflow_run_head_sha = require_sha(
        admission["workflow_run_head_sha"]
        if isinstance(admission["workflow_run_head_sha"], str)
        else "",
        label="object receipt admission.workflow_run_head_sha",
    )
    if workflow_run_head_sha != head_sha:
        raise WorkflowTreeError(
            "object receipt admission.workflow_run_head_sha must equal admission.head.sha",
        )
    return {
        "schema": ADMISSION_SCHEMA,
        "repository": repository,
        "pr_number": pr_number,
        "base": {"ref": "main", "sha": base_sha},
        "head": {"repository": head_repository, "sha": head_sha},
        "merge_sha": merge_sha,
        "workflow_run_head_sha": workflow_run_head_sha,
    }


def load_object_receipt(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > MAX_OBJECT_RECEIPT_BYTES:
            raise WorkflowTreeError("object receipt JSON exceeds the maximum size")
        decoded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkflowTreeError("object receipt must be valid UTF-8 JSON") from exc
    receipt = require_exact_mapping(
        decoded,
        label="object receipt",
        keys={"schema", "admission", "merge_parents"},
    )
    if receipt["schema"] != OBJECT_RECEIPT_SCHEMA:
        raise WorkflowTreeError(f"object receipt schema must equal {OBJECT_RECEIPT_SCHEMA}")
    admission = normalize_admission(receipt["admission"])
    merge_parents = receipt["merge_parents"]
    if not isinstance(merge_parents, list) or len(merge_parents) != 2:
        raise WorkflowTreeError("object receipt merge_parents must contain exactly two SHAs")
    parents = [
        require_sha(value if isinstance(value, str) else "", label="object receipt merge parent")
        for value in merge_parents
    ]
    base = admission["base"]
    head = admission["head"]
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise WorkflowTreeError("normalized object receipt admission has invalid bindings")
    if parents != [base["sha"], head["sha"]]:
        raise WorkflowTreeError("object receipt merge parents do not match admission base and head")
    return {"admission": admission, "merge_parents": parents}


def require_commit(repository: Path, revision: str, *, label: str) -> str:
    revision = require_sha(revision, label=label)
    observed = run_git(repository, "rev-parse", f"{revision}^{{commit}}")
    observed_text = observed.decode("ascii").strip()
    if observed_text != revision:
        raise WorkflowTreeError(f"{label} did not resolve to the exact requested commit")
    return observed_text


def require_bare_repository(repository: Path) -> None:
    observed = run_git(repository, "rev-parse", "--is-bare-repository").decode("ascii").strip()
    if observed != "true":
        raise WorkflowTreeError("candidate repository must be a bare Git-object store")


def commit_parents(repository: Path, revision: str) -> list[str]:
    return run_git(repository, "show", "-s", "--format=%P", revision).decode("ascii").strip().split()


def workflow_inventory(
    repository: Path,
    revision: str,
    *,
    label: str,
) -> dict[str, tuple[str, str, str]]:
    output = run_git(
        repository,
        "ls-tree",
        "-r",
        "-z",
        revision,
        "--",
        WORKFLOW_DIRECTORY,
    )
    prefix = f"{WORKFLOW_DIRECTORY}/"
    inventory: dict[str, tuple[str, str, str]] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", maxsplit=1)
            mode, object_type, object_id = metadata.split(b" ", maxsplit=2)
            path = raw_path.decode("utf-8")
            entry = (
                mode.decode("ascii"),
                object_type.decode("ascii"),
                object_id.decode("ascii"),
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise WorkflowTreeError(f"{label} contains an invalid Git tree entry") from exc
        if not path.startswith(prefix):
            raise WorkflowTreeError(f"{label} escaped the workflow directory: {path!r}")
        relative_path = path.removeprefix(prefix)
        if "/" in relative_path or not WORKFLOW_FILE_PATTERN.fullmatch(relative_path):
            raise WorkflowTreeError(f"{label} has an unsupported workflow path: {path!r}")
        if path in inventory:
            raise WorkflowTreeError(f"{label} contains a duplicate workflow path: {path}")
        inventory[path] = entry
    if not inventory or CI_WORKFLOW_PATH not in inventory:
        raise WorkflowTreeError(f"{label} must contain {CI_WORKFLOW_PATH}")
    return inventory


def git_blob(repository: Path, revision: str, path: str) -> bytes:
    return run_git(repository, "show", f"{revision}:{path}")


def verify(
    *,
    parent_repository: Path,
    parent_sha: str,
    candidate_repository: Path,
    candidate_sha: str,
    merge_sha: str,
) -> dict[str, object]:
    parent_sha = require_sha(parent_sha, label="parent_sha")
    candidate_sha = require_sha(candidate_sha, label="candidate_sha")
    merge_sha = require_sha(merge_sha, label="merge_sha")
    require_commit(parent_repository, parent_sha, label="parent_sha")
    require_bare_repository(candidate_repository)
    require_commit(candidate_repository, candidate_sha, label="candidate_sha")
    require_commit(candidate_repository, merge_sha, label="merge_sha")
    observed_head = run_git(candidate_repository, "rev-parse", "HEAD").decode("ascii").strip()
    if observed_head != merge_sha:
        raise WorkflowTreeError("candidate bare HEAD did not bind to merge_sha")
    if commit_parents(candidate_repository, merge_sha) != [parent_sha, candidate_sha]:
        raise WorkflowTreeError("merge commit parents do not exactly match parent_sha and candidate_sha")
    parent = workflow_inventory(
        parent_repository,
        parent_sha,
        label="immutable parent workflow tree",
    )
    candidate = workflow_inventory(
        candidate_repository,
        merge_sha,
        label="candidate merge workflow tree",
    )
    for path, (mode, object_type, _) in parent.items():
        if mode != REGULAR_MODE or object_type != "blob":
            raise WorkflowTreeError(
                f"immutable parent workflow tree has a non-regular entry: {path}",
            )
    parent_paths = set(parent)
    candidate_paths = set(candidate)
    if candidate_paths != parent_paths:
        raise WorkflowTreeError(
            "candidate workflow tree differs from immutable parent paths; "
            f"missing={sorted(parent_paths - candidate_paths)}, "
            f"unexpected={sorted(candidate_paths - parent_paths)}",
        )
    for path in sorted(parent_paths):
        parent_mode, parent_type, _ = parent[path]
        candidate_mode, candidate_type, _ = candidate[path]
        if (candidate_mode, candidate_type) != (parent_mode, parent_type):
            raise WorkflowTreeError(
                f"candidate workflow mode/type differs at {path}: "
                f"expected {parent_mode} {parent_type}, "
                f"observed {candidate_mode} {candidate_type}",
            )
        if git_blob(candidate_repository, merge_sha, path) != git_blob(
            parent_repository,
            parent_sha,
            path,
        ):
            raise WorkflowTreeError(
                f"candidate workflow blob differs from immutable parent: {path}",
            )
    return {
        "schema": "mindburn.authority-workflow-tree-admission/v1",
        "mode": "shadow-exact-tree",
        "parent_sha": parent_sha,
        "candidate_sha": candidate_sha,
        "merge_sha": merge_sha,
        "workflow_paths": sorted(parent_paths),
    }


def verify_object_receipt(
    *,
    parent_repository: Path,
    candidate_repository: Path,
    object_receipt: Path,
) -> dict[str, object]:
    """Verify a candidate using the single object-binding receipt from fetch.

    The receipt remains data, not authority: this function re-binds every
    referenced Git object and merge parent before comparing workflow blobs.
    """

    receipt = load_object_receipt(object_receipt)
    admission = receipt["admission"]
    if not isinstance(admission, dict):
        raise WorkflowTreeError("object receipt admission is invalid")
    base = admission["base"]
    head = admission["head"]
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise WorkflowTreeError("object receipt admission bindings are invalid")
    result = verify(
        parent_repository=parent_repository,
        parent_sha=base["sha"],
        candidate_repository=candidate_repository,
        candidate_sha=head["sha"],
        merge_sha=admission["merge_sha"],
    )
    result["schema"] = "mindburn.authority-workflow-tree-admission/v2"
    result["admission"] = admission
    result["object_receipt_schema"] = OBJECT_RECEIPT_SCHEMA
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify exact candidate workflow tree")
    parser.add_argument("--parent-repository", type=Path, required=True)
    parser.add_argument("--candidate-repository", type=Path, required=True)
    parser.add_argument("--object-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = verify_object_receipt(
            parent_repository=args.parent_repository.resolve(),
            candidate_repository=args.candidate_repository.resolve(),
            object_receipt=args.object_receipt.resolve(),
        )
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output is not None:
            args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (OSError, WorkflowTreeError) as exc:
        print(f"verify-workflow-tree: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
