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


def require_commit(repository: Path, revision: str, *, label: str) -> str:
    revision = require_sha(revision, label=label)
    observed = run_git(repository, "rev-parse", f"{revision}^{{commit}}")
    observed_text = observed.decode("ascii").strip()
    if observed_text != revision:
        raise WorkflowTreeError(f"{label} did not resolve to the exact requested commit")
    return observed_text


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
) -> dict[str, object]:
    parent_sha = require_sha(parent_sha, label="parent_sha")
    candidate_sha = require_sha(candidate_sha, label="candidate_sha")
    require_commit(parent_repository, parent_sha, label="parent_sha")
    require_commit(candidate_repository, candidate_sha, label="candidate_sha")
    parent = workflow_inventory(
        parent_repository,
        parent_sha,
        label="immutable parent workflow tree",
    )
    candidate = workflow_inventory(
        candidate_repository,
        candidate_sha,
        label="candidate workflow tree",
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
        if git_blob(candidate_repository, candidate_sha, path) != git_blob(
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
        "workflow_paths": sorted(parent_paths),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify exact candidate workflow tree")
    parser.add_argument("--parent-repository", type=Path, required=True)
    parser.add_argument("--parent-sha", required=True)
    parser.add_argument("--candidate-repository", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = verify(
            parent_repository=args.parent_repository.resolve(),
            parent_sha=args.parent_sha,
            candidate_repository=args.candidate_repository.resolve(),
            candidate_sha=args.candidate_sha,
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
