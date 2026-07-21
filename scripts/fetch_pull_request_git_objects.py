#!/usr/bin/env python3
"""Fetch exact pull-request objects into a bare store without a checkout.

This helper is for a trusted, default-branch broker. It accepts one strict PR
admission document, creates a new bare repository, and never checks out,
executes, or sources candidate content. The caller must retain the resulting
store locally; it is input for Git-object inspection, not an artifact to
publish.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


REPOSITORY_PATTERN = re.compile(r"^Mindburn-Labs/[A-Za-z0-9_.-]+$")
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
FETCH_DEPTHS = {"base": 1, "head": 1, "merge": 2}
SAFE_ENVIRONMENT_KEYS = ("HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH", "SYSTEMROOT", "TMPDIR")
ADMISSION_SCHEMA = "mindburn.authority-pr-admission/v1"
OBJECT_RECEIPT_SCHEMA = "mindburn.authority-bare-git-input/v2"
MAX_ADMISSION_BYTES = 16 * 1024


class PullRequestObjectError(ValueError):
    """Raised when a candidate Git-object store cannot be bound safely."""


def require_repository(value: str) -> str:
    if not REPOSITORY_PATTERN.fullmatch(value):
        raise PullRequestObjectError("repository must be a Mindburn-Labs owner/name pair")
    return value


def require_sha(value: str, *, label: str) -> str:
    if not SHA_PATTERN.fullmatch(value):
        raise PullRequestObjectError(f"{label} must be a lowercase 40-character SHA")
    return value


def require_positive_integer(value: object, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise PullRequestObjectError(f"{label} must be a positive integer")
    return value


def require_exact_mapping(value: object, *, label: str, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PullRequestObjectError(f"{label} must contain exactly {sorted(keys)}")
    return value


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PullRequestObjectError(f"admission JSON contains duplicate key: {key}")
        result[key] = value
    return result


def normalize_admission(value: object) -> dict[str, object]:
    """Validate one broker-produced PR snapshot without consulting GitHub.

    The future trusted broker must obtain these fields from one GitHub API/event
    snapshot. This parser deliberately does not claim to authenticate that
    snapshot; it only prevents independently supplied refs from being mixed.
    """

    admission = require_exact_mapping(
        value,
        label="admission",
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
        raise PullRequestObjectError(f"admission.schema must equal {ADMISSION_SCHEMA}")
    repository = require_repository(admission["repository"] if isinstance(admission["repository"], str) else "")
    pr_number = require_positive_integer(admission["pr_number"], label="admission.pr_number")
    base = require_exact_mapping(admission["base"], label="admission.base", keys={"ref", "sha"})
    head = require_exact_mapping(admission["head"], label="admission.head", keys={"repository", "sha"})
    if base["ref"] != "main":
        raise PullRequestObjectError("admission.base.ref must equal main")
    base_sha = require_sha(base["sha"] if isinstance(base["sha"], str) else "", label="admission.base.sha")
    head_repository = require_repository(
        head["repository"] if isinstance(head["repository"], str) else "",
    )
    if head_repository != repository:
        raise PullRequestObjectError("admission.head.repository must equal admission.repository")
    head_sha = require_sha(head["sha"] if isinstance(head["sha"], str) else "", label="admission.head.sha")
    merge_sha = require_sha(
        admission["merge_sha"] if isinstance(admission["merge_sha"], str) else "",
        label="admission.merge_sha",
    )
    workflow_run_head_sha = require_sha(
        admission["workflow_run_head_sha"] if isinstance(admission["workflow_run_head_sha"], str) else "",
        label="admission.workflow_run_head_sha",
    )
    if workflow_run_head_sha != head_sha:
        raise PullRequestObjectError("admission.workflow_run_head_sha must equal admission.head.sha")
    return {
        "schema": ADMISSION_SCHEMA,
        "repository": repository,
        "pr_number": pr_number,
        "base": {"ref": "main", "sha": base_sha},
        "head": {"repository": head_repository, "sha": head_sha},
        "merge_sha": merge_sha,
        "workflow_run_head_sha": workflow_run_head_sha,
    }


def load_admission(path: Path) -> dict[str, object]:
    try:
        if path.stat().st_size > MAX_ADMISSION_BYTES:
            raise PullRequestObjectError("admission JSON exceeds the maximum size")
        decoded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PullRequestObjectError("admission must be valid UTF-8 JSON") from exc
    return normalize_admission(decoded)


def require_token(environment_name: str) -> str:
    token = os.environ.get(environment_name)
    if not token or "\n" in token or "\r" in token:
        raise PullRequestObjectError(
            f"{environment_name} must contain a single-line GitHub token",
        )
    return token


def git_environment(token: str) -> dict[str, str]:
    """Return a minimal Git configuration with a process-local auth header.

    The credential is never put in a command argument, remote URL, or local
    config file. The bare store has no worktree and hooks are disabled.
    """

    environment = {
        key: os.environ[key]
        for key in SAFE_ENVIRONMENT_KEYS
        if key in os.environ
    }
    encoded = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode(
        "ascii",
    )
    configuration = (
        ("core.hooksPath", os.devnull),
        ("protocol.file.allow", "never"),
        ("protocol.git.allow", "never"),
        ("protocol.ssh.allow", "never"),
        ("protocol.ext.allow", "never"),
        ("protocol.http.allow", "never"),
        ("protocol.https.allow", "always"),
        ("fetch.fsckObjects", "true"),
        ("transfer.fsckObjects", "true"),
        ("http.https://github.com/.extraheader", f"AUTHORIZATION: basic {encoded}"),
    )
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": str(len(configuration)),
        },
    )
    for index, (key, value) in enumerate(configuration):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    return environment


def run_git(
    repository: Path | None,
    *arguments: str,
    environment: dict[str, str],
) -> bytes:
    command = ["git"]
    if repository is not None:
        command.extend(("-C", str(repository)))
    command.extend(arguments)
    process = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if process.returncode != 0:
        raise PullRequestObjectError(f"git {arguments[0]} failed while binding candidate objects")
    return process.stdout


def remote_url(repository: str) -> str:
    return f"https://github.com/{repository}.git"


def fetch_refspec(sha: str, *, label: str) -> str:
    return f"{sha}:refs/authority-input/{label}"


def fetch_arguments(sha: str, *, label: str) -> tuple[str, ...]:
    """Return a narrow fetch for one bound PR object.

    A shallow merge commit hides its parents, so the synthetic merge needs depth
    two for the parent binding that follows. Base and head are each fetched at
    depth one; no branch or tag refspec is accepted here.
    """

    try:
        depth = FETCH_DEPTHS[label]
    except KeyError as exc:
        raise PullRequestObjectError(f"unsupported pull-request object label: {label}") from exc
    return (
        "fetch",
        "--no-tags",
        "--no-recurse-submodules",
        f"--depth={depth}",
        "origin",
        fetch_refspec(sha, label=label),
    )


def prepare_store(
    *,
    admission: dict[str, object],
    output: Path,
    token: str,
) -> dict[str, Any]:
    admission = normalize_admission(admission)
    repository = admission["repository"]
    base_sha = admission["base"]["sha"]
    head_sha = admission["head"]["sha"]
    merge_sha = admission["merge_sha"]
    if not all(isinstance(value, str) for value in (repository, base_sha, head_sha, merge_sha)):
        raise PullRequestObjectError("normalized admission has invalid object bindings")
    if output.exists():
        raise PullRequestObjectError(f"candidate object store already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    environment = git_environment(token)
    run_git(None, "init", "--bare", str(output), environment=environment)
    run_git(output, "remote", "add", "origin", remote_url(repository), environment=environment)
    for label, sha in (("base", base_sha), ("head", head_sha), ("merge", merge_sha)):
        run_git(
            output,
            *fetch_arguments(sha, label=label),
            environment=environment,
        )
        run_git(output, "cat-file", "-e", f"{sha}^{{commit}}", environment=environment)
        observed_ref = run_git(
            output,
            "rev-parse",
            f"refs/authority-input/{label}",
            environment=environment,
        ).decode("ascii").strip()
        if observed_ref != sha:
            raise PullRequestObjectError(
                f"{label} ref did not bind to the requested commit",
            )

    parent_text = run_git(
        output,
        "show",
        "-s",
        "--format=%P",
        merge_sha,
        environment=environment,
    ).decode("ascii").strip()
    parents = parent_text.split()
    if parents != [base_sha, head_sha]:
        raise PullRequestObjectError(
            "merge commit parents do not exactly match the supplied base and head",
        )
    run_git(
        output,
        "symbolic-ref",
        "HEAD",
        "refs/authority-input/merge",
        environment=environment,
    )
    observed_head = run_git(output, "rev-parse", "HEAD", environment=environment).decode(
        "ascii",
    ).strip()
    if observed_head != merge_sha:
        raise PullRequestObjectError("bare candidate store did not bind HEAD to merge SHA")
    return {
        "schema": OBJECT_RECEIPT_SCHEMA,
        "admission": admission,
        "merge_parents": parents,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bind exact PR Git objects in a bare repository without checkout",
    )
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        receipt = prepare_store(
            admission=load_admission(args.admission.resolve()),
            output=args.output.resolve(),
            token=require_token("GITHUB_TOKEN"),
        )
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if args.receipt is not None:
            args.receipt.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (OSError, PullRequestObjectError) as exc:
        print(f"fetch-pull-request-git-objects: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
