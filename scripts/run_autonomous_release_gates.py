#!/usr/bin/env python3
"""Run immutable organization-owned validation commands for one repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


PROFILE_SCHEMA = "mindburn.autonomous-release-gates/v1"
REPOSITORY_PATTERN = re.compile(r"^Mindburn-Labs/[A-Za-z0-9_.-]+$")
TARGET_PATTERN_TEMPLATE = r"^{}:([^=]|$)"


class GateProfileError(ValueError):
    """Raised when a profile or target repository is not admissible."""


def parse_json_strict(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GateProfileError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise GateProfileError(f"{path}: invalid UTF-8: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as exc:
        raise GateProfileError(f"{path}: invalid JSON: {exc}") from exc


def require_exact_keys(value: dict[str, Any], required: set[str], label: str) -> None:
    keys = set(value)
    if keys != required:
        raise GateProfileError(
            f"{label} keys invalid; missing={sorted(required - keys)}, "
            f"unexpected={sorted(keys - required)}",
        )


def load_profiles(path: Path) -> dict[str, list[list[str]]]:
    document = parse_json_strict(path)
    if not isinstance(document, dict):
        raise GateProfileError("gate profile document must be an object")
    require_exact_keys(document, {"schema", "profiles"}, "gate profile document")
    if document["schema"] != PROFILE_SCHEMA:
        raise GateProfileError("unsupported gate profile schema")
    if not isinstance(document["profiles"], dict):
        raise GateProfileError("profiles must be an object")

    profiles: dict[str, list[list[str]]] = {}
    for repository, profile in document["profiles"].items():
        if not isinstance(repository, str) or not REPOSITORY_PATTERN.fullmatch(repository):
            raise GateProfileError(f"invalid profile repository: {repository!r}")
        if not isinstance(profile, dict):
            raise GateProfileError(f"profile {repository} must be an object")
        require_exact_keys(profile, {"commands"}, f"profile {repository}")
        commands = profile["commands"]
        if not isinstance(commands, list) or not commands or len(commands) > 32:
            raise GateProfileError(f"profile {repository} must contain 1-32 commands")
        validated_commands: list[list[str]] = []
        for index, command in enumerate(commands):
            if not isinstance(command, list) or not command or len(command) > 32:
                raise GateProfileError(f"profile {repository} command {index} is invalid")
            if any(
                not isinstance(argument, str)
                or not argument
                or len(argument) > 2048
                or "\x00" in argument
                for argument in command
            ):
                raise GateProfileError(
                    f"profile {repository} command {index} has an invalid argument",
                )
            if "/" in command[0] or "\\" in command[0]:
                raise GateProfileError(
                    f"profile {repository} command {index} must use a PATH executable",
                )
            validated_commands.append(command)
        profiles[repository] = validated_commands
    return profiles


def default_make_commands(target: Path) -> list[list[str]]:
    makefile = target / "Makefile"
    if not makefile.is_file():
        raise GateProfileError(
            "repository has no immutable profile and no Makefile fallback",
        )
    database = subprocess.run(
        ["make", "-qp"],
        cwd=target,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout

    def has_target(name: str) -> bool:
        return re.search(TARGET_PATTERN_TEMPLATE.format(re.escape(name)), database, re.MULTILINE) is not None

    for required_target in ("lint", "test"):
        if not has_target(required_target):
            raise GateProfileError(f"required make target {required_target!r} is not defined")

    commands: list[list[str]] = []
    if has_target("setup"):
        commands.append(["make", "setup"])
    commands.extend((["make", "lint"], ["make", "test"]))
    if has_target("build"):
        commands.append(["make", "build"])
    return commands


def resolve_commands(
    repository: str,
    target: Path,
    profiles: dict[str, list[list[str]]],
) -> tuple[str, list[list[str]]]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise GateProfileError("repository must be a Mindburn-Labs owner/name pair")
    if repository in profiles:
        return "explicit", profiles[repository]
    return "make-fallback", default_make_commands(target)


def run(args: argparse.Namespace) -> None:
    target = args.target.resolve()
    if not target.is_dir():
        raise GateProfileError(f"target directory does not exist: {target}")
    profiles = load_profiles(args.profiles)
    profile_kind, commands = resolve_commands(args.repository, target, profiles)
    profile_digest = hashlib.sha256(args.profiles.read_bytes()).hexdigest()
    print(
        f"release gate profile={profile_kind} repository={args.repository} "
        f"profile_sha256={profile_digest}",
        flush=True,
    )
    environment = os.environ.copy()
    environment["CI"] = "true"
    for index, command in enumerate(commands, start=1):
        rendered = " ".join(command)
        print(f"::group::release gate {index}/{len(commands)}: {rendered}", flush=True)
        completed = subprocess.run(command, cwd=target, env=environment, check=False)
        print("::endgroup::", flush=True)
        if completed.returncode != 0:
            raise GateProfileError(
                f"release gate command {index} failed with status {completed.returncode}: {rendered}",
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, required=True)
    return parser


def main() -> int:
    try:
        run(build_parser().parse_args())
    except (GateProfileError, OSError) as exc:
        print(f"release gate error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
