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


PROFILE_SCHEMA = "mindburn.autonomous-release-gates/v2"
REPOSITORY_PATTERN = re.compile(r"^Mindburn-Labs/[A-Za-z0-9_.-]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


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


def validate_protected_path(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GateProfileError(f"{label} must be a bounded relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise GateProfileError(f"{label} must not contain empty or traversal components")
    return value


def load_profiles(path: Path) -> dict[str, dict[str, Any]]:
    document = parse_json_strict(path)
    if not isinstance(document, dict):
        raise GateProfileError("gate profile document must be an object")
    require_exact_keys(document, {"schema", "profiles"}, "gate profile document")
    if document["schema"] != PROFILE_SCHEMA:
        raise GateProfileError("unsupported gate profile schema")
    if not isinstance(document["profiles"], dict):
        raise GateProfileError("profiles must be an object")

    profiles: dict[str, dict[str, Any]] = {}
    for repository, profile in document["profiles"].items():
        if not isinstance(repository, str) or not REPOSITORY_PATTERN.fullmatch(repository):
            raise GateProfileError(f"invalid profile repository: {repository!r}")
        if not isinstance(profile, dict):
            raise GateProfileError(f"profile {repository} must be an object")
        require_exact_keys(
            profile,
            {"commands", "protected_files"},
            f"profile {repository}",
        )
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
        protected_files = profile["protected_files"]
        if (
            not isinstance(protected_files, dict)
            or not protected_files
            or len(protected_files) > 32
        ):
            raise GateProfileError(
                f"profile {repository} must protect 1-32 gate-definition files",
            )
        validated_protected_files: dict[str, str] = {}
        for protected_path, digest in protected_files.items():
            validated_path = validate_protected_path(
                protected_path,
                label=f"profile {repository} protected path",
            )
            if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
                raise GateProfileError(
                    f"profile {repository} protected digest for {validated_path!r} is invalid",
                )
            validated_protected_files[validated_path] = digest
        profiles[repository] = {
            "commands": validated_commands,
            "protected_files": validated_protected_files,
        }
    return profiles


def verify_protected_files(target: Path, protected_files: dict[str, str]) -> None:
    for relative_path, expected_digest in protected_files.items():
        candidate = target.joinpath(*relative_path.split("/"))
        if candidate.is_symlink() or not candidate.is_file():
            raise GateProfileError(
                f"protected gate-definition file is missing or not regular: {relative_path}",
            )
        actual_digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            raise GateProfileError(
                f"protected gate-definition file changed before its source-owned profile: "
                f"{relative_path}",
            )


def resolve_commands(
    repository: str,
    target: Path,
    profiles: dict[str, dict[str, Any]],
) -> tuple[str, list[list[str]]]:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise GateProfileError("repository must be a Mindburn-Labs owner/name pair")
    if repository not in profiles:
        raise GateProfileError(
            "repository has no immutable source-owned gate profile; Makefile fallback is forbidden",
        )
    profile = profiles[repository]
    verify_protected_files(target, profile["protected_files"])
    return "explicit", profile["commands"]


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
