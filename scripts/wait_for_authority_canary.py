#!/usr/bin/env python3
"""Wait for an attested ALLOW permit from the exact candidate authority canary."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from autonomous_release_permit import PermitInputError, parse_json_strict, require_sha
from verify_authority_promotion import validate_permit, verify_permit_with_kernel


API_VERSION = "2026-03-10"
MAX_API_BYTES = 4 << 20
MAX_PERMIT_BYTES = 2 << 20
MAX_BUNDLE_BYTES = 4 << 20
MAX_CONTEXT_BYTES = 2 << 20
MAX_PROMPT_BYTES = 2 << 20
WORKFLOW_NAME = "HELM Autonomous Release Permit"
WORKFLOW_PATH = ".github/workflows/ci.yml"
SIGNER_WORKFLOW = "Mindburn-Labs/.github/.github/workflows/ci.yml"


class GitHubReadClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise PermitInputError("GH_TOKEN is required")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def get_bytes(self, path: str, *, accept: str = "application/vnd.github+json") -> bytes:
        request = urllib.request.Request(
            self.api_url + path,
            headers={
                "Accept": accept,
                "Authorization": " ".join(("Bearer", self.token)),
                "X-GitHub-Api-Version": API_VERSION,
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
                content = response.read(MAX_API_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            raise PermitInputError(f"GitHub GET {path} failed with HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PermitInputError(f"GitHub GET {path} failed: {exc}") from exc
        if len(content) > MAX_API_BYTES:
            raise PermitInputError(f"GitHub GET {path} exceeded the response limit")
        return content

    def get_json(self, path: str) -> dict[str, Any]:
        try:
            value = json.loads(self.get_bytes(path).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermitInputError(f"GitHub GET {path} returned invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise PermitInputError(f"GitHub GET {path} returned a non-object")
        return value


def parse_time(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise PermitInputError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise PermitInputError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def extract_attested_permit(archive: bytes) -> tuple[bytes, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            expected = {
                "release-permit.json": MAX_PERMIT_BYTES,
                "release-permit.attestation.json": MAX_BUNDLE_BYTES,
            }
            if len(entries) != len(expected) or {entry.filename for entry in entries} != set(expected):
                raise PermitInputError(
                    "canary artifact must contain exactly the permit and attestation bundle",
                )
            by_name = {entry.filename: entry for entry in entries}
            if any(
                entry.is_dir() or entry.file_size <= 0 or entry.file_size > expected[name]
                for name, entry in by_name.items()
            ):
                raise PermitInputError("canary permit exceeds the size limit")
            permit = bundle.read(by_name["release-permit.json"])
            attestation = bundle.read(by_name["release-permit.attestation.json"])
    except zipfile.BadZipFile as exc:
        raise PermitInputError("canary artifact is not a valid ZIP archive") from exc
    if not permit or len(permit) > MAX_PERMIT_BYTES:
        raise PermitInputError("canary permit exceeds the size limit")
    if not attestation or len(attestation) > MAX_BUNDLE_BYTES:
        raise PermitInputError("canary attestation bundle exceeds the size limit")
    return permit, attestation


def extract_trusted_context(archive: bytes) -> bytes:
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            expected = {
                "context.json": MAX_CONTEXT_BYTES,
                "review-prompt.txt": MAX_PROMPT_BYTES,
            }
            if len(entries) != len(expected) or {entry.filename for entry in entries} != set(expected):
                raise PermitInputError(
                    "permit-input artifact must contain exactly the context and review prompt",
                )
            by_name = {entry.filename: entry for entry in entries}
            if any(
                entry.is_dir() or entry.file_size <= 0 or entry.file_size > expected[name]
                for name, entry in by_name.items()
            ):
                raise PermitInputError("permit-input artifact exceeds the size limit")
            context = bundle.read(by_name["context.json"])
    except zipfile.BadZipFile as exc:
        raise PermitInputError("permit-input artifact is not a valid ZIP archive") from exc
    if not context or len(context) > MAX_CONTEXT_BYTES:
        raise PermitInputError("permit context exceeds the size limit")
    return context


def load_json_file(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def verify_attestation(
    permit_path: Path,
    bundle_path: Path,
    *,
    repository: str,
    workflow_sha: str,
    source_sha: str,
) -> None:
    process = subprocess.run(
        [
            "gh",
            "attestation",
            "verify",
            str(permit_path),
            "--bundle",
            str(bundle_path),
            "--repo",
            repository,
            "--signer-workflow",
            SIGNER_WORKFLOW,
            "--signer-digest",
            workflow_sha,
            "--source-digest",
            source_sha,
            "--deny-self-hosted-runners",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.copy(),
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(f"GitHub rejected canary permit provenance: {detail}")


def verify_candidate_permit(
    permit_path: Path,
    bundle_path: Path,
    trusted_context_path: Path,
    *,
    run: dict[str, Any],
    repository: str,
    pull_request: int,
    head_sha: str,
    expected_workflow_sha: str,
    expected_authority: dict[str, Any],
    kernel_verifier: Path,
) -> dict[str, Any]:
    permit = load_json_file(permit_path, label="canary permit")
    authority = validate_permit(permit)
    expected = {
        "repository": repository,
        "pull_request": pull_request,
        "head_sha": head_sha,
        "workflow_sha": expected_workflow_sha,
        "run_id": run.get("id"),
        "run_attempt": run.get("run_attempt"),
    }
    for field, value in expected.items():
        if permit.get(field) != value:
            raise PermitInputError(f"canary permit {field} does not match the candidate run")
    if authority != expected_authority:
        raise PermitInputError("canary permit authority does not match the candidate manifest")
    verify_attestation(
        permit_path,
        bundle_path,
        repository=repository,
        workflow_sha=expected_workflow_sha,
        source_sha=permit["merge_sha"],
    )
    verify_permit_with_kernel(kernel_verifier, permit_path, trusted_context_path)
    return permit


def artifact_for_run(
    client: GitHubReadClient,
    repository: str,
    run_id: int,
    artifact_name: str = "helm-autonomous-release-permit",
) -> int | None:
    artifacts = client.get_json(f"/repos/{repository}/actions/runs/{run_id}/artifacts")
    values = artifacts.get("artifacts")
    if not isinstance(values, list):
        raise PermitInputError("GitHub artifacts response is malformed")
    matches = [
        artifact
        for artifact in values
        if isinstance(artifact, dict)
        and artifact.get("name") == artifact_name
        and artifact.get("expired") is False
    ]
    if not matches:
        return None
    if len(matches) != 1 or not isinstance(matches[0].get("id"), int):
        raise PermitInputError("candidate run has an ambiguous permit artifact")
    return matches[0]["id"]


def wait_for_canary(args: argparse.Namespace, client: GitHubReadClient) -> dict[str, Any]:
    workflow_sha = require_sha(args.expected_workflow_sha, label="expected_workflow_sha", length=40)
    head_sha = require_sha(args.head_sha, label="head_sha", length=40)
    started_at = parse_time(args.started_at, label="started_at")
    authority = load_json_file(args.expected_authority, label="expected authority")
    deadline = time.monotonic() + args.timeout_seconds
    rejected_runs: set[int] = set()
    while time.monotonic() < deadline:
        query = urllib.parse.urlencode(
            {"event": "pull_request", "head_sha": head_sha, "per_page": 100},
        )
        payload = client.get_json(f"/repos/{args.repository}/actions/runs?{query}")
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise PermitInputError("GitHub Actions runs response is malformed")
        for run in runs:
            if not isinstance(run, dict) or not isinstance(run.get("id"), int):
                continue
            run_id = run["id"]
            if run_id in rejected_runs:
                continue
            if (
                run.get("name") != WORKFLOW_NAME
                or run.get("path") != WORKFLOW_PATH
                or run.get("head_sha") != head_sha
                or parse_time(run.get("created_at"), label="run created_at") < started_at
                or run.get("status") != "completed"
                or run.get("conclusion") != "success"
            ):
                continue
            artifact_id = artifact_for_run(client, args.repository, run_id)
            context_artifact_id = artifact_for_run(
                client,
                args.repository,
                run_id,
                "release-permit-input",
            )
            if artifact_id is None or context_artifact_id is None:
                rejected_runs.add(run_id)
                continue
            archive = client.get_bytes(
                f"/repos/{args.repository}/actions/artifacts/{artifact_id}/zip",
                accept="application/vnd.github+json",
            )
            permit_bytes, bundle_bytes = extract_attested_permit(archive)
            context_archive = client.get_bytes(
                f"/repos/{args.repository}/actions/artifacts/{context_artifact_id}/zip",
                accept="application/vnd.github+json",
            )
            context_bytes = extract_trusted_context(context_archive)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.bundle.parent.mkdir(parents=True, exist_ok=True)
            args.context.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(permit_bytes)
            args.bundle.write_bytes(bundle_bytes)
            args.context.write_bytes(context_bytes)
            try:
                permit = verify_candidate_permit(
                    args.output,
                    args.bundle,
                    args.context,
                    run=run,
                    repository=args.repository,
                    pull_request=args.pull_request,
                    head_sha=head_sha,
                    expected_workflow_sha=workflow_sha,
                    expected_authority=authority,
                    kernel_verifier=args.kernel_verifier,
                )
            except PermitInputError:
                args.output.unlink(missing_ok=True)
                args.bundle.unlink(missing_ok=True)
                args.context.unlink(missing_ok=True)
                rejected_runs.add(run_id)
                continue
            return {
                "schema": "mindburn.release-authority-canary/v1",
                "repository": args.repository,
                "pull_request": args.pull_request,
                "head_sha": head_sha,
                "workflow_sha": workflow_sha,
                "run_id": run_id,
                "run_attempt": run["run_attempt"],
                "permit_id": permit["permit_id"],
                "merge_sha": permit["merge_sha"],
                "merge_tree_sha": permit["merge_tree_sha"],
            }
        time.sleep(args.poll_seconds)
    raise PermitInputError("timed out waiting for an attested candidate-authority ALLOW canary")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--expected-workflow-sha", required=True)
    parser.add_argument("--expected-authority", type=Path, required=True)
    parser.add_argument("--kernel-verifier", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--poll-seconds", type=int, default=15)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.pull_request <= 0:
            raise PermitInputError("pull_request must be positive")
        output_paths = {
            args.output.resolve(),
            args.bundle.resolve(),
            args.context.resolve(),
        }
        if len(output_paths) != 3:
            raise PermitInputError("permit, attestation bundle, and context outputs must differ")
        if not 60 <= args.timeout_seconds <= 1800:
            raise PermitInputError("timeout_seconds must be between 60 and 1800")
        if not 5 <= args.poll_seconds <= 60:
            raise PermitInputError("poll_seconds must be between 5 and 60")
        client = GitHubReadClient(
            os.environ.get("GH_TOKEN", ""),
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        receipt = wait_for_canary(args, client)
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.receipt.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError) as exc:
        print(f"wait-for-authority-canary: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
