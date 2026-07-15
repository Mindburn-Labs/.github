#!/usr/bin/env python3
"""Wait for an attested ALLOW permit from the exact candidate authority canary."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    rebuild_review_evidence,
    require_sha,
)
from verify_authority_promotion import validate_permit, verify_permit_with_kernel


API_VERSION = "2026-03-10"
MAX_API_BYTES = 4 << 20
MAX_PERMIT_BYTES = 2 << 20
MAX_BUNDLE_BYTES = 4 << 20
MAX_CONTEXT_BYTES = 2 << 20
MAX_PROMPT_BYTES = 2 << 20
MAX_PATCH_BYTES = 4 << 20
MAX_REVIEW_BYTES = 2 << 20
MAX_REVIEW_TRANSPORT_BYTES = 16 << 20
MODEL_REVIEW_PROVIDERS = ("anthropic", "openai")
MODEL_REVIEW_MODELS = {
    "anthropic": "claude-fable-5",
    "openai": "gpt-5.6-sol",
}
WORKFLOW_NAME = "HELM Autonomous Release Permit"
WORKFLOW_PATH = ".github/workflows/ci.yml"
SIGNER_WORKFLOW = "Mindburn-Labs/.github/.github/workflows/ci.yml"
PROVENANCE_ARTIFACT = "release-workflow-provenance"
PROVENANCE_SCHEMA = "mindburn.release-workflow-provenance/v1"
MAX_PROVENANCE_BYTES = 64 << 10
MAX_PROVENANCE_BUNDLE_BYTES = 4 << 20


def sanitized_subprocess_environment(
    *, github_token: str | None = None
) -> dict[str, str]:
    """Return the minimum ambient environment needed by trusted local tools."""
    environment = {
        key: value
        for key in (
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "PATH",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "TMPDIR",
            "XDG_CONFIG_HOME",
        )
        if (value := os.environ.get(key))
    }
    environment.setdefault("PATH", os.defpath)
    if github_token is not None:
        if not github_token:
            raise PermitInputError(
                "attestation verification requires an explicit token"
            )
        environment["GH_TOKEN"] = github_token
    return environment


def _url_origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        raise PermitInputError("GitHub redirect target has no absolute origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise PermitInputError("GitHub redirect target has an invalid port") from exc
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return scheme, host, port


class StripCrossOriginAuthorizationRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward GitHub credentials to an artifact storage origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source_origin = _url_origin(req.full_url)
        target_origin = _url_origin(newurl)
        if target_origin[0] not in {"http", "https"}:
            raise PermitInputError("GitHub redirect target must use HTTP(S)")
        if source_origin[0] == "https" and target_origin[0] != "https":
            raise PermitInputError("GitHub redirect target cannot downgrade HTTPS")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and source_origin != target_origin:
            redirected.remove_header("Authorization")
        return redirected


class GitHubReadClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise PermitInputError("GH_TOKEN is required")
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.opener = urllib.request.build_opener(
            StripCrossOriginAuthorizationRedirectHandler()
        )

    def get_bytes(
        self, path: str, *, accept: str = "application/vnd.github+json"
    ) -> bytes:
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
            with self.opener.open(request, timeout=30) as response:  # nosec B310
                content = response.read(MAX_API_BYTES + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            raise PermitInputError(
                f"GitHub GET {path} failed with HTTP {exc.code}: {detail}"
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PermitInputError(f"GitHub GET {path} failed: {exc}") from exc
        if len(content) > MAX_API_BYTES:
            raise PermitInputError(f"GitHub GET {path} exceeded the response limit")
        return content

    def get_json(self, path: str) -> dict[str, Any]:
        try:
            value = json.loads(self.get_bytes(path).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermitInputError(
                f"GitHub GET {path} returned invalid JSON: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise PermitInputError(f"GitHub GET {path} returned a non-object")
        return value


def require_get_forbidden(
    client: GitHubReadClient,
    path: str,
    *,
    label: str,
) -> None:
    """Prove a token cannot use a safe GET endpoint that requires write scope."""
    request = urllib.request.Request(
        client.api_url + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": " ".join(("Bearer", client.token)),
            "X-GitHub-Api-Version": API_VERSION,
        },
        method="GET",
    )
    try:
        with client.opener.open(request, timeout=30) as response:  # nosec B310
            response.read(1)
    except urllib.error.HTTPError as exc:
        exc.read(4096)
        if exc.code == 403:
            return
        raise PermitInputError(
            f"{label} denial returned unexpected HTTP {exc.code}"
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise PermitInputError(f"{label} denial could not be verified: {exc}") from exc
    raise PermitInputError(f"{label} token retains forbidden write authority")


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
            if len(entries) != len(expected) or {
                entry.filename for entry in entries
            } != set(expected):
                raise PermitInputError(
                    "canary artifact must contain exactly the permit and attestation bundle",
                )
            by_name = {entry.filename: entry for entry in entries}
            if any(
                entry.is_dir()
                or entry.file_size <= 0
                or entry.file_size > expected[name]
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
                "patch.diff": MAX_PATCH_BYTES,
            }
            if len(entries) != len(expected) or {
                entry.filename for entry in entries
            } != set(expected):
                raise PermitInputError(
                    "permit-input artifact must contain exactly the context, prompt, and patch",
                )
            by_name = {entry.filename: entry for entry in entries}
            if any(
                entry.is_dir()
                or entry.file_size <= 0
                or entry.file_size > expected[name]
                for name, entry in by_name.items()
            ):
                raise PermitInputError("permit-input artifact exceeds the size limit")
            context = bundle.read(by_name["context.json"])
    except zipfile.BadZipFile as exc:
        raise PermitInputError(
            "permit-input artifact is not a valid ZIP archive"
        ) from exc
    if not context or len(context) > MAX_CONTEXT_BYTES:
        raise PermitInputError("permit context exceeds the size limit")
    return context


def extract_model_review(archive: bytes, provider: str) -> tuple[bytes, bytes, bytes]:
    if provider not in MODEL_REVIEW_PROVIDERS:
        raise PermitInputError(f"unsupported model review provider: {provider}")
    expected = {
        f"raw-{provider}.txt": MAX_REVIEW_TRANSPORT_BYTES,
        f"normalized-{provider}.json": MAX_REVIEW_BYTES,
        f"review-{provider}.json": MAX_REVIEW_BYTES,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            if len(entries) != len(expected) or {
                entry.filename for entry in entries
            } != set(expected):
                raise PermitInputError(
                    f"{provider} review artifact must contain exact raw, normalized, and envelope evidence",
                )
            by_name = {entry.filename: entry for entry in entries}
            if any(
                entry.is_dir()
                or entry.file_size <= 0
                or entry.file_size > expected[name]
                for name, entry in by_name.items()
            ):
                raise PermitInputError(
                    f"{provider} review artifact exceeds the size limit"
                )
            raw = bundle.read(by_name[f"raw-{provider}.txt"])
            normalized = bundle.read(by_name[f"normalized-{provider}.json"])
            review = bundle.read(by_name[f"review-{provider}.json"])
    except zipfile.BadZipFile as exc:
        raise PermitInputError(
            f"{provider} review artifact is not a valid ZIP archive"
        ) from exc
    return raw, normalized, review


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
    github_token: str,
) -> None:
    environment = sanitized_subprocess_environment(github_token=github_token)
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
        env=environment,
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
    attestation_token: str,
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
            raise PermitInputError(
                f"canary permit {field} does not match the candidate run"
            )
    if authority != expected_authority:
        raise PermitInputError(
            "canary permit authority does not match the candidate manifest"
        )
    verify_attestation(
        permit_path,
        bundle_path,
        repository=repository,
        workflow_sha=expected_workflow_sha,
        source_sha=permit["merge_sha"],
        github_token=attestation_token,
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


def extract_workflow_provenance(archive: bytes) -> tuple[bytes, bytes]:
    expected = {
        "release-workflow-provenance.json": MAX_PROVENANCE_BYTES,
        "release-workflow-provenance.attestation.json": MAX_PROVENANCE_BUNDLE_BYTES,
    }
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            entries = bundle.infolist()
            if len(entries) != len(expected) or {
                entry.filename for entry in entries
            } != set(expected):
                raise PermitInputError(
                    "workflow provenance artifact must contain exactly the marker and attestation",
                )
            by_name = {entry.filename: entry for entry in entries}
            if any(
                entry.is_dir()
                or entry.file_size <= 0
                or entry.file_size > expected[name]
                for name, entry in by_name.items()
            ):
                raise PermitInputError(
                    "workflow provenance artifact exceeds the size limit"
                )
            provenance = bundle.read(by_name["release-workflow-provenance.json"])
            attestation = bundle.read(
                by_name["release-workflow-provenance.attestation.json"],
            )
    except zipfile.BadZipFile as exc:
        raise PermitInputError(
            "workflow provenance artifact is not a valid ZIP archive",
        ) from exc
    return provenance, attestation


def verify_run_workflow_provenance(
    client: GitHubReadClient,
    repository: str,
    run: dict[str, Any],
    *,
    head_sha: str,
    expected_workflow_sha: str,
    directory: Path | None = None,
) -> dict[str, Any] | None:
    run_id = run.get("id")
    if not isinstance(run_id, int):
        raise PermitInputError("workflow provenance run ID is invalid")
    artifact_id = artifact_for_run(
        client,
        repository,
        run_id,
        PROVENANCE_ARTIFACT,
    )
    if artifact_id is None:
        return None
    provenance_bytes, bundle_bytes = extract_workflow_provenance(
        client.get_bytes(
            f"/repos/{repository}/actions/artifacts/{artifact_id}/zip",
            accept="application/vnd.github+json",
        ),
    )
    try:
        provenance = parse_json_strict(
            provenance_bytes.decode("utf-8"),
            label="workflow provenance",
        )
    except UnicodeDecodeError as exc:
        raise PermitInputError("workflow provenance is not UTF-8") from exc
    if not isinstance(provenance, dict):
        raise PermitInputError("workflow provenance must be an object")
    expected_keys = {
        "schema",
        "repository",
        "workflow_path",
        "workflow_sha",
        "head_sha",
        "merge_sha",
        "run_id",
        "run_attempt",
    }
    if set(provenance) != expected_keys:
        raise PermitInputError("workflow provenance keys are not exact")
    common = {
        "schema": PROVENANCE_SCHEMA,
        "repository": repository,
        "workflow_path": WORKFLOW_PATH,
        "head_sha": head_sha,
        "run_id": run_id,
        "run_attempt": run.get("run_attempt"),
    }
    for field, value in common.items():
        if provenance.get(field) != value:
            raise PermitInputError(
                f"workflow provenance {field} does not match the run"
            )
    workflow_sha = require_sha(
        provenance.get("workflow_sha"),
        label="workflow provenance workflow_sha",
        length=40,
    )
    merge_sha = require_sha(
        provenance.get("merge_sha"),
        label="workflow provenance merge_sha",
        length=40,
    )
    if directory is None:
        temporary = tempfile.TemporaryDirectory(prefix="helm-workflow-provenance-")
        output_dir = Path(temporary.name)
    else:
        temporary = None
        output_dir = directory
        output_dir.mkdir(parents=True, exist_ok=False)
    try:
        provenance_path = output_dir / "release-workflow-provenance.json"
        bundle_path = output_dir / "release-workflow-provenance.attestation.json"
        provenance_path.write_bytes(provenance_bytes)
        bundle_path.write_bytes(bundle_bytes)
        verify_attestation(
            provenance_path,
            bundle_path,
            repository=repository,
            workflow_sha=workflow_sha,
            source_sha=merge_sha,
            github_token=client.token,
        )
    finally:
        if temporary is not None:
            temporary.cleanup()
    return {
        "workflow_sha": workflow_sha,
        "is_expected_workflow": workflow_sha == expected_workflow_sha,
        "merge_sha": merge_sha,
        "workflow_provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
    }


def run_sort_key(run: dict[str, Any]) -> tuple[int, int, int]:
    """Sort repeated workflow runs newest-first without trusting list order."""
    run_number = run.get("run_number")
    run_attempt = run.get("run_attempt")
    run_id = run.get("id")
    return (
        run_number if isinstance(run_number, int) else 0,
        run_attempt if isinstance(run_attempt, int) else 0,
        run_id if isinstance(run_id, int) else 0,
    )


def write_model_reviews(
    client: GitHubReadClient,
    repository: str,
    run_id: int,
    directory: Path,
    *,
    context_path: Path,
) -> dict[str, Path]:
    evidence: dict[str, tuple[bytes, bytes, bytes]] = {}
    for provider in MODEL_REVIEW_PROVIDERS:
        artifact_id = artifact_for_run(
            client,
            repository,
            run_id,
            f"release-review-{provider}",
        )
        if artifact_id is None:
            raise PermitInputError(
                f"candidate run is missing the {provider} review artifact"
            )
        evidence[provider] = extract_model_review(
            client.get_bytes(
                f"/repos/{repository}/actions/artifacts/{artifact_id}/zip",
                accept="application/vnd.github+json",
            ),
            provider,
        )

    directory.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for provider in MODEL_REVIEW_PROVIDERS:
        raw, normalized, review = evidence[provider]
        raw_path = directory / f"raw-{provider}.txt"
        normalized_path = directory / f"normalized-{provider}.json"
        review_path = directory / f"review-{provider}.json"
        raw_path.write_bytes(raw)
        normalized_path.write_bytes(normalized)
        review_path.write_bytes(review)
        paths[provider] = rebuild_review_evidence(
            context=context_path,
            raw_transport=raw_path,
            normalized_response=normalized_path,
            review_envelope=review_path,
            provider=provider,
            model=MODEL_REVIEW_MODELS[provider],
            output_dir=directory / f"parent-rebuilt-{provider}",
        )
    return paths


def verify_permit_reduction(
    kernel_verifier: Path,
    permit_path: Path,
    context_path: Path,
    review_paths: dict[str, Path],
    output_path: Path,
) -> None:
    if set(review_paths) != set(MODEL_REVIEW_PROVIDERS):
        raise PermitInputError(
            "parent reduction requires the exact distinct-provider review artifacts"
        )
    command = [
        str(kernel_verifier.resolve()),
        "--context",
        str(context_path.resolve()),
    ]
    for provider in MODEL_REVIEW_PROVIDERS:
        command.extend(("--review", str(review_paths[provider].resolve())))
    command.extend(("--output", str(output_path.resolve())))
    process = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=sanitized_subprocess_environment(),
    )
    permit = load_json_file(permit_path, label="candidate reduced permit")
    expected_status = {"ALLOW": 0, "DENY": 3}.get(permit.get("decision"))
    if expected_status is None or process.returncode != expected_status:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise PermitInputError(
            "parent Kernel did not independently reproduce the candidate decision"
            + (f": {detail}" if detail else ""),
        )
    try:
        recomputed = output_path.read_bytes()
    except FileNotFoundError as exc:
        raise PermitInputError(
            "parent Kernel did not emit a recomputed permit"
        ) from exc
    if recomputed != permit_path.read_bytes():
        raise PermitInputError(
            "candidate permit differs from the parent Kernel reduction"
        )


def wait_for_canary(
    args: argparse.Namespace, client: GitHubReadClient
) -> dict[str, Any]:
    workflow_sha = require_sha(
        args.expected_workflow_sha, label="expected_workflow_sha", length=40
    )
    head_sha = require_sha(args.head_sha, label="head_sha", length=40)
    started_at = parse_time(args.started_at, label="started_at")
    authority = load_json_file(args.expected_authority, label="expected authority")
    deadline = time.monotonic() + args.timeout_seconds
    while time.monotonic() < deadline:
        query = urllib.parse.urlencode(
            {"event": "pull_request", "head_sha": head_sha, "per_page": 100},
        )
        payload = client.get_json(f"/repos/{args.repository}/actions/runs?{query}")
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise PermitInputError("GitHub Actions runs response is malformed")
        matching = [
            run
            for run in runs
            if isinstance(run, dict)
            and isinstance(run.get("id"), int)
            and run.get("name") == WORKFLOW_NAME
            and run.get("path") == WORKFLOW_PATH
            and run.get("head_sha") == head_sha
            and parse_time(run.get("created_at"), label="run created_at") >= started_at
        ]
        matching.sort(key=run_sort_key, reverse=True)
        exact_run = None
        unclassified_newer_run = False
        for run in matching:
            provenance = verify_run_workflow_provenance(
                client,
                args.repository,
                run,
                head_sha=head_sha,
                expected_workflow_sha=workflow_sha,
            )
            if provenance is None:
                unclassified_newer_run = True
                break
            if provenance["is_expected_workflow"]:
                exact_run = run
                break
        if unclassified_newer_run or exact_run is None:
            time.sleep(args.poll_seconds)
            continue

        run = exact_run
        run_id = run["id"]
        if run.get("status") != "completed":
            time.sleep(args.poll_seconds)
            continue
        if run.get("conclusion") != "success":
            raise PermitInputError(
                f"newest exact candidate workflow run {run_id} did not succeed"
            )
        artifact_id = artifact_for_run(client, args.repository, run_id)
        context_artifact_id = artifact_for_run(
            client,
            args.repository,
            run_id,
            "release-permit-input",
        )
        if artifact_id is None or context_artifact_id is None:
            raise PermitInputError(
                f"newest exact candidate workflow run {run_id} lacks permit evidence"
            )
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
        review_dir = args.context.parent / "reviews"
        try:
            review_paths = write_model_reviews(
                client,
                args.repository,
                run_id,
                review_dir,
                context_path=args.context,
            )
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
                attestation_token=client.token,
            )
            verify_permit_reduction(
                args.kernel_verifier,
                args.output,
                args.context,
                review_paths,
                review_dir / "parent-kernel-permit.json",
            )
        except (OSError, PermitInputError):
            args.output.unlink(missing_ok=True)
            args.bundle.unlink(missing_ok=True)
            args.context.unlink(missing_ok=True)
            if review_dir.exists():
                shutil.rmtree(review_dir)
            raise
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
    raise PermitInputError(
        "timed out waiting for an attested candidate-authority ALLOW canary"
    )


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
            raise PermitInputError(
                "permit, attestation bundle, and context outputs must differ"
            )
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
