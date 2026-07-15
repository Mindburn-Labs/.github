#!/usr/bin/env python3
"""Append exact signed authority evidence to the protected Git ledger."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from authority_ruleset_broker import API_VERSION, validate_ref


SCHEMA = "mindburn.authority-evidence-ledger/v1"
RECEIPT_SCHEMA = "mindburn.authority-evidence-ledger-append/v1"
REPOSITORY = "Mindburn-Labs/.github"
LEDGER_REF = "refs/heads/authority/evidence-v1"
LEDGER_ROOT = ".helm/evidence"
MAX_FILES = 512
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_API_BYTES = 96 * 1024 * 1024
MAX_NAMESPACE_ENTRIES = (MAX_FILES * 2) + 1
SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}\Z")
RECORD_PHASES = {
    "ordinary-merge": {"intent", "closure"},
    "authority-promotion": {"intent", "merged", "final"},
    "bootstrap": {"intent", "closure", "final"},
}
RECORD_TYPES = set(RECORD_PHASES)
ALL_PHASES = {phase for phases in RECORD_PHASES.values() for phase in phases}
MANIFEST_KEYS = {
    "schema",
    "repository",
    "ledger_ref",
    "namespace",
    "record_type",
    "phase",
    "workflow_sha",
    "run_id",
    "run_attempt",
    "ledger_parent_sha",
    "files",
}


@dataclass(frozen=True)
class APIResponse:
    body: Any
    etag: str | None


class GitHubLedgerClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise PermitInputError("GH_TOKEN is required")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> APIResponse:
        content = None
        if payload is not None:
            content = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if content is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.api_url + path,
            data=content,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # nosec B310
                body = response.read(MAX_API_BYTES + 1)
                etag = response.headers.get("ETag")
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            raise PermitInputError(
                f"GitHub {method} {path} failed with HTTP {exc.code}: {detail}"
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PermitInputError(f"GitHub {method} {path} failed: {exc}") from exc
        if len(body) > MAX_API_BYTES:
            raise PermitInputError(
                f"GitHub {method} {path} exceeded the response limit"
            )
        if not body:
            return APIResponse(None, etag)
        try:
            value = parse_json_strict(body.decode("utf-8"), label=f"GitHub {path}")
        except UnicodeDecodeError as exc:
            raise PermitInputError(f"GitHub {path} was not UTF-8") from exc
        return APIResponse(value, etag)


def require_object(response: APIResponse, *, label: str) -> dict[str, Any]:
    if not isinstance(response.body, dict):
        raise PermitInputError(f"{label} response must be an object")
    return response.body


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        manifest,
        required=MANIFEST_KEYS,
        label="evidence ledger manifest",
    )
    if (
        manifest["schema"] != SCHEMA
        or manifest["repository"] != REPOSITORY
        or manifest["ledger_ref"] != LEDGER_REF
        or manifest["record_type"] not in RECORD_TYPES
        or manifest["phase"] not in RECORD_PHASES[manifest["record_type"]]
    ):
        raise PermitInputError("evidence ledger manifest identity is invalid")
    validate_record_namespace(
        manifest["namespace"],
        record_type=manifest["record_type"],
        phase=manifest["phase"],
    )
    require_sha(manifest["workflow_sha"], label="manifest workflow SHA", length=40)
    require_sha(
        manifest["ledger_parent_sha"], label="manifest ledger parent SHA", length=40
    )
    for field in ("run_id", "run_attempt"):
        value = manifest[field]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PermitInputError(f"manifest {field} must be a positive integer")
    files = manifest["files"]
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise PermitInputError("manifest files must contain 1 to 512 entries")
    total = 0
    for path, metadata in files.items():
        validate_relative_path(path, label="manifest evidence path")
        if path == "ledger-manifest.json" or not isinstance(metadata, dict):
            raise PermitInputError("manifest evidence entry is invalid")
        require_exact_keys(
            metadata,
            required={"sha256", "size"},
            label=f"manifest evidence {path}",
        )
        require_sha(
            metadata["sha256"],
            label=f"manifest evidence {path} SHA-256",
            length=64,
        )
        size = metadata["size"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or size > MAX_FILE_BYTES
        ):
            raise PermitInputError(f"manifest evidence {path} size is invalid")
        total += size
    if total > MAX_TOTAL_BYTES:
        raise PermitInputError("manifest evidence exceeds the total size limit")
    return manifest


def validate_relative_path(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value:
        raise PermitInputError(f"{label} must be a bounded relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(
        part in {"", ".", ".."} or not SEGMENT.fullmatch(part) for part in path.parts
    ):
        raise PermitInputError(f"{label} is not an admissible relative path")
    return path.as_posix()


def collect_inputs(
    root: Path,
    *,
    includes: list[str],
    include_trees: list[str],
) -> dict[str, bytes]:
    root = root.resolve(strict=True)
    candidates: set[str] = set()
    for value in includes:
        candidates.add(validate_relative_path(value, label="included evidence path"))
    for value in include_trees:
        relative = validate_relative_path(value, label="included evidence tree")
        directory = root / relative
        if not directory.is_dir() or directory.is_symlink():
            raise PermitInputError(
                f"included evidence tree {relative} is not a directory"
            )
        for candidate in directory.rglob("*"):
            if candidate.is_symlink():
                raise PermitInputError("evidence trees cannot contain symbolic links")
            if candidate.is_file():
                candidates.add(candidate.relative_to(root).as_posix())
    if not candidates or len(candidates) > MAX_FILES:
        raise PermitInputError("evidence input must contain 1 to 512 files")
    result: dict[str, bytes] = {}
    total = 0
    for relative in sorted(candidates):
        relative = validate_relative_path(relative, label="evidence path")
        if relative == "ledger-manifest.json":
            raise PermitInputError("ledger-manifest.json is reserved")
        path = root / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(root)
        ):
            raise PermitInputError(f"evidence file {relative} escapes its input root")
        content = path.read_bytes()
        if not content or len(content) > MAX_FILE_BYTES:
            raise PermitInputError(f"evidence file {relative} has an invalid size")
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise PermitInputError("evidence input exceeds the total size limit")
        result[relative] = content
    return result


def validate_inputs(inputs: dict[str, bytes]) -> dict[str, bytes]:
    if not isinstance(inputs, dict) or not inputs or len(inputs) > MAX_FILES:
        raise PermitInputError("evidence input must contain 1 to 512 files")
    result: dict[str, bytes] = {}
    directories: set[str] = set()
    total = 0
    for path, content in sorted(inputs.items()):
        path = validate_relative_path(path, label="evidence path")
        if path == "ledger-manifest.json":
            raise PermitInputError("ledger-manifest.json is reserved")
        parts = PurePosixPath(path).parts
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        if (
            not isinstance(content, bytes)
            or not content
            or len(content) > MAX_FILE_BYTES
        ):
            raise PermitInputError(f"evidence file {path} has an invalid size")
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise PermitInputError("evidence input exceeds the total size limit")
        result[path] = content
    if len(directories) + len(result) + 1 > MAX_NAMESPACE_ENTRIES:
        raise PermitInputError("evidence path tree exceeds the namespace read bound")
    return result


def decode_blob(value: dict[str, Any], *, label: str) -> bytes:
    if value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise PermitInputError(f"{label} is not a base64 Git blob")
    try:
        return base64.b64decode(value["content"], validate=True)
    except ValueError as exc:
        raise PermitInputError(f"{label} has invalid base64") from exc


def namespace_entries(
    client: GitHubLedgerClient,
    *,
    prefix: str,
    commit_sha: str,
) -> dict[str, dict[str, Any]] | None:
    """Read one bounded evidence namespace without enumerating the whole ledger."""

    if not prefix.startswith(LEDGER_ROOT + "/"):
        raise PermitInputError("ledger namespace prefix is outside the ledger root")
    validate_relative_path(
        prefix.removeprefix(LEDGER_ROOT + "/"),
        label="ledger namespace prefix",
    )
    commit_sha = require_sha(commit_sha, label="ledger commit SHA", length=40)
    pending = [prefix]
    result: dict[str, dict[str, Any]] = {}
    observed_entries = 0
    while pending:
        directory = pending.pop()
        encoded = urllib.parse.quote(directory, safe="/")
        query = urllib.parse.urlencode({"ref": commit_sha})
        try:
            response = client.request(
                "GET",
                f"/repos/{REPOSITORY}/contents/{encoded}?{query}",
            ).body
        except PermitInputError as exc:
            if directory == prefix and "failed with HTTP 404:" in str(exc):
                return None
            raise
        if not isinstance(response, list):
            raise PermitInputError("existing ledger namespace is not a directory")
        for entry in response:
            observed_entries += 1
            if observed_entries > MAX_NAMESPACE_ENTRIES:
                raise PermitInputError("existing ledger namespace exceeds its bound")
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("path"), str)
                or not isinstance(entry.get("type"), str)
                or not isinstance(entry.get("sha"), str)
            ):
                raise PermitInputError("ledger namespace entry is malformed")
            entry_path = entry["path"]
            if not entry_path.startswith(directory + "/"):
                raise PermitInputError("ledger namespace entry escaped its directory")
            relative = entry_path.removeprefix(prefix + "/")
            relative = validate_relative_path(relative, label="ledger namespace entry")
            if entry["type"] == "dir":
                pending.append(entry_path)
            elif entry["type"] == "file":
                if relative in result:
                    raise PermitInputError("ledger namespace contains a duplicate file")
                result[relative] = {
                    **entry,
                    "sha": require_sha(
                        entry["sha"],
                        label=f"ledger namespace file {relative} SHA",
                        length=40,
                    ),
                }
            else:
                raise PermitInputError("ledger namespace contains a non-file object")
    return result


def manifest_for(
    *,
    namespace: str,
    record_type: str,
    phase: str,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    parent_sha: str,
    inputs: dict[str, bytes],
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "repository": REPOSITORY,
        "ledger_ref": LEDGER_REF,
        "namespace": namespace,
        "record_type": record_type,
        "phase": phase,
        "workflow_sha": workflow_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "ledger_parent_sha": parent_sha,
        "files": {
            path: {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
            for path, content in inputs.items()
        },
    }


def validate_record_namespace(
    namespace: str,
    *,
    record_type: str,
    phase: str,
) -> None:
    parts = namespace.split("/")
    if any(part in ALL_PHASES for part in parts[:-1]):
        raise PermitInputError("ledger namespace cannot nest beneath a phase leaf")
    if record_type == "bootstrap":
        valid = (
            len(parts) == 4
            and parts[0] == "bootstrap"
            and re.fullmatch(r"pr-[1-9][0-9]*", parts[1]) is not None
        )
        sha_index = 2
    elif record_type == "ordinary-merge":
        valid = (
            len(parts) == 5
            and parts[0] == "ordinary"
            and parts[1] in {"github-authority", "helm-ai-kernel"}
            and re.fullmatch(r"pr-[1-9][0-9]*", parts[2]) is not None
        )
        sha_index = 3
    else:
        valid = (
            len(parts) == 4
            and parts[0] == "promotions"
            and re.fullmatch(r"generation-[1-9][0-9]*", parts[1]) is not None
        )
        sha_index = 2
    if not valid or parts[-1] != phase:
        raise PermitInputError("ledger namespace does not match its record grammar")
    require_sha(parts[sha_index], label="ledger namespace merge SHA", length=40)


def load_manifest_blob(
    client: GitHubLedgerClient,
    entry: dict[str, Any],
) -> dict[str, Any]:
    manifest_blob = require_object(
        client.request(
            "GET",
            f"/repos/{REPOSITORY}/git/blobs/{entry.get('sha')}",
        ),
        label="existing ledger manifest",
    )
    try:
        manifest = parse_json_strict(
            decode_blob(manifest_blob, label="existing ledger manifest").decode(
                "utf-8"
            ),
            label="existing ledger manifest",
        )
    except UnicodeDecodeError as exc:
        raise PermitInputError("existing ledger manifest is not UTF-8") from exc
    if not isinstance(manifest, dict):
        raise PermitInputError("existing ledger manifest must be an object")
    return validate_manifest(manifest)


def descriptor_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    manifest = validate_manifest(manifest)
    return {
        "schema": RECEIPT_SCHEMA,
        "namespace": manifest["namespace"],
        "record_type": manifest["record_type"],
        "phase": manifest["phase"],
        "ledger_ref": manifest["ledger_ref"],
        "ledger_parent_sha": manifest["ledger_parent_sha"],
        "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
        "files": manifest["files"],
    }


def read_record(
    client: GitHubLedgerClient,
    *,
    namespace: str,
    record_type: str,
    phase: str,
) -> dict[str, Any] | None:
    namespace = validate_relative_path(namespace, label="ledger namespace")
    if record_type not in RECORD_TYPES or phase not in RECORD_PHASES[record_type]:
        raise PermitInputError("unsupported evidence ledger record identity")
    validate_record_namespace(namespace, record_type=record_type, phase=phase)
    ref_path = LEDGER_REF.removeprefix("refs/")
    ref = require_object(
        client.request("GET", f"/repos/{REPOSITORY}/git/ref/{ref_path}"),
        label="ledger ref",
    )
    if ref.get("ref") != LEDGER_REF or not isinstance(ref.get("object"), dict):
        raise PermitInputError("evidence ledger ref is malformed")
    head_sha = require_sha(
        ref["object"].get("sha"), label="evidence ledger head SHA", length=40
    )
    prefix = f"{LEDGER_ROOT}/{namespace}"
    entries = namespace_entries(client, prefix=prefix, commit_sha=head_sha)
    if entries is None:
        return None
    manifest_entry = entries.get("ledger-manifest.json")
    if manifest_entry is None:
        raise PermitInputError("existing ledger namespace lacks its manifest")
    manifest = load_manifest_blob(client, manifest_entry)
    if (
        manifest["namespace"] != namespace
        or manifest["record_type"] != record_type
        or manifest["phase"] != phase
    ):
        raise PermitInputError("existing ledger manifest names another record")
    if set(entries) != {*manifest["files"], "ledger-manifest.json"}:
        raise PermitInputError("existing ledger namespace has an unexpected file set")
    inputs: dict[str, bytes] = {}
    for path, metadata in manifest["files"].items():
        blob = require_object(
            client.request(
                "GET",
                f"/repos/{REPOSITORY}/git/blobs/{entries[path].get('sha')}",
            ),
            label=f"existing ledger file {path}",
        )
        content = decode_blob(blob, label=f"existing ledger file {path}")
        if (
            len(content) != metadata["size"]
            or hashlib.sha256(content).hexdigest() != metadata["sha256"]
        ):
            raise PermitInputError(f"existing ledger file {path} differs from manifest")
        inputs[path] = content
    parent_sha = manifest["ledger_parent_sha"]
    comparison = require_object(
        client.request(
            "GET",
            f"/repos/{REPOSITORY}/compare/{parent_sha}...{head_sha}",
        ),
        label="ledger record ancestry",
    )
    if (
        comparison.get("status") != "ahead"
        or comparison.get("behind_by") != 0
        or not isinstance(comparison.get("merge_base_commit"), dict)
        or comparison["merge_base_commit"].get("sha") != parent_sha
    ):
        raise PermitInputError("ledger record parent is not an ancestor of its head")
    return {
        "manifest": manifest,
        "descriptor": descriptor_from_manifest(manifest),
        "inputs": inputs,
        "ledger_head_sha": head_sha,
    }


def verify_existing(
    client: GitHubLedgerClient,
    *,
    entries: dict[str, dict[str, Any]],
    expected: dict[str, Any],
    inputs: dict[str, bytes],
    ledger_head_sha: str,
) -> dict[str, Any] | None:
    existing = entries
    expected_names = {*inputs, "ledger-manifest.json"}
    if set(existing) != expected_names:
        raise PermitInputError("existing ledger namespace has an unexpected file set")
    manifest_entry = existing["ledger-manifest.json"]
    manifest_blob = require_object(
        client.request(
            "GET",
            f"/repos/{REPOSITORY}/git/blobs/{manifest_entry.get('sha')}",
        ),
        label="existing ledger manifest",
    )
    try:
        manifest = parse_json_strict(
            decode_blob(manifest_blob, label="existing ledger manifest").decode(
                "utf-8"
            ),
            label="existing ledger manifest",
        )
    except UnicodeDecodeError as exc:
        raise PermitInputError("existing ledger manifest is not UTF-8") from exc
    if not isinstance(manifest, dict):
        raise PermitInputError("existing ledger manifest must be an object")
    require_exact_keys(
        manifest,
        required={
            "schema",
            "repository",
            "ledger_ref",
            "namespace",
            "record_type",
            "phase",
            "workflow_sha",
            "run_id",
            "run_attempt",
            "ledger_parent_sha",
            "files",
        },
        label="existing ledger manifest",
    )
    comparable = {
        key: value for key, value in expected.items() if key != "ledger_parent_sha"
    }
    if {key: manifest.get(key) for key in comparable} != comparable:
        raise PermitInputError("existing ledger manifest does not match this record")
    for path, content in inputs.items():
        blob = require_object(
            client.request(
                "GET",
                f"/repos/{REPOSITORY}/git/blobs/{existing[path].get('sha')}",
            ),
            label=f"existing ledger file {path}",
        )
        if decode_blob(blob, label=f"existing ledger file {path}") != content:
            raise PermitInputError(f"existing ledger file {path} differs")
    return {
        "schema": RECEIPT_SCHEMA,
        "namespace": expected["namespace"],
        "record_type": expected["record_type"],
        "phase": expected["phase"],
        "ledger_ref": LEDGER_REF,
        "ledger_parent_sha": manifest["ledger_parent_sha"],
        "ledger_head_sha": ledger_head_sha,
        "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
        "files": expected["files"],
        "idempotent": True,
    }


def append_record(
    client: GitHubLedgerClient,
    *,
    namespace: str,
    record_type: str,
    phase: str,
    workflow_sha: str,
    run_id: int,
    run_attempt: int,
    inputs: dict[str, bytes],
    expected_parent_sha: str | None = None,
) -> dict[str, Any]:
    namespace = validate_relative_path(namespace, label="ledger namespace")
    inputs = validate_inputs(inputs)
    if record_type not in RECORD_TYPES:
        raise PermitInputError("record_type is not supported")
    if phase not in RECORD_PHASES[record_type]:
        raise PermitInputError("phase is not supported for this record type")
    validate_record_namespace(namespace, record_type=record_type, phase=phase)
    workflow_sha = require_sha(workflow_sha, label="workflow_sha", length=40)
    if expected_parent_sha is not None:
        expected_parent_sha = require_sha(
            expected_parent_sha,
            label="expected ledger parent SHA",
            length=40,
        )
    for value, label in ((run_id, "run_id"), (run_attempt, "run_attempt")):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PermitInputError(f"{label} must be a positive integer")
    validate_ref(LEDGER_REF, label="ledger ref")
    ref_path = LEDGER_REF.removeprefix("refs/")
    ref = require_object(
        client.request("GET", f"/repos/{REPOSITORY}/git/ref/{ref_path}"),
        label="ledger ref",
    )
    parent_sha = require_sha(
        ref.get("object", {}).get("sha")
        if isinstance(ref.get("object"), dict)
        else None,
        label="ledger parent SHA",
        length=40,
    )
    parent = require_object(
        client.request("GET", f"/repos/{REPOSITORY}/git/commits/{parent_sha}"),
        label="ledger parent commit",
    )
    parent_tree_sha = require_sha(
        parent.get("tree", {}).get("sha")
        if isinstance(parent.get("tree"), dict)
        else None,
        label="ledger parent tree SHA",
        length=40,
    )
    manifest = manifest_for(
        namespace=namespace,
        record_type=record_type,
        phase=phase,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        parent_sha=parent_sha,
        inputs=inputs,
    )
    prefix = f"{LEDGER_ROOT}/{namespace}"
    entries = namespace_entries(
        client,
        prefix=prefix,
        commit_sha=parent_sha,
    )
    if entries is not None:
        return verify_existing(
            client,
            entries=entries,
            expected=manifest,
            inputs=inputs,
            ledger_head_sha=parent_sha,
        )
    if expected_parent_sha is not None and parent_sha != expected_parent_sha:
        raise PermitInputError("evidence ledger moved after the signed plan")

    blobs: dict[str, str] = {}
    all_files = {**inputs, "ledger-manifest.json": canonical_json(manifest)}
    for path, content in all_files.items():
        created = require_object(
            client.request(
                "POST",
                f"/repos/{REPOSITORY}/git/blobs",
                payload={
                    "content": base64.b64encode(content).decode("ascii"),
                    "encoding": "base64",
                },
            ),
            label=f"created ledger blob {path}",
        )
        blobs[path] = require_sha(
            created.get("sha"), label=f"ledger blob {path} SHA", length=40
        )
    created_tree = require_object(
        client.request(
            "POST",
            f"/repos/{REPOSITORY}/git/trees",
            payload={
                "base_tree": parent_tree_sha,
                "tree": [
                    {
                        "path": f"{prefix}/{path}",
                        "mode": "100644",
                        "type": "blob",
                        "sha": sha,
                    }
                    for path, sha in sorted(blobs.items())
                ],
            },
        ),
        label="created ledger tree",
    )
    tree_sha = require_sha(
        created_tree.get("sha"), label="created ledger tree SHA", length=40
    )
    commit = require_object(
        client.request(
            "POST",
            f"/repos/{REPOSITORY}/git/commits",
            payload={
                "message": f"HELM evidence: {namespace}",
                "tree": tree_sha,
                "parents": [parent_sha],
            },
        ),
        label="created ledger commit",
    )
    commit_sha = require_sha(
        commit.get("sha"), label="created ledger commit SHA", length=40
    )
    updated = require_object(
        client.request(
            "PATCH",
            f"/repos/{REPOSITORY}/git/refs/{ref_path}",
            payload={"sha": commit_sha, "force": False},
        ),
        label="updated ledger ref",
    )
    if (
        updated.get("ref") != LEDGER_REF
        or not isinstance(updated.get("object"), dict)
        or updated["object"].get("sha") != commit_sha
    ):
        raise PermitInputError("GitHub did not atomically advance the ledger ref")
    confirmed = require_object(
        client.request("GET", f"/repos/{REPOSITORY}/git/ref/{ref_path}"),
        label="confirmed ledger ref",
    )
    if (
        confirmed.get("ref") != LEDGER_REF
        or not isinstance(confirmed.get("object"), dict)
        or confirmed["object"].get("sha") != commit_sha
    ):
        raise PermitInputError("ledger ref drifted after append")
    return {
        "schema": RECEIPT_SCHEMA,
        "namespace": namespace,
        "record_type": record_type,
        "phase": phase,
        "ledger_ref": LEDGER_REF,
        "ledger_parent_sha": parent_sha,
        "ledger_head_sha": commit_sha,
        "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
        "files": manifest["files"],
        "idempotent": False,
    }


def stable_record_descriptor(receipt: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        receipt,
        required={
            "schema",
            "namespace",
            "record_type",
            "phase",
            "ledger_ref",
            "ledger_parent_sha",
            "ledger_head_sha",
            "manifest_sha256",
            "files",
            "idempotent",
        },
        label="evidence ledger append receipt",
    )
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["ledger_ref"] != LEDGER_REF
        or not isinstance(receipt["idempotent"], bool)
        or not isinstance(receipt["files"], dict)
    ):
        raise PermitInputError("evidence ledger append receipt is malformed")
    for field in ("ledger_parent_sha", "ledger_head_sha", "manifest_sha256"):
        require_sha(
            receipt[field],
            label=f"evidence ledger append receipt {field}",
            length=64 if field == "manifest_sha256" else 40,
        )
    validate_record_namespace(
        receipt["namespace"],
        record_type=receipt["record_type"],
        phase=receipt["phase"],
    )
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"ledger_head_sha", "idempotent"}
    }


def materialize_record(record: dict[str, Any], output_dir: Path) -> None:
    if output_dir.exists() or output_dir.is_symlink():
        raise PermitInputError("ledger materialization output already exists")
    output_dir.mkdir(parents=True)
    inputs = record.get("inputs")
    if not isinstance(inputs, dict) or not inputs:
        raise PermitInputError("ledger record has no materializable inputs")
    for relative, content in inputs.items():
        relative = validate_relative_path(relative, label="materialized evidence path")
        target = output_dir.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise PermitInputError("ledger materialization contains a duplicate path")
        target.write_bytes(content)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    append_parser = subparsers.add_parser("append")
    append_parser.add_argument("--namespace", required=True)
    append_parser.add_argument(
        "--record-type", required=True, choices=sorted(RECORD_TYPES)
    )
    append_parser.add_argument("--phase", required=True)
    append_parser.add_argument("--workflow-sha", required=True)
    append_parser.add_argument("--run-id", required=True, type=int)
    append_parser.add_argument("--run-attempt", required=True, type=int)
    append_parser.add_argument("--expected-parent-sha", required=True)
    append_parser.add_argument("--input-root", required=True, type=Path)
    append_parser.add_argument("--include", action="append", default=[])
    append_parser.add_argument("--include-tree", action="append", default=[])
    append_parser.add_argument("--output", required=True, type=Path)
    descriptor_parser = subparsers.add_parser("descriptor")
    descriptor_parser.add_argument("--receipt", required=True, type=Path)
    descriptor_parser.add_argument("--output", required=True, type=Path)
    read_parser = subparsers.add_parser("read")
    read_parser.add_argument("--namespace", required=True)
    read_parser.add_argument(
        "--record-type", required=True, choices=sorted(RECORD_TYPES)
    )
    read_parser.add_argument("--phase", required=True)
    read_parser.add_argument("--output-dir", required=True, type=Path)
    read_parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command == "append":
            inputs = collect_inputs(
                args.input_root,
                includes=args.include,
                include_trees=args.include_tree,
            )
            value = append_record(
                GitHubLedgerClient(
                    os.environ.get("GH_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
                namespace=args.namespace,
                record_type=args.record_type,
                phase=args.phase,
                workflow_sha=args.workflow_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                inputs=inputs,
                expected_parent_sha=args.expected_parent_sha,
            )
        elif args.command == "descriptor":
            value = stable_record_descriptor(
                parse_json_strict(
                    args.receipt.read_text(encoding="utf-8"),
                    label="evidence ledger append receipt",
                )
            )
        else:
            record = read_record(
                GitHubLedgerClient(
                    os.environ.get("GH_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
                namespace=args.namespace,
                record_type=args.record_type,
                phase=args.phase,
            )
            if record is None:
                raise PermitInputError("evidence ledger record is absent")
            materialize_record(record, args.output_dir)
            value = {
                **record["descriptor"],
                "ledger_head_sha": record["ledger_head_sha"],
                "idempotent": True,
            }
        encoded = canonical_json(value)
        args.output.write_bytes(encoded)
        sys.stdout.buffer.write(encoded)
    except (OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"authority-evidence-ledger: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
