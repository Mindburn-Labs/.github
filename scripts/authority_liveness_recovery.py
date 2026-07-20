#!/usr/bin/env python3
"""Validate the inert authority/recovery-v1 liveness-recovery contract.

This module is deliberately a pure verifier. It has no network client, no
credential input, and no code path that changes refs, rulesets, environments,
deployments, repository settings, Apps, or external systems. Its only merge
artifact is an exact, non-force REST CAS *intent* that a separately authorized
future broker may consume after independent live proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_NAME = "authority/recovery-v1"
WORKFLOW_PATH = ".github/workflows/ci.yml"
MAIN_REF = "refs/heads/main"
RESTORE_STATE = "ordinary-authority-restore-required"
RESTORE_RECEIPTS = [
    "normal-candidate-liveness",
    "two-provider-adversarial-suite",
]

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REF_RE = re.compile(r"^refs/heads/[A-Za-z0-9._/-]+$")
PROVIDER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
CONTROL_REF_RE = re.compile(r"(?:^|[-_/])control(?:[-_/]|$)")


class ValidationError(ValueError):
    """Raised when a recovery request does not satisfy the closed contract."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{path} must be an object")
    return value


def require_exact_keys(value: Mapping[str, Any], path: str, keys: Sequence[str]) -> None:
    actual = set(value)
    expected = set(keys)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if extra:
            details.append(f"extra={','.join(extra)}")
        raise ValidationError(f"{path} must have an exact field set ({'; '.join(details)})")


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{path} must be a non-empty string")
    return value


def require_integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValidationError(f"{path} must be a positive integer")
    return value


def require_sha(value: Any, path: str) -> str:
    text = require_string(value, path)
    if not SHA_RE.fullmatch(text):
        raise ValidationError(f"{path} must be a lowercase 40-character SHA")
    return text


def require_digest(value: Any, path: str) -> str:
    text = require_string(value, path)
    if not DIGEST_RE.fullmatch(text):
        raise ValidationError(f"{path} must be a lowercase SHA-256 digest")
    return text


def require_ref(value: Any, path: str) -> str:
    text = require_string(value, path)
    if not REF_RE.fullmatch(text):
        raise ValidationError(f"{path} must be a refs/heads ref")
    if CONTROL_REF_RE.search(text):
        raise ValidationError(f"{path} must not name a control ref")
    return text


def validate_schema_document(schema: Any) -> None:
    document = require_mapping(schema, "schema")
    if document.get("$id") != SCHEMA_NAME:
        raise ValidationError("schema.$id must equal authority/recovery-v1")
    properties = require_mapping(document.get("properties"), "schema.properties")
    schema_field = require_mapping(properties.get("schema"), "schema.properties.schema")
    if schema_field.get("const") != SCHEMA_NAME:
        raise ValidationError("schema.properties.schema.const must equal authority/recovery-v1")


def validate_scope(scope: Any) -> None:
    value = require_mapping(scope, "scope")
    require_exact_keys(
        value,
        "scope",
        [
            "app",
            "control_ref",
            "deployment",
            "environment",
            "external_effects",
            "repository_settings",
            "ruleset",
        ],
    )
    expected = {
        "app": False,
        "control_ref": None,
        "deployment": False,
        "environment": False,
        "external_effects": [],
        "repository_settings": False,
        "ruleset": False,
    }
    for key, required_value in expected.items():
        if value[key] != required_value:
            raise ValidationError(f"scope.{key} must remain {required_value!r} in source-only mode")


def validate_parent(parent: Any) -> Mapping[str, Any]:
    value = require_mapping(parent, "parent")
    require_exact_keys(value, "parent", ["workflow_path", "workflow_ref", "workflow_sha"])
    if value["workflow_path"] != WORKFLOW_PATH:
        raise ValidationError(f"parent.workflow_path must equal {WORKFLOW_PATH}")
    require_ref(value["workflow_ref"], "parent.workflow_ref")
    require_sha(value["workflow_sha"], "parent.workflow_sha")
    return value


def validate_candidate(candidate: Any) -> Mapping[str, Any]:
    value = require_mapping(candidate, "candidate")
    require_exact_keys(value, "candidate", ["changed_paths", "head_ref", "head_sha", "pull_number", "transport"])
    require_integer(value["pull_number"], "candidate.pull_number")
    require_ref(value["head_ref"], "candidate.head_ref")
    require_sha(value["head_sha"], "candidate.head_sha")
    if value["changed_paths"] != [WORKFLOW_PATH]:
        raise ValidationError(f"candidate.changed_paths must be exactly [{WORKFLOW_PATH!r}]")
    transport = require_mapping(value["transport"], "candidate.transport")
    require_exact_keys(transport, "candidate.transport", ["from", "to"])
    if transport != {"from": "prompt-as-argv", "to": "prompt-on-stdin"}:
        raise ValidationError("candidate.transport must be the exact argv-to-stdin remediation")
    return value


def validate_e2big_proof(proof: Any, repository: str, parent: Mapping[str, Any]) -> Mapping[str, Any]:
    value = require_mapping(proof, "e2big_proof")
    require_exact_keys(
        value,
        "e2big_proof",
        [
            "argv_sha256",
            "argv_shape",
            "error",
            "executor",
            "job_id",
            "log_sha256",
            "repository",
            "run_attempt",
            "run_id",
            "stderr_sha256",
            "workflow_path",
            "workflow_ref",
            "workflow_sha",
        ],
    )
    if value["repository"] != repository:
        raise ValidationError("e2big_proof.repository must bind the requested repository")
    for key in ("workflow_path", "workflow_ref", "workflow_sha"):
        if value[key] != parent[key]:
            raise ValidationError(f"e2big_proof.{key} must bind the exact parent workflow")
    if value["executor"] != "execve":
        raise ValidationError("e2big_proof.executor must equal execve")
    if value["argv_shape"] != "copilot -p <prompt-as-argv>":
        raise ValidationError("e2big_proof.argv_shape must prove the exact argv transport")
    if value["error"] != "E2BIG":
        raise ValidationError("e2big_proof.error must equal E2BIG; no fallback failure class is accepted")
    for key in ("run_id", "run_attempt", "job_id"):
        require_integer(value[key], f"e2big_proof.{key}")
    for key in ("argv_sha256", "stderr_sha256", "log_sha256"):
        require_digest(value[key], f"e2big_proof.{key}")
    return value


def validate_parent_semantic_replay(
    replay: Any, parent: Mapping[str, Any], candidate: Mapping[str, Any]
) -> Mapping[str, Any]:
    value = require_mapping(replay, "parent_semantic_replay")
    require_exact_keys(
        value,
        "parent_semantic_replay",
        ["candidate_workflow_sha", "parent_workflow_sha", "replay_input_sha256", "reviews", "semantic_claim"],
    )
    if value["parent_workflow_sha"] != parent["workflow_sha"]:
        raise ValidationError("parent_semantic_replay.parent_workflow_sha must bind the parent")
    if value["candidate_workflow_sha"] != candidate["head_sha"]:
        raise ValidationError("parent_semantic_replay.candidate_workflow_sha must bind the candidate")
    require_digest(value["replay_input_sha256"], "parent_semantic_replay.replay_input_sha256")
    if value["semantic_claim"] != "stdin-transport-only":
        raise ValidationError("parent_semantic_replay.semantic_claim must be stdin-transport-only")
    reviews = value["reviews"]
    if not isinstance(reviews, list) or len(reviews) != 2:
        raise ValidationError("parent_semantic_replay.reviews must contain exactly two provider receipts")
    providers: set[str] = set()
    identities: set[str] = set()
    for index, review in enumerate(reviews):
        item = require_mapping(review, f"parent_semantic_replay.reviews[{index}]")
        require_exact_keys(
            item,
            f"parent_semantic_replay.reviews[{index}]",
            [
                "candidate_workflow_sha",
                "model",
                "parent_workflow_sha",
                "provider",
                "provider_identity",
                "receipt_sha256",
                "replay_input_sha256",
                "verdict",
            ],
        )
        provider = require_string(item["provider"], f"parent_semantic_replay.reviews[{index}].provider")
        if not PROVIDER_RE.fullmatch(provider):
            raise ValidationError(f"parent_semantic_replay.reviews[{index}].provider is not canonical")
        identity = require_string(item["provider_identity"], f"parent_semantic_replay.reviews[{index}].provider_identity")
        require_string(item["model"], f"parent_semantic_replay.reviews[{index}].model")
        if item["parent_workflow_sha"] != parent["workflow_sha"]:
            raise ValidationError(f"parent_semantic_replay.reviews[{index}] does not bind the parent")
        if item["candidate_workflow_sha"] != candidate["head_sha"]:
            raise ValidationError(f"parent_semantic_replay.reviews[{index}] does not bind the candidate")
        if item["replay_input_sha256"] != value["replay_input_sha256"]:
            raise ValidationError(f"parent_semantic_replay.reviews[{index}] has a different replay input")
        if item["verdict"] != "parent-equivalent":
            raise ValidationError(f"parent_semantic_replay.reviews[{index}] must be parent-equivalent")
        require_digest(item["receipt_sha256"], f"parent_semantic_replay.reviews[{index}].receipt_sha256")
        if provider in providers:
            raise ValidationError("parent_semantic_replay requires two distinct providers")
        if identity in identities:
            raise ValidationError("parent_semantic_replay requires two distinct provider identities")
        providers.add(provider)
        identities.add(identity)
    return value


def validate_merge(merge: Any, repository: str, parent: Mapping[str, Any], candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    value = require_mapping(merge, "merge")
    require_exact_keys(
        value,
        "merge",
        ["base_ref", "expected_parent_sha", "head_ref", "head_sha", "method", "pull_number", "repository"],
    )
    if value["repository"] != repository:
        raise ValidationError("merge.repository must bind the requested repository")
    if value["pull_number"] != candidate["pull_number"]:
        raise ValidationError("merge.pull_number must bind the candidate pull request")
    if value["base_ref"] != MAIN_REF:
        raise ValidationError(f"merge.base_ref must equal {MAIN_REF}")
    if value["head_ref"] != candidate["head_ref"]:
        raise ValidationError("merge.head_ref must bind the candidate")
    if value["head_sha"] != candidate["head_sha"]:
        raise ValidationError("merge.head_sha must bind the exact candidate head")
    if value["expected_parent_sha"] != parent["workflow_sha"]:
        raise ValidationError("merge.expected_parent_sha must bind the exact parent")
    if value["method"] != "merge":
        raise ValidationError("merge.method must be merge; squash, rebase, and force are forbidden")
    return value


def validate_restore(restore: Any) -> Mapping[str, Any]:
    value = require_mapping(restore, "restore")
    require_exact_keys(value, "restore", ["required", "required_receipts", "state"])
    if value["required"] is not True:
        raise ValidationError("restore.required must be true")
    if value["state"] != RESTORE_STATE:
        raise ValidationError(f"restore.state must equal {RESTORE_STATE}")
    if value["required_receipts"] != RESTORE_RECEIPTS:
        raise ValidationError("restore.required_receipts must preserve the ordinary authority restore sequence")
    return value


def validate_request(request: Any, schema: Any) -> Mapping[str, Any]:
    validate_schema_document(schema)
    value = require_mapping(request, "request")
    require_exact_keys(
        value,
        "request",
        [
            "candidate",
            "e2big_proof",
            "merge",
            "parent",
            "parent_semantic_replay",
            "recovery_id",
            "repository",
            "restore",
            "schema",
            "scope",
            "source_only",
        ],
    )
    if value["schema"] != SCHEMA_NAME:
        raise ValidationError(f"request.schema must equal {SCHEMA_NAME}")
    if value["source_only"] is not True:
        raise ValidationError("request.source_only must be true")
    recovery_id = require_string(value["recovery_id"], "request.recovery_id")
    if not re.fullmatch(r"authority-recovery-v1-[a-z0-9][a-z0-9-]{2,80}", recovery_id):
        raise ValidationError("request.recovery_id must be a stable authority-recovery-v1 identifier")
    repository = require_string(value["repository"], "request.repository")
    if not REPOSITORY_RE.fullmatch(repository):
        raise ValidationError("request.repository must be owner/repository")
    validate_scope(value["scope"])
    parent = validate_parent(value["parent"])
    candidate = validate_candidate(value["candidate"])
    if candidate["head_sha"] == parent["workflow_sha"]:
        raise ValidationError("candidate.head_sha must differ from parent.workflow_sha")
    validate_e2big_proof(value["e2big_proof"], repository, parent)
    validate_parent_semantic_replay(value["parent_semantic_replay"], parent, candidate)
    validate_merge(value["merge"], repository, parent, candidate)
    validate_restore(value["restore"])
    return value


def build_receipt(request: Mapping[str, Any]) -> dict[str, Any]:
    """Build the only source-only output: a plan that still requires restore."""
    merge = request["merge"]
    return {
        "schema": "authority/recovery-v1/receipt",
        "recovery_id": request["recovery_id"],
        "request_sha256": sha256_json(request),
        "e2big_proof_tuple_sha256": sha256_json(request["e2big_proof"]),
        "parent_semantic_replay_sha256": sha256_json(request["parent_semantic_replay"]),
        "merge_cas": {
            "endpoint": f"/repos/{merge['repository']}/pulls/{merge['pull_number']}/merge",
            "expected_head_sha": merge["head_sha"],
            "force": False,
            "http_method": "PUT",
            "merge_method": "merge",
            "status": "not-authorized-source-only",
        },
        "forbidden_effects": [
            "control-ref",
            "deployment",
            "environment",
            "ruleset",
            "repository-setting",
            "app",
            "external-effect",
        ],
        "state": "restore_required",
        "restore": request["restore"],
    }


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValidationError(f"{label} file does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise ValidationError(f"{label} is not valid JSON: {error}") from error


def write_output(path: str, receipt: Mapping[str, Any]) -> None:
    rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if path == "-":
        sys.stdout.write(rendered)
        return
    Path(path).write_text(rendered, encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="authority/recovery-v1 request JSON")
    parser.add_argument("--schema", required=True, help="authority/recovery-v1 schema JSON")
    parser.add_argument("--output", default="-", help="receipt path, or - for stdout")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        request = load_json(Path(args.request), "request")
        schema = load_json(Path(args.schema), "schema")
        validated = validate_request(request, schema)
        write_output(args.output, build_receipt(validated))
    except ValidationError as error:
        print(f"authority/recovery-v1 denied: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
