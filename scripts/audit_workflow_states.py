#!/usr/bin/env python3
"""Compare live GitHub workflow states with reviewed disabled exceptions."""

from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import re
import sys


POLICY_SCHEMA = "mindburn.workflow-state-policy/v2"
REPORT_SCHEMA = "mindburn.workflow-state-audit/v2"
REPOSITORY_PATTERN = re.compile(r"^Mindburn-Labs/[A-Za-z0-9_.-]+$")
WORKFLOW_PATH_PATTERN = re.compile(
    r"^(?:\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml|dynamic/[A-Za-z0-9][A-Za-z0-9._/-]*)$",
)
DOCUMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
INVENTORY_KEYS = {"repository", "workflow_id", "name", "path", "state"}
REPOSITORY_KEYS = {"repository", "actions_enabled"}
AUDIT_EVENT_KEYS = {"document_id", "action", "repository", "workflow_id", "actor", "created_at"}
REVIEWED_EVENT_KEYS = {
    "document_id",
    "action",
    "repository",
    "workflow_id",
    "actor",
    "approval_record",
}
EXCEPTION_KEYS = {
    "repository",
    "workflow_id",
    "path",
    "expected_state",
    "allow_absent",
    "reason",
}
STATE_CHANGE_ACTIONS = {"workflows.disable_workflow", "workflows.enable_workflow"}


class WorkflowStateError(ValueError):
    """Raised when workflow-state evidence or policy is malformed."""


def require_record(value: object, *, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise WorkflowStateError(f"{label} must contain exactly {sorted(keys)}")
    repository = value["repository"]
    workflow_id = value["workflow_id"]
    path = value["path"]
    if not isinstance(repository, str) or not REPOSITORY_PATTERN.fullmatch(repository):
        raise WorkflowStateError(f"{label}.repository is invalid")
    if type(workflow_id) is not int or workflow_id <= 0:
        raise WorkflowStateError(f"{label}.workflow_id must be a positive integer")
    if not isinstance(path, str) or not WORKFLOW_PATH_PATTERN.fullmatch(path):
        raise WorkflowStateError(f"{label}.path is invalid")
    return value


def load_inventory(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WorkflowStateError(f"inventory line {line_number} is not valid JSON") from exc
        record = require_record(value, keys=INVENTORY_KEYS, label=f"inventory line {line_number}")
        if not isinstance(record["name"], str) or not record["name"]:
            raise WorkflowStateError(f"inventory line {line_number}.name is invalid")
        if not isinstance(record["state"], str) or not record["state"]:
            raise WorkflowStateError(f"inventory line {line_number}.state is invalid")
        records.append(record)
    return records


def load_repositories(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WorkflowStateError(f"repository line {line_number} is not valid JSON") from exc
        if not isinstance(value, dict) or set(value) != REPOSITORY_KEYS:
            raise WorkflowStateError(
                f"repository line {line_number} must contain exactly {sorted(REPOSITORY_KEYS)}",
            )
        if not isinstance(value["repository"], str) or not REPOSITORY_PATTERN.fullmatch(value["repository"]):
            raise WorkflowStateError(f"repository line {line_number}.repository is invalid")
        if type(value["actions_enabled"]) is not bool:
            raise WorkflowStateError(f"repository line {line_number}.actions_enabled must be boolean")
        records.append(value)
    return records


def load_expected_repositories(path: Path) -> set[str]:
    repositories: set[str] = set()
    for line_number, repository in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not REPOSITORY_PATTERN.fullmatch(repository):
            raise WorkflowStateError(f"expected repository line {line_number} is invalid")
        if repository in repositories:
            raise WorkflowStateError(f"duplicate expected repository: {repository}")
        repositories.add(repository)
    if not repositories:
        raise WorkflowStateError("expected repository inventory is empty")
    return repositories


def require_state_change(
    value: object,
    *,
    keys: set[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise WorkflowStateError(f"{label} must contain exactly {sorted(keys)}")
    if not isinstance(value["document_id"], str) or not DOCUMENT_ID_PATTERN.fullmatch(value["document_id"]):
        raise WorkflowStateError(f"{label}.document_id is invalid")
    if value["action"] not in STATE_CHANGE_ACTIONS:
        raise WorkflowStateError(f"{label}.action is invalid")
    if not isinstance(value["repository"], str) or not REPOSITORY_PATTERN.fullmatch(value["repository"]):
        raise WorkflowStateError(f"{label}.repository is invalid")
    if type(value["workflow_id"]) is not int or value["workflow_id"] <= 0:
        raise WorkflowStateError(f"{label}.workflow_id must be a positive integer")
    if not isinstance(value["actor"], str) or not value["actor"]:
        raise WorkflowStateError(f"{label}.actor is invalid")
    return value


def load_audit_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WorkflowStateError(f"audit event line {line_number} is not valid JSON") from exc
        event = require_state_change(value, keys=AUDIT_EVENT_KEYS, label=f"audit event line {line_number}")
        if type(event["created_at"]) is not int or event["created_at"] <= 0:
            raise WorkflowStateError(f"audit event line {line_number}.created_at must be a positive integer")
        events.append(event)
    return events


def load_policy(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WorkflowStateError("workflow-state policy is not valid JSON") from exc
    expected_keys = {"schema", "audit_log_since", "reviewed_state_changes", "intentionally_disabled"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise WorkflowStateError("workflow-state policy has unexpected keys")
    if value["schema"] != POLICY_SCHEMA:
        raise WorkflowStateError(f"workflow-state policy must use {POLICY_SCHEMA}")
    if not isinstance(value["audit_log_since"], str) or not DATE_PATTERN.fullmatch(value["audit_log_since"]):
        raise WorkflowStateError("workflow-state policy audit_log_since must be an ISO date")
    try:
        audit_log_since = date.fromisoformat(value["audit_log_since"])
    except ValueError as exc:
        raise WorkflowStateError("workflow-state policy audit_log_since must be an ISO date") from exc
    if audit_log_since > date.today():
        raise WorkflowStateError("workflow-state policy audit_log_since cannot be in the future")
    if not isinstance(value["reviewed_state_changes"], list):
        raise WorkflowStateError("workflow-state policy reviewed_state_changes must be a list")
    if not isinstance(value["intentionally_disabled"], list):
        raise WorkflowStateError("workflow-state policy intentionally_disabled must be a list")

    reviewed_events: list[dict[str, object]] = []
    for index, item in enumerate(value["reviewed_state_changes"]):
        event = require_state_change(item, keys=REVIEWED_EVENT_KEYS, label=f"reviewed state change {index}")
        if not isinstance(event["approval_record"], str) or not event["approval_record"].strip():
            raise WorkflowStateError(f"reviewed state change {index}.approval_record is required")
        reviewed_events.append(event)

    exceptions: list[dict[str, object]] = []
    for index, item in enumerate(value["intentionally_disabled"]):
        exception = require_record(item, keys=EXCEPTION_KEYS, label=f"policy exception {index}")
        if (
            not isinstance(exception["expected_state"], str)
            or not exception["expected_state"]
            or exception["expected_state"] == "active"
        ):
            raise WorkflowStateError(f"policy exception {index}.expected_state must be non-active")
        if type(exception["allow_absent"]) is not bool:
            raise WorkflowStateError(f"policy exception {index}.allow_absent must be boolean")
        if not isinstance(exception["reason"], str) or not exception["reason"].strip():
            raise WorkflowStateError(f"policy exception {index}.reason is required")
        exceptions.append(exception)
    return {
        "audit_log_since": value["audit_log_since"],
        "reviewed_state_changes": reviewed_events,
        "intentionally_disabled": exceptions,
    }


def audit(
    inventory: list[dict[str, object]],
    exceptions: list[dict[str, object]],
    *,
    repositories: list[dict[str, object]],
    expected_repositories: set[str],
    audit_events: list[dict[str, object]],
    reviewed_state_changes: list[dict[str, object]],
    audit_log_since: str,
) -> dict[str, object]:
    observed_repositories: dict[str, dict[str, object]] = {}
    for repository in repositories:
        name = str(repository["repository"])
        if name in observed_repositories:
            raise WorkflowStateError(f"duplicate repository evidence: {name}")
        observed_repositories[name] = repository

    observed: dict[tuple[str, int], dict[str, object]] = {}
    for record in inventory:
        if record["repository"] not in observed_repositories:
            raise WorkflowStateError(f"workflow inventory repository is absent: {record['repository']}")
        key = (str(record["repository"]), int(record["workflow_id"]))
        if key in observed:
            raise WorkflowStateError(f"duplicate inventory workflow: {key[0]}#{key[1]}")
        observed[key] = record

    expected: dict[tuple[str, int], dict[str, object]] = {}
    for exception in exceptions:
        key = (str(exception["repository"]), int(exception["workflow_id"]))
        if key in expected:
            raise WorkflowStateError(f"duplicate policy workflow: {key[0]}#{key[1]}")
        expected[key] = exception

    allowed: list[dict[str, object]] = []
    violations: list[dict[str, object]] = []

    for repository in sorted(expected_repositories - observed_repositories.keys()):
        violations.append({"kind": "repository_missing_from_credential_view", "repository": repository})
    for repository in sorted(observed_repositories.keys() - expected_repositories):
        violations.append({"kind": "repository_missing_from_source_manifest", "repository": repository})
    for repository in observed_repositories.values():
        if not repository["actions_enabled"]:
            violations.append({"kind": "repository_actions_disabled", **repository})

    for key, record in observed.items():
        exception = expected.get(key)
        if exception is None:
            if record["state"] != "active":
                violations.append({"kind": "unexpected_disabled", **record})
            continue
        if record["path"] != exception["path"] or record["state"] != exception["expected_state"]:
            violations.append(
                {
                    "kind": "exception_mismatch",
                    **record,
                    "expected_path": exception["path"],
                    "expected_state": exception["expected_state"],
                },
            )
        else:
            allowed.append(record)

    for key, exception in expected.items():
        if key not in observed and not exception["allow_absent"]:
            violations.append({"kind": "expected_workflow_absent", **exception})

    reviewed_by_id: dict[str, dict[str, object]] = {}
    for event in reviewed_state_changes:
        document_id = str(event["document_id"])
        if document_id in reviewed_by_id:
            raise WorkflowStateError(f"duplicate reviewed state change: {document_id}")
        reviewed_by_id[document_id] = event

    observed_event_ids: set[str] = set()
    reviewed_events: list[dict[str, object]] = []
    for event in audit_events:
        document_id = str(event["document_id"])
        if document_id in observed_event_ids:
            raise WorkflowStateError(f"duplicate audit event: {document_id}")
        observed_event_ids.add(document_id)
        reviewed = reviewed_by_id.get(document_id)
        if reviewed is None:
            violations.append({"kind": "unreviewed_state_change", **event})
            continue
        compared_keys = REVIEWED_EVENT_KEYS - {"approval_record"}
        if any(event[key] != reviewed[key] for key in compared_keys):
            violations.append(
                {
                    "kind": "reviewed_state_change_mismatch",
                    **event,
                    "reviewed": reviewed,
                },
            )
        else:
            reviewed_events.append(event)

    repository_coverage_complete = not any(
        violation["kind"]
        in {"repository_missing_from_credential_view", "repository_missing_from_source_manifest"}
        for violation in violations
    )

    return {
        "schema": REPORT_SCHEMA,
        "status": "fail" if violations else "observed_scope_pass",
        "coverage": {
            "repository_inventory": "exact_manifest_match" if repository_coverage_complete else "incomplete",
            "repository_actions_permissions": "checked",
            "audit_log_since": audit_log_since,
            "self_monitoring": "external_watchdog_required",
            "continuous_coverage": False,
        },
        "repository_count": len(repositories),
        "workflow_count": len(inventory),
        "audit_event_count": len(audit_events),
        "non_active_count": sum(record["state"] != "active" for record in inventory),
        "allowed_disabled": sorted(allowed, key=lambda item: (item["repository"], item["workflow_id"])),
        "reviewed_state_changes": sorted(reviewed_events, key=lambda item: item["document_id"]),
        "violations": sorted(
            violations,
            key=lambda item: (
                str(item.get("repository", "")),
                int(item.get("workflow_id", 0)),
                str(item["kind"]),
            ),
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--repositories", type=Path, required=True)
    parser.add_argument("--expected-repositories", type=Path, required=True)
    parser.add_argument("--audit-events", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        policy = load_policy(args.policy)
        result = audit(
            load_inventory(args.inventory),
            policy["intentionally_disabled"],
            repositories=load_repositories(args.repositories),
            expected_repositories=load_expected_repositories(args.expected_repositories),
            audit_events=load_audit_events(args.audit_events),
            reviewed_state_changes=policy["reviewed_state_changes"],
            audit_log_since=str(policy["audit_log_since"]),
        )
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
        return 1 if result["violations"] else 0
    except (OSError, WorkflowStateError) as exc:
        print(f"audit-workflow-states: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
