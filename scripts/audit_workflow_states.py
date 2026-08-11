#!/usr/bin/env python3
"""Compare live GitHub workflow states with reviewed disabled exceptions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


POLICY_SCHEMA = "mindburn.workflow-state-policy/v1"
REPORT_SCHEMA = "mindburn.workflow-state-audit/v1"
REPOSITORY_PATTERN = re.compile(r"^Mindburn-Labs/[A-Za-z0-9_.-]+$")
WORKFLOW_PATH_PATTERN = re.compile(
    r"^(?:\.github/workflows/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml|dynamic/[A-Za-z0-9][A-Za-z0-9._/-]*)$",
)
INVENTORY_KEYS = {"repository", "workflow_id", "name", "path", "state"}
EXCEPTION_KEYS = {
    "repository",
    "workflow_id",
    "path",
    "expected_state",
    "allow_absent",
    "reason",
}


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


def load_policy(path: Path) -> list[dict[str, object]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WorkflowStateError("workflow-state policy is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "intentionally_disabled"}:
        raise WorkflowStateError("workflow-state policy has unexpected keys")
    if value["schema"] != POLICY_SCHEMA or not isinstance(value["intentionally_disabled"], list):
        raise WorkflowStateError(f"workflow-state policy must use {POLICY_SCHEMA}")
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
    return exceptions


def audit(
    inventory: list[dict[str, object]],
    exceptions: list[dict[str, object]],
) -> dict[str, object]:
    observed: dict[tuple[str, int], dict[str, object]] = {}
    for record in inventory:
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

    return {
        "schema": REPORT_SCHEMA,
        "status": "fail" if violations else "pass",
        "workflow_count": len(inventory),
        "non_active_count": sum(record["state"] != "active" for record in inventory),
        "allowed_disabled": sorted(allowed, key=lambda item: (item["repository"], item["workflow_id"])),
        "violations": sorted(violations, key=lambda item: (item["repository"], item["workflow_id"])),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        result = audit(load_inventory(args.inventory), load_policy(args.policy))
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
        return 1 if result["violations"] else 0
    except (OSError, WorkflowStateError) as exc:
        print(f"audit-workflow-states: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
