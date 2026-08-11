from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "audit_workflow_states.py"
SPEC = importlib.util.spec_from_file_location("audit_workflow_states", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def workflow(repository: str, workflow_id: int, state: str = "active") -> dict[str, object]:
    return {
        "repository": repository,
        "workflow_id": workflow_id,
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "state": state,
    }


def exception(repository: str, workflow_id: int, *, allow_absent: bool = False) -> dict[str, object]:
    return {
        "repository": repository,
        "workflow_id": workflow_id,
        "path": ".github/workflows/ci.yml",
        "expected_state": "disabled_manually",
        "allow_absent": allow_absent,
        "reason": "reviewed exception",
    }


class WorkflowStateAuditTests(unittest.TestCase):
    def test_accepts_github_generated_dynamic_workflow_paths(self) -> None:
        record = workflow("Mindburn-Labs/example", 1)
        record["path"] = "dynamic/agents/copilot-pull-request-reviewer"
        self.assertEqual(
            MODULE.require_record(record, keys=MODULE.INVENTORY_KEYS, label="inventory")["path"],
            record["path"],
        )

    def test_detects_unexpected_disable_and_exception_drift(self) -> None:
        policy = [
            exception("Mindburn-Labs/risky", 2),
            exception("Mindburn-Labs/obsolete", 3, allow_absent=True),
        ]

        passing = MODULE.audit(
            [
                workflow("Mindburn-Labs/normal", 1),
                workflow("Mindburn-Labs/risky", 2, "disabled_manually"),
            ],
            policy,
        )
        self.assertEqual(passing["status"], "pass")

        failing = MODULE.audit(
            [
                workflow("Mindburn-Labs/normal", 1, "disabled_manually"),
                workflow("Mindburn-Labs/risky", 2),
            ],
            policy,
        )
        self.assertEqual(
            {item["kind"] for item in failing["violations"]},
            {"unexpected_disabled", "exception_mismatch"},
        )

    def test_required_exception_cannot_silently_disappear(self) -> None:
        result = MODULE.audit([], [exception("Mindburn-Labs/risky", 2)])
        self.assertEqual(result["violations"][0]["kind"], "expected_workflow_absent")


if __name__ == "__main__":
    unittest.main()
