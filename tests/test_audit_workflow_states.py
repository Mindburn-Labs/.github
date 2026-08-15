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


def repository(name: str, *, actions_enabled: bool = True) -> dict[str, object]:
    return {"repository": name, "actions_enabled": actions_enabled}


def state_change(document_id: str = "event-1") -> dict[str, object]:
    return {
        "document_id": document_id,
        "action": "workflows.disable_workflow",
        "repository": "Mindburn-Labs/example",
        "workflow_id": 1,
        "actor": "mindburnlabs",
        "created_at": 1786400000000,
    }


def audit(
    workflows: list[dict[str, object]],
    exceptions: list[dict[str, object]],
    *,
    repositories: list[dict[str, object]] | None = None,
    expected_repositories: set[str] | None = None,
    audit_events: list[dict[str, object]] | None = None,
    reviewed_state_changes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if repositories is None:
        names = {str(item["repository"]) for item in workflows + exceptions} or {"Mindburn-Labs/example"}
        repositories = [repository(name) for name in names]
    if expected_repositories is None:
        expected_repositories = {str(item["repository"]) for item in repositories}
    return MODULE.audit(
        workflows,
        exceptions,
        repositories=repositories,
        expected_repositories=expected_repositories,
        audit_events=[] if audit_events is None else audit_events,
        reviewed_state_changes=[] if reviewed_state_changes is None else reviewed_state_changes,
        audit_log_since="2026-08-11",
    )


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

        passing = audit(
            [
                workflow("Mindburn-Labs/normal", 1),
                workflow("Mindburn-Labs/risky", 2, "disabled_manually"),
            ],
            policy,
        )
        self.assertEqual(passing["status"], "observed_scope_pass")

        failing = audit(
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
        result = audit([], [exception("Mindburn-Labs/risky", 2)])
        self.assertEqual(result["violations"][0]["kind"], "expected_workflow_absent")

    def test_requires_complete_repository_view_and_enabled_actions(self) -> None:
        repositories = [
            repository("Mindburn-Labs/visible", actions_enabled=False),
            repository("Mindburn-Labs/unexpected"),
        ]
        result = audit(
            [],
            [],
            repositories=repositories,
            expected_repositories={"Mindburn-Labs/visible", "Mindburn-Labs/missing"},
        )
        self.assertEqual(
            {item["kind"] for item in result["violations"]},
            {
                "repository_actions_disabled",
                "repository_missing_from_credential_view",
                "repository_missing_from_source_manifest",
            },
        )

    def test_detects_transient_unreviewed_state_change(self) -> None:
        event = state_change()
        failing = audit([], [], audit_events=[event])
        self.assertEqual(failing["violations"][0]["kind"], "unreviewed_state_change")

        reviewed = {key: value for key, value in event.items() if key != "created_at"}
        reviewed["approval_record"] = "HELM-366 exact single-use approval"
        passing = audit([], [], audit_events=[event], reviewed_state_changes=[reviewed])
        self.assertEqual(passing["status"], "observed_scope_pass")

    def test_reports_self_monitoring_limit_and_has_no_manual_dispatch(self) -> None:
        result = audit([], [])
        self.assertFalse(result["coverage"]["continuous_coverage"])
        self.assertEqual(result["coverage"]["self_monitoring"], "external_watchdog_required")
        workflow_text = (ROOT / ".github" / "workflows" / "workflow-state-audit.yml").read_text()
        self.assertNotIn("workflow_dispatch", workflow_text)


if __name__ == "__main__":
    unittest.main()
