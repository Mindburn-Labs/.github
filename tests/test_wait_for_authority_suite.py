from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wait_for_authority_suite.py"
SPEC = importlib.util.spec_from_file_location("wait_for_authority_suite", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)


class FakeJobClient:
    def __init__(self, *, artifacts=None, jobs=None) -> None:
        self.artifacts = artifacts or []
        self.jobs = jobs or []

    def get_json(self, path: str):
        if path.endswith("/artifacts"):
            return {"artifacts": self.artifacts}
        if "/jobs" in path:
            return {"jobs": self.jobs}
        raise AssertionError(path)


class AuthoritySuiteTests(unittest.TestCase):
    def test_trigger_must_exactly_match_source_contract(self) -> None:
        contract = MODULE.load_json(
            ROOT / "config" / "autonomous-release-control-plane.json",
            label="contract",
        )
        corpus = MODULE.load_json(
            ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
            label="corpus",
        )
        contract = MODULE.validate_contract(contract, corpus)
        trigger = {
            "schema": MODULE.TRIGGER_SCHEMA,
            "repository": contract["adversarial_suite"]["repository"],
            "workflow_sha": "a" * 40,
            "started_at": "2026-07-14T00:00:00Z",
            "cases": contract["adversarial_suite"]["cases"],
        }
        self.assertEqual(MODULE.validate_trigger(trigger, contract), trigger)
        trigger["cases"] = trigger["cases"][:-1]
        with self.assertRaisesRegex(MODULE.PermitInputError, "exactly match"):
            MODULE.validate_trigger(trigger, contract)

    def test_pre_model_reject_requires_failed_gate_and_no_evidence(self) -> None:
        client = FakeJobClient(
            jobs=[
                {"name": "Deterministic repository gates", "conclusion": "failure"},
                {"name": "anthropic / claude-fable-5", "conclusion": "skipped"},
                {"name": "openai / gpt-5.6-sol", "conclusion": "skipped"},
            ],
        )
        detail = MODULE.validate_pre_model_reject(client, "Mindburn-Labs/lab", {"id": 7})
        self.assertEqual(detail["failed_gates"], ["Deterministic repository gates"])

    def test_pre_model_reject_fails_if_review_artifact_exists(self) -> None:
        client = FakeJobClient(
            artifacts=[{"name": "release-review-openai", "expired": False}],
            jobs=[{"name": "Bind immutable review input", "conclusion": "failure"}],
        )
        with self.assertRaisesRegex(MODULE.PermitInputError, "forbidden review evidence"):
            MODULE.validate_pre_model_reject(client, "Mindburn-Labs/lab", {"id": 7})


if __name__ == "__main__":
    unittest.main()
