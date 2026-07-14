from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "remove_human_approval_gates.py"
SPEC = importlib.util.spec_from_file_location("remove_human_approval_gates", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

CANDIDATE_SHA = "2" * 40
CANDIDATE_REF = "refs/heads/codex/autonomous-release-gen2-bootstrap"


def machine_ruleset() -> dict[str, object]:
    broker = sys.modules["authority_ruleset_broker"]
    return {
        "id": broker.STABLE_RULESET_ID,
        "name": broker.STABLE_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": broker.expected_conditions("stable"),
        "rules": [
            {
                "type": "workflows",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "workflows": [
                        {
                            "repository_id": broker.AUTHORITY_REPOSITORY_ID,
                            "path": broker.WORKFLOW_PATH,
                            "sha": CANDIDATE_SHA,
                            "ref": CANDIDATE_REF,
                        },
                    ],
                },
            },
        ],
    }


def raw_protection(normalized: dict[str, object]) -> dict[str, object]:
    boolean_fields = (
        "allow_deletions",
        "allow_force_pushes",
        "allow_fork_syncing",
        "block_creations",
        "enforce_admins",
        "lock_branch",
        "required_conversation_resolution",
        "required_linear_history",
        "required_signatures",
    )
    result: dict[str, object] = {
        field: {"enabled": normalized[field]}
        for field in boolean_fields
    }
    if normalized["required_pull_request_reviews"] is not None:
        result["required_pull_request_reviews"] = normalized[
            "required_pull_request_reviews"
        ]
    if normalized["required_status_checks"] is not None:
        result["required_status_checks"] = normalized["required_status_checks"]
    if normalized["restrictions"] is not None:
        result["restrictions"] = normalized["restrictions"]
    return result


class FakeClient:
    def __init__(self, contract: dict[str, object]) -> None:
        self.machine = machine_ruleset()
        human = MODULE.human_ruleset_state(contract, "before")
        self.human = {"id": MODULE.HUMAN_RULESET_ID, **human}
        self.protection = raw_protection(
            contract["classic_branch_protection"]["before"],
        )
        self.methods: list[str] = []

    def request(self, method: str, path: str, *, payload=None):
        self.methods.append(method)
        if path.endswith(f"rulesets/{MODULE.STABLE_RULESET_ID}"):
            return json.loads(json.dumps(self.machine))
        if path.endswith(f"rulesets/{MODULE.HUMAN_RULESET_ID}"):
            if method == "GET":
                return json.loads(json.dumps(self.human))
            if method == "PUT" and payload is not None:
                self.human = {"id": MODULE.HUMAN_RULESET_ID, **json.loads(json.dumps(payload))}
                return json.loads(json.dumps(self.human))
        if path.endswith("/required_pull_request_reviews") and method == "DELETE":
            self.protection.pop("required_pull_request_reviews", None)
            return None
        if path.endswith("/branches/main/protection") and method == "GET":
            return json.loads(json.dumps(self.protection))
        raise AssertionError(f"unexpected request {method} {path}")


class RemoveHumanApprovalGatesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract_path = ROOT / "config" / "autonomous-release-bootstrap-v1.json"
        self.contract = MODULE.load_contract(self.contract_path)
        self.args = argparse.Namespace(
            candidate_sha=CANDIDATE_SHA,
            candidate_ref=CANDIDATE_REF,
            contract=self.contract_path,
        )

    def test_removes_only_covered_human_approvals_after_machine_enforcement(self) -> None:
        client = FakeClient(self.contract)
        receipt = MODULE.remove_human_approval_gates(self.args, client)
        self.assertEqual(
            receipt["removed_repository_ids"],
            [MODULE.KERNEL_REPOSITORY_ID, MODULE.AUTHORITY_REPOSITORY_ID],
        )
        self.assertEqual(
            MODULE.controlled_ruleset(client.human),
            MODULE.human_ruleset_state(self.contract, "after"),
        )
        self.assertEqual(
            MODULE.normalize_classic_protection(client.protection),
            self.contract["classic_branch_protection"]["after"],
        )
        self.assertIn("PUT", client.methods)
        self.assertIn("DELETE", client.methods)

    def test_operation_is_idempotent_at_exact_post_removal_state(self) -> None:
        client = FakeClient(self.contract)
        MODULE.remove_human_approval_gates(self.args, client)
        client.methods.clear()
        MODULE.remove_human_approval_gates(self.args, client)
        self.assertNotIn("PUT", client.methods)
        self.assertNotIn("DELETE", client.methods)

    def test_refuses_to_remove_approvals_before_machine_gate_is_active(self) -> None:
        client = FakeClient(self.contract)
        client.machine["enforcement"] = "evaluate"
        with self.assertRaisesRegex(Exception, "unexpected stable ruleset"):
            MODULE.remove_human_approval_gates(self.args, client)
        self.assertNotIn("PUT", client.methods)
        self.assertNotIn("DELETE", client.methods)


if __name__ == "__main__":
    unittest.main()
