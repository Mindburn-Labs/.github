from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "configure_machine_approval_gates.py"
SPEC = importlib.util.spec_from_file_location("configure_machine_approval_gates", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CANDIDATE_SHA = "2" * 40
CANDIDATE_REF = "refs/heads/codex/autonomous-release-gen2-bootstrap"


def machine_workflow_ruleset() -> dict[str, object]:
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
        field: {"enabled": normalized[field]} for field in boolean_fields
    }
    for field in ("required_pull_request_reviews", "required_status_checks", "restrictions"):
        if normalized[field] is not None:
            result[field] = normalized[field]
    return result


class FakeClient:
    def __init__(self, contract: dict[str, object]) -> None:
        self.workflow = machine_workflow_ruleset()
        self.machine: dict[str, object] | None = None
        self.human = {
            "id": MODULE.HUMAN_RULESET_ID,
            **MODULE.human_ruleset_state(contract, "before"),
        }
        self.protection = raw_protection(contract["classic_branch_protection"]["expected"])
        self.puts = 0
        self.posts = 0
        self.etag = 'W/"human-v1"'

    def request(self, method: str, path: str, *, payload=None, if_match=None):
        response = MODULE.AdminResponse
        if path.endswith(f"rulesets/{MODULE.STABLE_RULESET_ID}"):
            return response(json.loads(json.dumps(self.workflow)), 'W/"workflow"')
        if path.endswith("rulesets?per_page=100"):
            values = [] if self.machine is None else [{"id": self.machine["id"], "name": MODULE.MACHINE_RULESET_NAME}]
            return response(values, None)
        if path.endswith("/rulesets") and method == "POST":
            self.posts += 1
            self.machine = {"id": 9001, **json.loads(json.dumps(payload))}
            return response(json.loads(json.dumps(self.machine)), 'W/"machine"')
        if path.endswith("rulesets/9001"):
            return response(json.loads(json.dumps(self.machine)), 'W/"machine"')
        if path.endswith(f"rulesets/{MODULE.HUMAN_RULESET_ID}"):
            if method == "GET":
                return response(json.loads(json.dumps(self.human)), self.etag)
            if method == "PUT":
                if if_match != self.etag:
                    raise MODULE.PermitInputError("stale")
                self.puts += 1
                self.human = {"id": MODULE.HUMAN_RULESET_ID, **json.loads(json.dumps(payload))}
                self.etag = 'W/"human-v2"'
                return response(json.loads(json.dumps(self.human)), self.etag)
        if path.endswith("/branches/main/protection"):
            return response(json.loads(json.dumps(self.protection)), 'W/"classic"')
        raise AssertionError(f"unexpected request {method} {path}")


class ConfigureMachineApprovalGatesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract_path = ROOT / "config" / "autonomous-release-bootstrap-v1.json"
        self.contract = MODULE.load_contract(self.contract_path)
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.approval_path = Path(self.tempdir.name) / "approval.json"
        self.approval_path.write_text(
            json.dumps(
                {
                    "schema": MODULE.APPROVAL_SCHEMA,
                    "repository": "Mindburn-Labs/.github",
                    "pull_request": 36,
                    "head_sha": CANDIDATE_SHA,
                    "review_state": "APPROVED",
                    "approver_login": MODULE.APPROVER_LOGIN,
                    "review_id": 42,
                },
            ),
            encoding="utf-8",
        )
        self.args = argparse.Namespace(
            candidate_sha=CANDIDATE_SHA,
            candidate_ref=CANDIDATE_REF,
            pull_request=36,
            approval_receipt=self.approval_path,
            contract=self.contract_path,
        )

    def test_installs_machine_interlock_before_retiring_codeowner_scope(self) -> None:
        client = FakeClient(self.contract)
        receipt = MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.posts, 1)
        self.assertEqual(client.puts, 1)
        self.assertEqual(receipt["machine_approval_review_id"], 42)
        self.assertEqual(
            MODULE.controlled_ruleset(client.human),
            MODULE.human_ruleset_state(self.contract, "after"),
        )
        self.assertEqual(
            MODULE.normalize_classic_protection(client.protection),
            self.contract["classic_branch_protection"]["expected"],
        )

    def test_exact_post_cutover_state_is_idempotent(self) -> None:
        client = FakeClient(self.contract)
        MODULE.configure_machine_approval_gates(self.args, client)
        client.posts = 0
        client.puts = 0
        MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.posts, 0)
        self.assertEqual(client.puts, 0)

    def test_missing_etag_fails_before_human_rule_mutation(self) -> None:
        client = FakeClient(self.contract)
        client.etag = ""
        with self.assertRaisesRegex(MODULE.PermitInputError, "ETag"):
            MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.puts, 0)

    def test_machine_ruleset_drift_blocks_cutover(self) -> None:
        client = FakeClient(self.contract)
        client.machine = {"id": 9001, **MODULE.machine_ruleset_payload()}
        client.machine["enforcement"] = "evaluate"
        with self.assertRaisesRegex(MODULE.PermitInputError, "not exact and active"):
            MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.puts, 0)


if __name__ == "__main__":
    unittest.main()
