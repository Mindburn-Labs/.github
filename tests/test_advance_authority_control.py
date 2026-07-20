from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "advance_authority_control.py"
SPEC = importlib.util.spec_from_file_location("advance_authority_control", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)
from verify_control_plane import (  # noqa: E402
    expected_control_successor_ruleset,
)

PARENT_SHA = "1" * 40
CANDIDATE_SHA = "2" * 40
SUCCESSOR_SHA = "3" * 40
TREE_SHA = "4" * 40
PERMIT_ID = "sha256:" + "5" * 64
SUITE_SHA = "6" * 64
CANARY_ID = "sha256:" + "7" * 64
APP_ID = 4299000
INSTALLATION_ID = 146590000


class FakeClient:
    def __init__(self, *, current_sha: str = PARENT_SHA) -> None:
        self.current_sha = current_sha
        self.graphql_calls: list[tuple[str, dict[str, object]]] = []

    def get(self, path: str):
        if path == "/installation/repositories?per_page=100":
            return {"repositories": [{"full_name": MODULE.REPOSITORY}]}
        if path.endswith("/git/ref/heads/authority/control-v1"):
            return {"ref": MODULE.CONTROL_REF, "object": {"sha": self.current_sha}}
        if path.endswith("/pulls/36"):
            return {
                "number": 36,
                "state": "closed",
                "draft": False,
                "merged": True,
                "merge_commit_sha": SUCCESSOR_SHA,
                "base": {"ref": "main", "sha": PARENT_SHA},
                "head": {
                    "sha": CANDIDATE_SHA,
                    "repo": {"full_name": MODULE.REPOSITORY},
                },
            }
        if path.endswith(f"/git/commits/{SUCCESSOR_SHA}"):
            return {
                "parents": [{"sha": PARENT_SHA}, {"sha": CANDIDATE_SHA}],
                "tree": {"sha": TREE_SHA},
            }
        if "/contents/.github/workflows/promote-authority.yml" in path:
            return {
                "type": "file",
                "path": ".github/workflows/promote-authority.yml",
            }
        raise AssertionError(f"unexpected GET {path}")

    def graphql(self, query: str, variables: dict[str, object]):
        self.graphql_calls.append((query, variables))
        if "repository(owner:" in query:
            return {"repository": {"id": "R_kgDO"}}
        self.current_sha = str(variables["afterOid"])
        return {"updateRefs": {"clientMutationId": None}}


class FakeLedgerClient:
    token = "control-updater-token"


def execution() -> dict[str, object]:
    return {
        "schema": "mindburn.release-authority-promotion-execution/v2",
        "parent_generation": 2,
        "candidate_generation": 3,
        "parent_base_sha": PARENT_SHA,
        "parent_workflow_sha": PARENT_SHA,
        "control_workflow_sha": PARENT_SHA,
        "candidate_workflow_sha": CANDIDATE_SHA,
        "candidate_workflow_ref": "refs/heads/codex/successor",
        "candidate_tree_sha": TREE_SHA,
        "candidate_pull_request": 36,
        "merged_workflow_sha": SUCCESSOR_SHA,
        "merged_tree_sha": TREE_SHA,
        "ratification_permit_id": PERMIT_ID,
        "ratification_run_id": 9001,
        "ratification_run_attempt": 1,
        "canary_run_id": 9002,
        "canary_run_attempt": 1,
        "canary_permit_id": CANARY_ID,
        "authority_suite_sha256": SUITE_SHA,
    }


def observer() -> dict[str, object]:
    return {
        "schema": "mindburn.release-authority-observer-receipt/v4",
        "phase": "final",
        "decision": "ALLOW",
        "promotion_run_id": 9100,
        "promotion_run_attempt": 1,
        "control_workflow_sha": PARENT_SHA,
        "parent_workflow_sha": PARENT_SHA,
        "candidate_workflow_sha": CANDIDATE_SHA,
        "merged_workflow_sha": SUCCESSOR_SHA,
        "merged_tree_sha": TREE_SHA,
        "ratification_permit_id": PERMIT_ID,
        "canary_permit_id": CANARY_ID,
        "authority_suite_sha256": SUITE_SHA,
        "stable_workflow_sha": SUCCESSOR_SHA,
        "candidate_workflow_binding_sha": SUCCESSOR_SHA,
    }


def final_record() -> tuple[dict[str, object], dict[str, object]]:
    inputs = {
        "authority-promotion-execution.json": json.dumps(execution()).encode(),
        "final-observer-receipt.json": json.dumps(observer()).encode(),
        "final-observer-receipt.attestation.json": b'{"bundle":true}',
    }
    files = {
        path: {"sha256": str(index + 1) * 64, "size": len(content)}
        for index, (path, content) in enumerate(inputs.items())
    }
    receipt = {
        "schema": "mindburn.authority-evidence-ledger-append/v1",
        "namespace": f"promotions/generation-3/{SUCCESSOR_SHA}/final",
        "record_type": "authority-promotion",
        "phase": "final",
        "ledger_ref": "refs/heads/authority/evidence-v1",
        "ledger_parent_sha": "8" * 40,
        "ledger_head_sha": "9" * 40,
        "manifest_sha256": "a" * 64,
        "files": files,
        "idempotent": False,
    }
    record = {
        "descriptor": MODULE.stable_record_descriptor(receipt),
        "manifest": {"workflow_sha": PARENT_SHA},
        "inputs": inputs,
    }
    return receipt, record


class AdvanceAuthorityControlTests(unittest.TestCase):
    def invoke(self, client: FakeClient, *, mutate=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = json.loads(
                (ROOT / "config" / "autonomous-release-control-plane.json").read_text(
                    encoding="utf-8"
                )
            )
            successor = contract["control_workflow"]["successor_app"]
            successor["app_id"] = APP_ID
            successor["installation_id"] = INSTALLATION_ID
            contract["control_workflow"]["successor_ruleset"] = (
                expected_control_successor_ruleset(APP_ID)
            )
            receipt, record = final_record()
            if mutate is not None:
                mutate(contract, receipt, record)
            contract_path = root / "control.json"
            receipt_path = root / "final-receipt.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            args = argparse.Namespace(
                control_contract=contract_path,
                final_receipt=receipt_path,
                generation=3,
                parent_control_sha=PARENT_SHA,
                successor_sha=SUCCESSOR_SHA,
                updater_app_slug="helm-authority-control-updater",
                updater_app_id=APP_ID,
                updater_installation_id=INSTALLATION_ID,
            )
            with (
                mock.patch.object(MODULE, "read_record", return_value=record),
                mock.patch.object(MODULE, "verify_attestation") as verify,
            ):
                result = MODULE.advance_control(args, client, FakeLedgerClient())
            verify.assert_called_once()
            return result

    def test_advances_exact_durable_final_successor_with_cas(self) -> None:
        client = FakeClient()
        receipt = self.invoke(client)
        self.assertEqual(receipt["state"], "advanced")
        self.assertEqual(receipt["before_sha"], PARENT_SHA)
        self.assertEqual(receipt["after_sha"], SUCCESSOR_SHA)
        self.assertFalse(receipt["force"])
        self.assertEqual(client.current_sha, SUCCESSOR_SHA)
        self.assertEqual(len(client.graphql_calls), 2)

    def test_retry_accepts_only_the_exact_already_advanced_state(self) -> None:
        client = FakeClient(current_sha=SUCCESSOR_SHA)
        receipt = self.invoke(client)
        self.assertEqual(receipt["state"], "already-advanced")
        self.assertEqual(client.graphql_calls, [])

    def test_rejects_spliced_observer_canary(self) -> None:
        def mutate(_contract, _receipt, record):
            value = json.loads(record["inputs"]["final-observer-receipt.json"])
            value["canary_permit_id"] = "sha256:" + "b" * 64
            record["inputs"]["final-observer-receipt.json"] = json.dumps(value).encode()

        with self.assertRaisesRegex(MODULE.PermitInputError, "bind the successor"):
            self.invoke(FakeClient(), mutate=mutate)

    def test_rejects_control_ref_outside_the_two_resumable_states(self) -> None:
        with self.assertRaisesRegex(MODULE.PermitInputError, "resumable successor"):
            self.invoke(FakeClient(current_sha="c" * 40))

    def test_rejects_another_control_updater_installation(self) -> None:
        def mutate(contract, _receipt, _record):
            contract["control_workflow"]["successor_app"]["installation_id"] += 1

        with self.assertRaisesRegex(MODULE.PermitInputError, "action identity"):
            self.invoke(FakeClient(), mutate=mutate)


if __name__ == "__main__":
    unittest.main()
