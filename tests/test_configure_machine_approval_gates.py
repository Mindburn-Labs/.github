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
SPEC = importlib.util.spec_from_file_location(
    "configure_machine_approval_gates", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CANDIDATE_SHA = "2" * 40
CANDIDATE_REF = "refs/heads/codex/autonomous-release-gen2-bootstrap"
BASE_SHA = "1" * 40
MERGE_SHA = "3" * 40
TREE_SHA = "4" * 40
PERMIT_ID = "sha256:" + "5" * 64
MERGER_APP_ID = 5000001
MERGER_INSTALLATION_ID = 6000001


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
    for field in (
        "required_pull_request_reviews",
        "required_status_checks",
        "restrictions",
    ):
        if normalized[field] is not None:
            result[field] = normalized[field]
    return result


class FakeClient:
    def __init__(self, contract: dict[str, object]) -> None:
        self.workflow = machine_workflow_ruleset()
        self.machine: dict[str, object] | None = None
        self.updater: dict[str, object] | None = None
        self.proof_ruleset: dict[str, object] | None = None
        self.evidence_updater: dict[str, object] | None = None
        self.evidence_history: dict[str, object] | None = None
        self.human = {
            "id": MODULE.HUMAN_RULESET_ID,
            **MODULE.human_ruleset_state(contract, "before"),
        }
        self.kernel_quality = {
            "id": MODULE.KERNEL_QUALITY_RULESET_ID,
            **MODULE.kernel_quality_ruleset_legacy_payload(),
        }
        self.repository_settings = {
            repository: {
                "full_name": repository,
                **MODULE.ATOMIC_MERGE_SETTINGS,
            }
            for repository in MODULE.AUTONOMOUS_REPOSITORIES
        }
        self.repository_settings["Mindburn-Labs/.github"]["allow_merge_commit"] = False
        self.repository_settings["Mindburn-Labs/.github"]["delete_branch_on_merge"] = (
            True
        )
        self.protection = raw_protection(
            contract["classic_branch_protection"]["expected"]
        )
        self.review_state = "APPROVED"
        self.review_reads = 0
        self.drift_on_second_review = False
        self.merged = False
        self.puts = 0
        self.posts = 0
        self.kernel_puts = 0
        self.repository_patches = 0
        self.proof_puts = 0
        self.classic_deletes = 0
        self.etag = 'W/"human-v1"'
        self.kernel_etag = 'W/"kernel-v1"'

    def request(self, method: str, path: str, *, payload=None, if_match=None):
        response = MODULE.AdminResponse
        if path.endswith("/pulls/36/reviews/42"):
            self.review_reads += 1
            return response(
                {
                    "id": 42,
                    "state": (
                        "DISMISSED"
                        if self.drift_on_second_review and self.review_reads >= 2
                        else self.review_state
                    ),
                    "commit_id": CANDIDATE_SHA,
                    "body": f"HELM signed ALLOW permit {PERMIT_ID}",
                    "user": {"login": MODULE.APPROVER_LOGIN},
                },
                None,
            )
        if path.endswith("/pulls/36"):
            return response(
                {
                    "number": 36,
                    "state": "closed" if self.merged else "open",
                    "draft": False,
                    "merged": self.merged,
                    "merge_commit_sha": MERGE_SHA,
                    "base": {"ref": "main", "sha": BASE_SHA},
                    "head": {
                        "sha": CANDIDATE_SHA,
                        "repo": {"full_name": "Mindburn-Labs/.github"},
                    },
                },
                None,
            )
        if path.endswith(f"/git/commits/{MERGE_SHA}"):
            return response(
                {
                    "parents": [{"sha": BASE_SHA}, {"sha": CANDIDATE_SHA}],
                    "tree": {"sha": TREE_SHA},
                },
                None,
            )
        if path.endswith(f"rulesets/{MODULE.STABLE_RULESET_ID}"):
            return response(json.loads(json.dumps(self.workflow)), 'W/"workflow"')
        if path.endswith(f"rulesets/{MODULE.KERNEL_QUALITY_RULESET_ID}"):
            if method == "GET":
                return response(
                    json.loads(json.dumps(self.kernel_quality)), self.kernel_etag
                )
            if method == "PUT":
                if if_match != self.kernel_etag:
                    raise MODULE.PermitInputError("stale Kernel ruleset")
                self.kernel_puts += 1
                self.kernel_quality = {
                    "id": MODULE.KERNEL_QUALITY_RULESET_ID,
                    **json.loads(json.dumps(payload)),
                }
                self.kernel_etag = 'W/"kernel-v2"'
                return response(
                    json.loads(json.dumps(self.kernel_quality)), self.kernel_etag
                )
        if path.endswith("rulesets?per_page=100"):
            values = []
            if self.machine is not None:
                values.append(
                    {"id": self.machine["id"], "name": MODULE.MACHINE_RULESET_NAME}
                )
            if self.updater is not None:
                values.append(
                    {"id": self.updater["id"], "name": MODULE.UPDATER_RULESET_NAME}
                )
            if self.proof_ruleset is not None:
                values.append(
                    {
                        "id": self.proof_ruleset["id"],
                        "name": MODULE.PROOF_REF_RULESET_NAME,
                    }
                )
            if self.evidence_updater is not None:
                values.append(
                    {
                        "id": self.evidence_updater["id"],
                        "name": MODULE.EVIDENCE_UPDATER_RULESET_NAME,
                    }
                )
            if self.evidence_history is not None:
                values.append(
                    {
                        "id": self.evidence_history["id"],
                        "name": MODULE.EVIDENCE_HISTORY_RULESET_NAME,
                    }
                )
            return response(values, None)
        if path.endswith("/rulesets") and method == "POST":
            self.posts += 1
            if payload["name"] == MODULE.MACHINE_RULESET_NAME:
                self.machine = {"id": 9001, **json.loads(json.dumps(payload))}
                return response(json.loads(json.dumps(self.machine)), 'W/"machine"')
            if payload["name"] == MODULE.UPDATER_RULESET_NAME:
                self.updater = {"id": 9002, **json.loads(json.dumps(payload))}
                return response(json.loads(json.dumps(self.updater)), 'W/"updater"')
            if payload["name"] == MODULE.PROOF_REF_RULESET_NAME:
                self.proof_ruleset = {"id": 9003, **json.loads(json.dumps(payload))}
                return response(json.loads(json.dumps(self.proof_ruleset)), 'W/"proof"')
            if payload["name"] == MODULE.EVIDENCE_UPDATER_RULESET_NAME:
                self.evidence_updater = {
                    "id": 9004,
                    **json.loads(json.dumps(payload)),
                }
                return response(
                    json.loads(json.dumps(self.evidence_updater)), 'W/"ledger-updater"'
                )
            if payload["name"] == MODULE.EVIDENCE_HISTORY_RULESET_NAME:
                self.evidence_history = {
                    "id": 9005,
                    **json.loads(json.dumps(payload)),
                }
                return response(
                    json.loads(json.dumps(self.evidence_history)), 'W/"ledger-history"'
                )
            raise AssertionError("unexpected ruleset creation")
        if path.endswith("rulesets/9001"):
            return response(json.loads(json.dumps(self.machine)), 'W/"machine"')
        if path.endswith("rulesets/9002"):
            return response(json.loads(json.dumps(self.updater)), 'W/"updater"')
        if path.endswith("rulesets/9003"):
            if method == "PUT":
                if if_match != 'W/"proof"':
                    raise MODULE.PermitInputError("stale proof ruleset")
                self.proof_puts += 1
                self.proof_ruleset = {
                    "id": 9003,
                    **json.loads(json.dumps(payload)),
                }
            return response(json.loads(json.dumps(self.proof_ruleset)), 'W/"proof"')
        if path.endswith("rulesets/9004"):
            return response(
                json.loads(json.dumps(self.evidence_updater)), 'W/"ledger-updater"'
            )
        if path.endswith("rulesets/9005"):
            return response(
                json.loads(json.dumps(self.evidence_history)), 'W/"ledger-history"'
            )
        if path.endswith(f"rulesets/{MODULE.HUMAN_RULESET_ID}"):
            if method == "GET":
                return response(json.loads(json.dumps(self.human)), self.etag)
            if method == "PUT":
                if if_match != self.etag:
                    raise MODULE.PermitInputError("stale")
                self.puts += 1
                self.human = {
                    "id": MODULE.HUMAN_RULESET_ID,
                    **json.loads(json.dumps(payload)),
                }
                self.etag = 'W/"human-v2"'
                return response(json.loads(json.dumps(self.human)), self.etag)
        if path.endswith(
            "/branches/main/protection/required_conversation_resolution"
        ):
            if method != "DELETE" or if_match != 'W/"classic"':
                raise AssertionError((method, path, if_match))
            self.classic_deletes += 1
            self.protection["required_conversation_resolution"] = {"enabled": False}
            return response({}, None)
        if path.endswith("/branches/main/protection"):
            return response(json.loads(json.dumps(self.protection)), 'W/"classic"')
        for repository in MODULE.AUTONOMOUS_REPOSITORIES:
            if path == f"/repos/{repository}":
                if method == "GET":
                    return response(
                        json.loads(json.dumps(self.repository_settings[repository])),
                        None,
                    )
                if method == "PATCH":
                    self.repository_patches += 1
                    self.repository_settings[repository].update(payload)
                    return response(
                        json.loads(json.dumps(self.repository_settings[repository])),
                        None,
                    )
        proof_prefix = (
            "/repos/Mindburn-Labs/contracts-autonomous-release-lab/git/ref/heads/"
        )
        if path.startswith(proof_prefix) and method == "GET":
            ref = "refs/heads/" + path.removeprefix(proof_prefix)
            return response(
                {"ref": ref, "object": {"sha": MODULE.PROOF_REFS[ref]}},
                None,
            )
        if path == (
            "/repos/Mindburn-Labs/.github/git/ref/heads/authority/evidence-v1"
        ):
            return response(
                {"ref": MODULE.LEDGER_REF, "object": {"sha": CANDIDATE_SHA}},
                None,
            )
        raise AssertionError(f"unexpected request {method} {path}")


class ConfigureMachineApprovalGatesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.contract_path = Path(self.tempdir.name) / "bootstrap.json"
        contract = json.loads(
            (ROOT / "config" / "autonomous-release-bootstrap-v1.json").read_text(
                encoding="utf-8"
            )
        )
        contract["merger"].update(
            {
                "enabled": True,
                "app_id": MERGER_APP_ID,
                "installation_id": MERGER_INSTALLATION_ID,
            }
        )
        contract["machine_approval_ruleset"] = MODULE.machine_ruleset_payload()
        contract["exclusive_updater_ruleset"] = MODULE.updater_ruleset_payload(
            MERGER_APP_ID
        )
        contract["evidence_ledger"]["exclusive_updater_ruleset"] = (
            MODULE.evidence_updater_ruleset_payload(MERGER_APP_ID)
        )
        self.contract_path.write_text(json.dumps(contract), encoding="utf-8")
        self.contract = MODULE.load_contract(self.contract_path)
        self.approval_path = Path(self.tempdir.name) / "approval.json"
        self.approval_path.write_text(
            json.dumps(
                {
                    "schema": MODULE.APPROVAL_SCHEMA,
                    "repository": "Mindburn-Labs/.github",
                    "pull_request": 36,
                    "head_sha": CANDIDATE_SHA,
                    "workflow_sha": CANDIDATE_SHA,
                    "permit_id": PERMIT_ID,
                    "base_sha": BASE_SHA,
                    "merge_sha": MERGE_SHA,
                    "merge_tree_sha": TREE_SHA,
                    "review_state": "APPROVED",
                    "approver_login": MODULE.APPROVER_LOGIN,
                    "approver_app_id": MODULE.APPROVER_APP_ID,
                    "approver_installation_id": MODULE.APPROVER_INSTALLATION_ID,
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
            allow_merged_resume=False,
        )

    def test_installs_machine_interlock_before_retiring_codeowner_scope(self) -> None:
        client = FakeClient(self.contract)
        receipt = MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.posts, 5)
        self.assertEqual(client.puts, 1)
        self.assertEqual(client.kernel_puts, 1)
        self.assertEqual(client.proof_puts, 1)
        self.assertEqual(client.repository_patches, 1)
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
        client.kernel_puts = 0
        client.repository_patches = 0
        MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.posts, 0)
        self.assertEqual(client.puts, 0)
        self.assertEqual(client.kernel_puts, 0)
        self.assertEqual(client.repository_patches, 0)

    def test_post_merge_retry_revalidates_exact_graph(self) -> None:
        client = FakeClient(self.contract)
        MODULE.configure_machine_approval_gates(self.args, client)
        client.merged = True
        self.args.allow_merged_resume = True
        receipt = MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(receipt["machine_approval_head_sha"], CANDIDATE_SHA)

    def test_missing_etag_fails_before_human_rule_mutation(self) -> None:
        client = FakeClient(self.contract)
        client.etag = ""
        with self.assertRaisesRegex(MODULE.PermitInputError, "ETag"):
            MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.puts, 0)

    def test_machine_ruleset_drift_blocks_cutover(self) -> None:
        client = FakeClient(self.contract)
        client.machine = {
            "id": 9001,
            **MODULE.machine_ruleset_payload(),
        }
        client.machine["enforcement"] = "evaluate"
        with self.assertRaisesRegex(MODULE.PermitInputError, "not exact and active"):
            MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.puts, 0)

    def test_comment_resolution_gate_is_removed_before_cutover_receipt(self) -> None:
        client = FakeClient(self.contract)
        client.protection["required_conversation_resolution"] = {"enabled": True}
        MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.classic_deletes, 1)
        self.assertFalse(
            MODULE.normalize_classic_protection(client.protection)[
                "required_conversation_resolution"
            ]
        )

    def test_dismissed_approval_blocks_cutover(self) -> None:
        client = FakeClient(self.contract)
        client.review_state = "DISMISSED"
        with self.assertRaisesRegex(MODULE.PermitInputError, "not exact and active"):
            MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.posts, 0)
        self.assertEqual(client.puts, 0)

    def test_post_cutover_approval_drift_blocks_receipt(self) -> None:
        client = FakeClient(self.contract)
        client.drift_on_second_review = True
        with self.assertRaisesRegex(MODULE.PermitInputError, "not exact and active"):
            MODULE.configure_machine_approval_gates(self.args, client)
        self.assertEqual(client.puts, 1)


if __name__ == "__main__":
    unittest.main()
