from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "autonomous_release_controller.py"
SPEC = importlib.util.spec_from_file_location(
    "autonomous_release_controller", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

CONTROL_SHA = "1" * 40
ACTIVE_SHA = "2" * 40
BASE_SHA = "3" * 40
HEAD_SHA = "4" * 40
MERGE_SHA = "5" * 40
TREE_SHA = "6" * 40
PERMIT_ID = "sha256:" + "7" * 64
KERNEL = "Mindburn-Labs/helm-ai-kernel"
EFFECTIVE_KERNEL_RULES = [
    {
        "ruleset_id": 7001,
        "type": "update",
        "ruleset_source_type": "Organization",
        "ruleset_source": "Mindburn-Labs",
    }
]


def enabled_contract() -> dict[str, object]:
    value = json.loads(
        (ROOT / "config" / "autonomous-release-controller.json").read_text(
            encoding="utf-8"
        )
    )
    value["enabled"] = True
    value["apps"]["merger"]["app_id"] = 5000001
    value["apps"]["merger"]["installation_id"] = 6000001
    value["apps"]["control_updater"]["app_id"] = 5000002
    value["apps"]["control_updater"]["installation_id"] = 6000002
    return value


def entry(
    *,
    repository: str = KERNEL,
    workflow_sha: str = ACTIVE_SHA,
    recovery: bool = False,
) -> dict[str, object]:
    return {
        "repository": repository,
        "pull_request": 42,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "merge_sha": MERGE_SHA,
        "merge_tree_sha": TREE_SHA,
        "permit_id": PERMIT_ID,
        "run_id": 9001,
        "run_attempt": 1,
        "workflow_sha": workflow_sha,
        "evidence": "evidence/helm-ai-kernel/42",
        "merge_method": "merge",
        "recovery": recovery,
    }


def plan_value(*, ordinary=None, promotions=None) -> dict[str, object]:
    return {
        "schema": MODULE.PLAN_SCHEMA,
        "controller_sha": CONTROL_SHA,
        "active_workflow_sha": ACTIVE_SHA,
        "observed_at": "2026-07-15T00:00:00Z",
        "merge_interlock": {
            "schema": "mindburn.autonomous-release-merge-interlock/v1",
            "merger_app_id": 5000001,
            "merger_installation_id": 6000001,
            "machine_ruleset_id": 7000,
            "updater_ruleset_id": 7001,
            "kernel_quality_ruleset_id": 7002,
            "proof_ref_ruleset_id": 7003,
            "proof_refs": {},
            "evidence_ledger_ref": "refs/heads/authority/evidence-v1",
            "evidence_ledger_head_sha": "c" * 40,
            "evidence_history_ruleset_id": 7004,
            "evidence_updater_ruleset_id": 7005,
            "evidence_ledger_effective_rules": [],
            "effective_rules": {
                KERNEL: [
                    [
                        rule["ruleset_id"],
                        rule["type"],
                        rule["ruleset_source_type"],
                        rule["ruleset_source"],
                    ]
                    for rule in EFFECTIVE_KERNEL_RULES
                ]
            },
            "repository_settings": {},
            "classic_branch_protection": {},
        },
        "ordinary": ordinary or [],
        "promotions": promotions or [],
        "blocked": [],
    }


class JsonBytesClient:
    def __init__(self, value):
        self.value = value

    def get_bytes(self, _path, *, accept="application/vnd.github+json"):
        del accept
        return json.dumps(self.value).encode("utf-8")


class MergeClient:
    def __init__(self, *, main_sha: str, merged: bool = False) -> None:
        self.main_sha = main_sha
        self.merged = merged
        self.graphql_calls: list[dict[str, object]] = []

    def request(self, method: str, path: str, *, payload=None):
        if path == "/installation":
            return {
                "app_id": 5000001,
                "id": 6000001,
                "permissions": {"contents": "write", "pull_requests": "read"},
                "account": {"login": "Mindburn-Labs"},
            }
        if path == "/installation/repositories?per_page=100":
            return {"repositories": [{"full_name": KERNEL}]}
        if path == f"/repos/{KERNEL}/rules/branches/main":
            return json.loads(json.dumps(EFFECTIVE_KERNEL_RULES))
        if path.endswith("/reviews/101"):
            return {
                "id": 101,
                "state": "APPROVED",
                "commit_id": HEAD_SHA,
                "body": f"HELM signed ALLOW permit {PERMIT_ID}",
                "user": {"login": MODULE.APPROVER_LOGIN},
            }
        if path == f"/repos/{KERNEL}/pulls/42":
            return {
                "number": 42,
                "state": "closed" if self.merged else "open",
                "merged": self.merged,
                "draft": False,
                "merge_commit_sha": MERGE_SHA,
                "base": {"ref": "main", "sha": BASE_SHA},
                "head": {"sha": HEAD_SHA, "repo": {"full_name": KERNEL}},
            }
        if path == f"/repos/{KERNEL}/git/ref/heads/main":
            return {"object": {"sha": self.main_sha}}
        if path == f"/repos/{KERNEL}/git/commits/{MERGE_SHA}":
            return {
                "parents": [{"sha": BASE_SHA}, {"sha": HEAD_SHA}],
                "tree": {"sha": TREE_SHA},
            }
        if path == "/graphql" and method == "POST":
            variables = payload["variables"]
            self.graphql_calls.append(variables)
            if "owner" in variables:
                return {"data": {"repository": {"id": "R_kernel"}}}
            if variables["beforeOid"] != self.main_sha:
                return {"errors": [{"message": "beforeOid mismatch"}]}
            self.main_sha = variables["afterOid"]
            self.merged = True
            return {"data": {"updateRefs": {"clientMutationId": None}}}
        raise AssertionError(f"unexpected request {method} {path}")


class AutonomousReleaseControllerTests(unittest.TestCase):
    def write_json(self, directory: Path, name: str, value: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_disabled_contract_has_no_latent_merger_identity(self) -> None:
        value = json.loads(
            (ROOT / "config" / "autonomous-release-controller.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(MODULE.validate_contract(value)["enabled"])
        value["apps"]["merger"]["app_id"] = 123
        with self.assertRaisesRegex(MODULE.PermitInputError, "must not declare"):
            MODULE.validate_contract(value)

    def test_enabled_contract_requires_distinct_positive_merger_identity(self) -> None:
        value = enabled_contract()
        self.assertTrue(MODULE.validate_contract(value)["enabled"])
        value["apps"]["merger"]["installation_id"] = None
        with self.assertRaisesRegex(MODULE.PermitInputError, "positive integer"):
            MODULE.validate_contract(value)

    def test_bootstrap_verification_uses_original_merge_not_current_control(self) -> None:
        intent = {
            "descriptor": {"manifest_sha256": "8" * 64},
            "manifest": {"workflow_sha": MERGE_SHA, "run_id": 1, "run_attempt": 1},
            "inputs": {"bootstrap.json": b"{}"},
        }
        closure = {
            "descriptor": {"manifest_sha256": "9" * 64},
            "manifest": intent["manifest"],
            "inputs": {
                "intent-descriptor.json": json.dumps(intent["descriptor"]).encode(),
                "atomic-merge.json": json.dumps(
                    {
                        "schema": "mindburn.release-authority-atomic-merge/v1",
                        "repository": MODULE.AUTHORITY_REPOSITORY,
                        "pull_request": 36,
                        "base_sha": BASE_SHA,
                        "head_sha": HEAD_SHA,
                        "merge_sha": MERGE_SHA,
                        "merge_tree_sha": TREE_SHA,
                        "ref": "refs/heads/main",
                        "force": False,
                    }
                ).encode(),
                "final-control-plane.json": b"{}",
                "final-control-plane-observer.json": b"{}",
            },
        }
        final = {
            "descriptor": {"manifest_sha256": "a" * 64},
            "ledger_head_sha": "b" * 40,
            "manifest": intent["manifest"],
            "inputs": {
                "closure-descriptor.json": json.dumps(
                    closure["descriptor"]
                ).encode(),
                "ruleset-finalization.json": json.dumps(
                    {
                        "schema": "mindburn.release-authority-ruleset-transition/v1",
                        "operation": "bootstrap-finalize",
                        "merged_workflow_sha": MERGE_SHA,
                        "stable_ruleset_id": MODULE.STABLE_RULESET_ID,
                    }
                ).encode(),
                "final-control-plane.json": b"{}",
                "final-control-plane-observer.json": b"{}",
            },
        }

        class BootstrapClient:
            def request(self, _method, path):
                if path.endswith("/pulls/36"):
                    body = {
                        "number": 36,
                        "state": "closed",
                        "merged": True,
                        "draft": False,
                        "merge_commit_sha": MERGE_SHA,
                        "base": {"ref": "main", "sha": BASE_SHA},
                        "head": {
                            "sha": HEAD_SHA,
                            "repo": {"full_name": MODULE.AUTHORITY_REPOSITORY},
                        },
                    }
                elif path.endswith(f"/git/commits/{MERGE_SHA}"):
                    body = {
                        "parents": [{"sha": BASE_SHA}, {"sha": HEAD_SHA}],
                        "tree": {"sha": TREE_SHA},
                    }
                else:
                    raise AssertionError(path)
                return mock.Mock(body=body)

        records = {"intent": intent, "closure": closure, "final": final}

        def read(_client, *, namespace, record_type, phase):
            self.assertEqual(record_type, "bootstrap")
            self.assertIn(f"bootstrap/pr-36/{MERGE_SHA}/", namespace)
            return records[phase]

        with mock.patch.object(MODULE, "read_record", side_effect=read):
            receipt = MODULE.verify_bootstrap_final(
                argparse.Namespace(
                    contract=ROOT / "config" / "autonomous-release-controller.json",
                    control_sha=CONTROL_SHA,
                ),
                BootstrapClient(),
            )
        self.assertEqual(receipt["bootstrap_sha"], MERGE_SHA)
        self.assertEqual(receipt["control_sha"], CONTROL_SHA)

    def test_kernel_transition_requires_parent_closed_ordinary_merge(self) -> None:
        class KernelClient:
            def get_json(self, path):
                if path.endswith("/git/ref/heads/main"):
                    return {"object": {"sha": MERGE_SHA}}
                raise AssertionError(path)

        closed = entry(workflow_sha=ACTIVE_SHA)
        closed["repository"] = KERNEL
        closed["recovery"] = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self.write_json(root, "contract.json", enabled_contract())
            args = argparse.Namespace(
                contract=contract,
                control_sha=ACTIVE_SHA,
                parent_workflow_sha=ACTIVE_SHA,
                parent_kernel_sha=BASE_SHA,
                candidate_kernel_sha=MERGE_SHA,
                kernel_verifier=root / "parent-verifier",
                output_dir=root / "evidence",
            )
            with (
                mock.patch.object(
                    MODULE,
                    "head_authority",
                    return_value={"kernel_sha": BASE_SHA},
                ),
                mock.patch.object(
                    MODULE,
                    "recover_ordinary_from_ledger",
                    return_value=closed,
                ) as verify_closed,
            ):
                receipt = MODULE.verify_kernel_transition(args, KernelClient())
            self.assertEqual(receipt["mode"], "upgrade")
            self.assertEqual(receipt["ordinary_merge"]["merge_sha"], MERGE_SHA)
            self.assertTrue(verify_closed.call_args.kwargs["return_closed"])

            with (
                mock.patch.object(
                    MODULE,
                    "head_authority",
                    return_value={"kernel_sha": BASE_SHA},
                ),
                mock.patch.object(
                    MODULE, "recover_ordinary_from_ledger", return_value=None
                ),
                self.assertRaisesRegex(MODULE.PermitInputError, "durable ordinary"),
            ):
                MODULE.verify_kernel_transition(args, KernelClient())

    def test_plan_separates_immutable_control_from_active_workflow(self) -> None:
        value = plan_value(ordinary=[entry()])
        self.assertEqual(
            MODULE.validate_plan(value, control_sha=CONTROL_SHA)["active_workflow_sha"],
            ACTIVE_SHA,
        )
        value["controller_sha"] = ACTIVE_SHA
        with self.assertRaisesRegex(MODULE.PermitInputError, "not issued"):
            MODULE.validate_plan(value, control_sha=CONTROL_SHA)

    def test_only_recovery_promotion_may_name_the_parent_authority(self) -> None:
        parent = "8" * 40
        recovery = plan_value(
            promotions=[
                entry(
                    repository=MODULE.AUTHORITY_REPOSITORY,
                    workflow_sha=parent,
                    recovery=True,
                )
            ]
        )
        MODULE.validate_plan(recovery, control_sha=CONTROL_SHA)
        recovery["promotions"][0]["recovery"] = False
        with self.assertRaisesRegex(MODULE.PermitInputError, "forward promotion"):
            MODULE.validate_plan(recovery, control_sha=CONTROL_SHA)

    def test_signed_plan_cannot_mix_ordinary_and_promotion_actions(self) -> None:
        value = plan_value(
            ordinary=[entry()],
            promotions=[entry(repository=MODULE.AUTHORITY_REPOSITORY)],
        )
        with self.assertRaisesRegex(MODULE.PermitInputError, "fixed serialization"):
            MODULE.validate_plan(value, control_sha=CONTROL_SHA)

    def test_generation_two_closure_is_bound_to_bootstrap_control_sha(self) -> None:
        authority = {"generation": 2}
        self.assertTrue(
            MODULE.has_final_promotion_closure(
                mock.Mock(),
                mock.Mock(),
                authority=authority,
                control_sha=CONTROL_SHA,
                active_workflow_sha=CONTROL_SHA,
            )
        )
        self.assertFalse(
            MODULE.has_final_promotion_closure(
                mock.Mock(),
                mock.Mock(),
                authority=authority,
                control_sha=CONTROL_SHA,
                active_workflow_sha=ACTIVE_SHA,
            )
        )

    def test_activated_recovery_stops_only_after_successor_closure(self) -> None:
        authority = {
            "generation": 3,
            "parent": {"generation": 2, "workflow_sha": ACTIVE_SHA},
        }
        recovered_entry = entry(
            repository=MODULE.AUTHORITY_REPOSITORY,
            workflow_sha=ACTIVE_SHA,
        )
        recovered_entry["evidence"] = "promotion"
        repository_config = {"merge_method": "merge"}
        with (
            mock.patch.object(MODULE, "head_authority", return_value={"generation": 2}),
            mock.patch.object(
                MODULE,
                "read_verified_promotion_chain",
                return_value=(recovered_entry, {"phase": "merged"}, None, None),
            ) as reader,
        ):
            result = MODULE.verified_activated_recovery_entry(
                argparse.Namespace(),
                mock.Mock(),
                authority=authority,
                control_sha=ACTIVE_SHA,
                active_workflow_sha=MERGE_SHA,
                repository_config=repository_config,
            )
        self.assertTrue(result["recovery"])
        reader.assert_called_once()

        with (
            mock.patch.object(MODULE, "head_authority", return_value={"generation": 2}),
            mock.patch.object(
                MODULE,
                "read_verified_promotion_chain",
                return_value=(
                    recovered_entry,
                    {"phase": "merged"},
                    {"phase": "final"},
                    {"phase": "successor"},
                ),
            ),
        ):
            self.assertIsNone(
                MODULE.verified_activated_recovery_entry(
                    argparse.Namespace(),
                    mock.Mock(),
                    authority=authority,
                    control_sha=ACTIVE_SHA,
                    active_workflow_sha=MERGE_SHA,
                    repository_config=repository_config,
                )
            )

    def test_promotion_merged_phase_binds_intent_approval_and_atomic_merge(
        self,
    ) -> None:
        promotion_entry = entry(
            repository=MODULE.AUTHORITY_REPOSITORY,
            workflow_sha=ACTIVE_SHA,
        )
        promotion_entry["base_sha"] = ACTIVE_SHA
        promotion_entry["evidence"] = "promotion"
        approval = {
            "schema": "mindburn.release-authority-machine-approval/v2",
            "repository": MODULE.AUTHORITY_REPOSITORY,
            "pull_request": promotion_entry["pull_request"],
            "head_sha": promotion_entry["head_sha"],
            "workflow_sha": promotion_entry["workflow_sha"],
            "permit_id": promotion_entry["permit_id"],
            "base_sha": promotion_entry["base_sha"],
            "merge_sha": promotion_entry["merge_sha"],
            "merge_tree_sha": promotion_entry["merge_tree_sha"],
            "review_id": 101,
            "review_state": "APPROVED",
            "approver_login": MODULE.APPROVER_LOGIN,
            "approver_app_id": MODULE.APPROVER_APP_ID,
            "approver_installation_id": MODULE.APPROVER_INSTALLATION_ID,
        }
        merge_response = {
            "schema": "mindburn.release-authority-atomic-merge/v1",
            "repository": MODULE.AUTHORITY_REPOSITORY,
            "pull_request": promotion_entry["pull_request"],
            "base_sha": promotion_entry["base_sha"],
            "head_sha": promotion_entry["head_sha"],
            "merge_sha": promotion_entry["merge_sha"],
            "merge_tree_sha": promotion_entry["merge_tree_sha"],
            "ref": MODULE.MAIN_REF,
            "force": False,
        }
        intent = {
            "descriptor": {"manifest_sha256": "8" * 64},
            "manifest": {
                "workflow_sha": ACTIVE_SHA,
                "run_id": 9001,
                "run_attempt": 1,
            },
        }
        merged = {
            "inputs": {
                "intent-descriptor.json": json.dumps(intent["descriptor"]).encode(),
                "approval.json": json.dumps(approval).encode(),
                "merge-response.json": json.dumps(merge_response).encode(),
            },
            "manifest": {
                "namespace": f"promotions/generation-3/{MERGE_SHA}/merged",
                "workflow_sha": ACTIVE_SHA,
                "run_id": 9001,
                "run_attempt": 1,
            },
        }
        client = mock.Mock()
        client.get_json.return_value = {
            "state": "APPROVED",
            "commit_id": HEAD_SHA,
            "body": f"HELM signed ALLOW permit {PERMIT_ID}",
            "user": {"login": MODULE.APPROVER_LOGIN},
        }
        MODULE.verify_promotion_merged(
            client,
            intent=intent,
            merged=merged,
            entry=promotion_entry,
            generation=3,
        )
        merge_response["force"] = True
        merged["inputs"]["merge-response.json"] = json.dumps(merge_response).encode()
        with self.assertRaisesRegex(MODULE.PermitInputError, "merge response"):
            MODULE.verify_promotion_merged(
                client,
                intent=intent,
                merged=merged,
                entry=promotion_entry,
                generation=3,
            )

    def test_promotion_final_phase_requires_signed_observer_and_activation_chain(
        self,
    ) -> None:
        promotion_entry = entry(
            repository=MODULE.AUTHORITY_REPOSITORY,
            workflow_sha=ACTIVE_SHA,
        )
        promotion_entry["base_sha"] = ACTIVE_SHA
        promotion_entry["evidence"] = "promotion"
        kernel_sha = "d" * 40
        parent_authority = {"generation": 2, "kernel_sha": kernel_sha}
        authority = {"generation": 3, "kernel_sha": kernel_sha}
        kernel_transition = {
            "schema": MODULE.KERNEL_TRANSITION_SCHEMA,
            "mode": "unchanged",
            "control_workflow_sha": ACTIVE_SHA,
            "parent_workflow_sha": ACTIVE_SHA,
            "parent_kernel_sha": kernel_sha,
            "candidate_kernel_sha": kernel_sha,
            "ordinary_merge": None,
        }
        kernel_transition_bytes = json.dumps(kernel_transition).encode()
        promotion_receipt = {
            "kernel_transition_sha256": hashlib.sha256(
                kernel_transition_bytes
            ).hexdigest()
        }
        intent = {
            "inputs": {
                "promotion/authority-promotion.json": json.dumps(
                    promotion_receipt
                ).encode(),
                "promotion/kernel-transition.json": kernel_transition_bytes,
                "promotion/parent-authority.json": json.dumps(
                    parent_authority
                ).encode(),
            },
            "manifest": {
                "workflow_sha": ACTIVE_SHA,
                "run_id": 9001,
                "run_attempt": 1,
            }
        }
        merged = {"descriptor": {"manifest_sha256": "8" * 64}}
        observer = {
            "schema": MODULE.PROMOTION_RECEIPT_SCHEMA,
            "phase": "final",
            "decision": "ALLOW",
            "control_workflow_sha": ACTIVE_SHA,
            "parent_workflow_sha": ACTIVE_SHA,
            "candidate_workflow_sha": HEAD_SHA,
            "merged_workflow_sha": MERGE_SHA,
            "merged_tree_sha": TREE_SHA,
            "ratification_permit_id": PERMIT_ID,
            "canary_permit_id": "sha256:" + "9" * 64,
            "promotion_run_id": 9100,
            "promotion_run_attempt": 1,
        }
        control = json.loads(
            (ROOT / "config" / "autonomous-release-control-plane.json").read_text(
                encoding="utf-8"
            )
        )
        expected_cases = control["adversarial_suite"]["cases"]
        suite = {
            "schema": "mindburn.release-authority-suite/v1",
            "repository": "Mindburn-Labs/contracts-autonomous-release-lab",
            "workflow_sha": HEAD_SHA,
            "cases": [
                {
                    "id": case["id"],
                    "expected": case["expected"],
                    "run_id": 9200 + index,
                    "run_attempt": 1,
                    "permit_id": "sha256:" + f"{index + 1:x}" * 64,
                    "merge_sha": "a" * 40,
                    "merge_tree_sha": "b" * 40,
                }
                for index, case in enumerate(expected_cases)
            ],
        }
        suite_bytes = json.dumps(suite).encode()
        suite_digest = hashlib.sha256(suite_bytes).hexdigest()
        observer["authority_suite_sha256"] = suite_digest
        pre_observer = {**observer, "phase": "pre-activation"}
        trigger = {
            "schema": "mindburn.release-authority-suite-trigger/v1",
            "repository": suite["repository"],
            "workflow_sha": HEAD_SHA,
            "started_at": "2026-07-15T00:00:00Z",
            "cases": expected_cases,
        }
        execution = {
            "schema": "mindburn.release-authority-promotion-execution/v2",
            "parent_generation": 2,
            "candidate_generation": 3,
            "parent_base_sha": ACTIVE_SHA,
            "parent_workflow_sha": ACTIVE_SHA,
            "control_workflow_sha": ACTIVE_SHA,
            "candidate_workflow_sha": HEAD_SHA,
            "candidate_workflow_ref": "refs/heads/codex/successor",
            "candidate_tree_sha": TREE_SHA,
            "candidate_pull_request": 42,
            "merged_workflow_sha": MERGE_SHA,
            "merged_tree_sha": TREE_SHA,
            "ratification_permit_id": PERMIT_ID,
            "ratification_run_id": 9001,
            "ratification_run_attempt": 1,
            "canary_run_id": 9200,
            "canary_run_attempt": 1,
            "canary_permit_id": "sha256:" + "9" * 64,
            "authority_suite_sha256": suite_digest,
        }
        activation = {
            "schema": "mindburn.release-authority-ruleset-transition/v1",
            "operation": "activate",
            "parent_workflow_sha": ACTIVE_SHA,
            "candidate_workflow_sha": HEAD_SHA,
            "merged_workflow_sha": MERGE_SHA,
        }
        final = {
            "inputs": {
                "merged-descriptor.json": json.dumps(merged["descriptor"]).encode(),
                "final-observer-receipt.json": json.dumps(observer).encode(),
                "final-observer-receipt.attestation.json": b'{"bundle":true}',
                "pre-activation-observer-receipt.json": json.dumps(
                    pre_observer
                ).encode(),
                "pre-activation-observer-receipt.attestation.json": b'{"bundle":true}',
                "authority-promotion-execution.json": json.dumps(execution).encode(),
                "authority-suite.json": suite_bytes,
                "suite-trigger.json": json.dumps(trigger).encode(),
                "kernel-transition.json": kernel_transition_bytes,
                "ruleset-activate.json": json.dumps(activation).encode(),
                "observer-replay-final/recomputed.json": b'{"decision":"ALLOW"}',
                **{
                    f"suite/cases/{case['id']}/receipt.json": json.dumps(
                        suite["cases"][index]
                    ).encode()
                    for index, case in enumerate(expected_cases)
                },
                **{
                    f"suite/cases/{case['id']}/{name}-kernel-permit.json": b'{"decision":"ALLOW"}'
                    for case in expected_cases
                    if case["expected"] != "PRE_MODEL_REJECT"
                    for name in ("parent", "candidate")
                },
            },
            "manifest": {
                "namespace": f"promotions/generation-3/{MERGE_SHA}/final",
                "workflow_sha": ACTIVE_SHA,
                "run_id": 9001,
                "run_attempt": 1,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(MODULE, "verify_attestation") as verify:
                MODULE.verify_promotion_final(
                    argparse.Namespace(
                        output_dir=Path(temporary),
                        contract=ROOT / "config" / "autonomous-release-controller.json",
                    ),
                    mock.Mock(token="token"),
                    intent=intent,
                    merged=merged,
                    final=final,
                    entry=promotion_entry,
                    authority=authority,
                    materialization_label="test",
                )
            self.assertEqual(verify.call_count, 2)
        observer["decision"] = "DENY"
        final["inputs"]["final-observer-receipt.json"] = json.dumps(observer).encode()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(MODULE.PermitInputError, "observer receipt"):
                MODULE.verify_promotion_final(
                    argparse.Namespace(
                        output_dir=Path(temporary),
                        contract=ROOT / "config" / "autonomous-release-controller.json",
                    ),
                    mock.Mock(token="token"),
                    intent=intent,
                    merged=merged,
                    final=final,
                    entry=promotion_entry,
                    authority=authority,
                    materialization_label="deny",
                )

        observer["decision"] = "ALLOW"
        observer["ratification_permit_id"] = "sha256:" + "a" * 64
        final["inputs"]["final-observer-receipt.json"] = json.dumps(observer).encode()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(MODULE.PermitInputError, "observer receipt"):
                MODULE.verify_promotion_final(
                    argparse.Namespace(
                        output_dir=Path(temporary),
                        contract=ROOT / "config" / "autonomous-release-controller.json",
                    ),
                    mock.Mock(token="token"),
                    intent=intent,
                    merged=merged,
                    final=final,
                    entry=promotion_entry,
                    authority=authority,
                    materialization_label="spliced-permit",
                )

        observer["ratification_permit_id"] = PERMIT_ID
        final["inputs"]["final-observer-receipt.json"] = json.dumps(observer).encode()
        execution["candidate_pull_request"] = 43
        final["inputs"]["authority-promotion-execution.json"] = json.dumps(
            execution
        ).encode()
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(MODULE, "verify_attestation"):
                with self.assertRaisesRegex(
                    MODULE.PermitInputError, "promotion execution identity"
                ):
                    MODULE.verify_promotion_final(
                    argparse.Namespace(
                        output_dir=Path(temporary),
                        contract=ROOT / "config" / "autonomous-release-controller.json",
                    ),
                        mock.Mock(token="token"),
                        intent=intent,
                        merged=merged,
                        final=final,
                        entry=promotion_entry,
                        authority=authority,
                        materialization_label="spliced-execution",
                    )

    def test_promotion_successor_binds_durable_final_and_live_control(self) -> None:
        promotion_entry = entry(
            repository=MODULE.AUTHORITY_REPOSITORY,
            workflow_sha=ACTIVE_SHA,
        )
        promotion_entry["base_sha"] = ACTIVE_SHA
        authority = {"generation": 3}
        final = {"descriptor": {"manifest_sha256": "8" * 64}}
        parent_controller = enabled_contract()
        parent_control = json.loads(
            (ROOT / "config" / "autonomous-release-control-plane.json").read_text(
                encoding="utf-8"
            )
        )
        updater = parent_controller["apps"]["control_updater"]
        parent_control["control_workflow"]["successor_app"] = updater
        parent_control["control_workflow"]["successor_ruleset"]["bypass_actors"] = [
            {
                "actor_id": updater["app_id"],
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ]
        parent_control_bytes = (
            json.dumps(parent_control, indent=2, sort_keys=True) + "\n"
        ).encode()
        observer = {
            "schema": MODULE.CONTROL_OBSERVER_SCHEMA,
            "contract_sha256": hashlib.sha256(parent_control_bytes).hexdigest(),
            "live": True,
            "repository_settings": parent_control["repository_settings"],
            "control_workflow": {
                "branch": MODULE.CONTROL_BRANCH,
                "ref": MODULE.CONTROL_REF,
                "sha": MERGE_SHA,
                "workflow_path": MODULE.CONTROL_WORKFLOW_PATH,
                "workflow_blob_sha": "9" * 40,
                "ruleset": {
                    "history": {
                        "id": 101,
                        **parent_control["control_workflow"]["ruleset"],
                    },
                    "successor": {
                        "id": 102,
                        **parent_control["control_workflow"]["successor_ruleset"],
                    },
                },
                "active_rules": [],
            },
            "control_ruleset": {},
            "environments": parent_control["environments"],
            "suite_cases": len(parent_control["adversarial_suite"]["cases"]),
        }
        transition = {
            "schema": MODULE.CONTROL_SUCCESSOR_SCHEMA,
            "repository": MODULE.AUTHORITY_REPOSITORY,
            "ruleset": MODULE.CONTROL_SUCCESSOR_RULESET_NAME,
            "ref": MODULE.CONTROL_REF,
            "before_sha": ACTIVE_SHA,
            "after_sha": MERGE_SHA,
            "force": False,
            "state": "advanced",
            "candidate_generation": 3,
            "candidate_pull_request": 42,
            "ratification_permit_id": PERMIT_ID,
            "final_descriptor": final["descriptor"],
            "updater_app_id": updater["app_id"],
            "updater_installation_id": updater["installation_id"],
        }
        successor = {
            "inputs": {
                "final-descriptor.json": json.dumps(final["descriptor"]).encode(),
                "control-transition.json": json.dumps(transition).encode(),
                "control-observer.json": json.dumps(observer).encode(),
                "control-observer.attestation.json": b'{"bundle":true}',
            },
            "manifest": {
                "namespace": f"promotions/generation-3/{MERGE_SHA}/successor",
                "workflow_sha": ACTIVE_SHA,
                "run_id": 9300,
                "run_attempt": 1,
            },
        }

        class ParentSourceClient:
            token = "token"

            def get_bytes(self, path, *, accept="application/vnd.github+json"):
                del accept
                if "autonomous-release-controller.json" in path:
                    return json.dumps(parent_controller).encode()
                if "autonomous-release-control-plane.json" in path:
                    return parent_control_bytes
                raise AssertionError(path)

        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(MODULE, "verify_attestation") as verify:
                MODULE.verify_promotion_successor(
                    argparse.Namespace(output_dir=Path(temporary)),
                    ParentSourceClient(),
                    final=final,
                    successor=successor,
                    entry=promotion_entry,
                    authority=authority,
                    control_sha=MERGE_SHA,
                    materialization_label="test",
                )
            verify.assert_called_once()

        successor["manifest"]["workflow_sha"] = MERGE_SHA
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                MODULE.PermitInputError, "cannot authorize control advance"
            ):
                MODULE.verify_promotion_successor(
                    argparse.Namespace(output_dir=Path(temporary)),
                    ParentSourceClient(),
                    final=final,
                    successor=successor,
                    entry=promotion_entry,
                    authority=authority,
                    control_sha=MERGE_SHA,
                    materialization_label="successor-signed-advance",
                )

    def test_renames_bind_both_old_and_new_authority_paths(self) -> None:
        client = JsonBytesClient(
            [
                {
                    "filename": "docs/inert.md",
                    "previous_filename": ".github/workflows/ci.yml",
                    "status": "renamed",
                }
            ]
        )
        paths = MODULE.changed_paths(client, MODULE.AUTHORITY_REPOSITORY, 36)
        self.assertEqual(paths, ["docs/inert.md", ".github/workflows/ci.yml"])
        self.assertTrue(MODULE.is_authority_path(paths[1]))

    def test_all_github_prs_are_serialized_as_authority_promotions(self) -> None:
        parent_authority = {
            "schema": "mindburn.release-authority/v1",
            "generation": 2,
            "parent": {"generation": 1, "workflow_sha": "9" * 40},
            "kernel_sha": "a" * 40,
            "gate_profiles_sha256": "b" * 64,
            "adversarial_corpus_sha256": "c" * 64,
        }
        candidate_authority = {
            **parent_authority,
            "generation": 3,
            "parent": {"generation": 2, "workflow_sha": CONTROL_SHA},
        }
        pull_request = {
            "number": 42,
            "state": "open",
            "merged": False,
            "draft": False,
            "base": {"ref": "main", "sha": BASE_SHA},
            "head": {
                "sha": HEAD_SHA,
                "repo": {"full_name": MODULE.AUTHORITY_REPOSITORY},
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            contract = self.write_json(directory, "contract.json", enabled_contract())
            authority = self.write_json(directory, "authority.json", parent_authority)
            args = argparse.Namespace(
                contract=contract,
                authority=authority,
                kernel_verifier=directory / "verifier",
                control_sha=CONTROL_SHA,
                active_workflow_sha=CONTROL_SHA,
                observer_app_slug="helm-authority-observer",
                observer_installation_id=146542079,
                output_dir=directory / "plan",
            )

            def heads(_client, *, head_sha):
                return candidate_authority if head_sha == HEAD_SHA else parent_authority

            with (
                mock.patch.object(MODULE, "verify_observer_installation"),
                mock.patch.object(
                    MODULE, "discover_effective_workflow_sha", return_value=CONTROL_SHA
                ),
                mock.patch.object(MODULE, "observe_effective_stable_rules"),
                mock.patch.object(
                    MODULE,
                    "observe_merge_interlock",
                    return_value=plan_value()["merge_interlock"],
                ),
                mock.patch.object(MODULE, "head_authority", side_effect=heads),
                mock.patch.object(MODULE, "verify_repository_settings"),
                mock.patch.object(
                    MODULE,
                    "open_pull_requests",
                    side_effect=lambda _client, repository: (
                        [pull_request]
                        if repository == MODULE.AUTHORITY_REPOSITORY
                        else []
                    ),
                ),
                mock.patch.object(
                    MODULE,
                    "newest_run",
                    return_value=({"id": 9001, "run_attempt": 1}, None),
                ),
                mock.patch.object(
                    MODULE,
                    "verified_plan_entry",
                    return_value=entry(
                        repository=MODULE.AUTHORITY_REPOSITORY,
                        workflow_sha=CONTROL_SHA,
                    ),
                ),
                mock.patch.object(MODULE, "changed_paths", return_value=["README.md"]),
                mock.patch.object(
                    MODULE, "recover_merged_authority_promotion", return_value=None
                ),
            ):
                result = MODULE.plan(args, mock.Mock())
        self.assertEqual(result["ordinary"], [])
        self.assertEqual(
            [item["repository"] for item in result["promotions"]],
            [MODULE.AUTHORITY_REPOSITORY],
        )

    def merge_args(self, directory: Path) -> argparse.Namespace:
        contract = self.write_json(directory, "contract.json", enabled_contract())
        plan = self.write_json(directory, "plan.json", plan_value(ordinary=[entry()]))
        approvals = self.write_json(
            directory,
            "approvals.json",
            {
                "schema": MODULE.APPROVAL_SCHEMA,
                "controller_sha": CONTROL_SHA,
                "repository": KERNEL,
                "approvals": [
                    {
                        "schema": "mindburn.release-authority-machine-approval/v2",
                        "repository": KERNEL,
                        "pull_request": 42,
                        "head_sha": HEAD_SHA,
                        "workflow_sha": ACTIVE_SHA,
                        "permit_id": PERMIT_ID,
                        "base_sha": BASE_SHA,
                        "merge_sha": MERGE_SHA,
                        "merge_tree_sha": TREE_SHA,
                        "review_id": 101,
                        "review_state": "APPROVED",
                        "approver_login": MODULE.APPROVER_LOGIN,
                        "approver_app_id": MODULE.APPROVER_APP_ID,
                        "approver_installation_id": MODULE.APPROVER_INSTALLATION_ID,
                    }
                ],
            },
        )
        return argparse.Namespace(
            contract=contract,
            plan=plan,
            approvals=approvals,
            control_sha=CONTROL_SHA,
            repository=KERNEL,
            merger_app_slug="helm-authority-merger",
            merger_installation_id=6000001,
        )

    def test_merge_uses_atomic_before_oid_and_exact_reviewed_merge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.merge_args(Path(temporary))
            client = MergeClient(main_sha=BASE_SHA)
            with (
                mock.patch.object(MODULE, "GitHubApprovalClient", return_value=client),
                mock.patch.dict(os.environ, {"GH_TOKEN": "merger"}),
            ):
                receipt = MODULE.merge(args)
        self.assertEqual(client.graphql_calls[-1]["beforeOid"], BASE_SHA)
        self.assertEqual(client.graphql_calls[-1]["afterOid"], MERGE_SHA)
        self.assertIn("force: false", MODULE.UPDATE_REFS_MUTATION)
        self.assertFalse(receipt["merges"][0]["resumed"])

    def test_merge_resumes_without_a_second_ref_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.merge_args(Path(temporary))
            client = MergeClient(main_sha=MERGE_SHA, merged=True)
            with (
                mock.patch.object(MODULE, "GitHubApprovalClient", return_value=client),
                mock.patch.dict(os.environ, {"GH_TOKEN": "merger"}),
            ):
                receipt = MODULE.merge(args)
        self.assertEqual(client.graphql_calls, [])
        self.assertTrue(receipt["merges"][0]["resumed"])

    def test_merge_rejects_base_race_before_graphql(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.merge_args(Path(temporary))
            client = MergeClient(main_sha="f" * 40)
            with (
                mock.patch.object(MODULE, "GitHubApprovalClient", return_value=client),
                mock.patch.dict(os.environ, {"GH_TOKEN": "merger"}),
                self.assertRaisesRegex(MODULE.PermitInputError, "main moved"),
            ):
                MODULE.merge(args)
        self.assertEqual(client.graphql_calls, [])


if __name__ == "__main__":
    unittest.main()
