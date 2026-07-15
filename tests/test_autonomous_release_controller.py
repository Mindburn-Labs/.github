from __future__ import annotations

import argparse
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

    def test_activated_recovery_uses_ledger_chain_and_stops_after_final(self) -> None:
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
                return_value=(recovered_entry, {"phase": "merged"}, None),
            ) as reader,
        ):
            result = MODULE.verified_activated_recovery_entry(
                argparse.Namespace(),
                mock.Mock(),
                authority=authority,
                control_sha=CONTROL_SHA,
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
                ),
            ),
        ):
            self.assertIsNone(
                MODULE.verified_activated_recovery_entry(
                    argparse.Namespace(),
                    mock.Mock(),
                    authority=authority,
                    control_sha=CONTROL_SHA,
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
        promotion_entry["evidence"] = "promotion"
        authority = {"generation": 3}
        intent = {
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
            "control_workflow_sha": CONTROL_SHA,
            "parent_workflow_sha": ACTIVE_SHA,
            "candidate_workflow_sha": HEAD_SHA,
            "merged_workflow_sha": MERGE_SHA,
            "candidate_generation": 3,
            "promotion_run_id": 9100,
            "promotion_run_attempt": 1,
        }
        execution = {
            "schema": "mindburn.release-authority-promotion-execution/v2",
            "parent_generation": 2,
            "candidate_generation": 3,
            "parent_workflow_sha": ACTIVE_SHA,
            "candidate_workflow_sha": HEAD_SHA,
            "merged_workflow_sha": MERGE_SHA,
            "ratification_run_id": 9001,
            "ratification_run_attempt": 1,
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
                "authority-promotion-execution.json": json.dumps(execution).encode(),
                "ruleset-activate.json": json.dumps(activation).encode(),
                "observer-replay-final/recomputed.json": b'{"decision":"ALLOW"}',
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
                    argparse.Namespace(output_dir=Path(temporary)),
                    mock.Mock(token="token"),
                    intent=intent,
                    merged=merged,
                    final=final,
                    entry=promotion_entry,
                    authority=authority,
                    control_sha=CONTROL_SHA,
                    materialization_label="test",
                )
            verify.assert_called_once()
        observer["decision"] = "DENY"
        final["inputs"]["final-observer-receipt.json"] = json.dumps(observer).encode()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(MODULE.PermitInputError, "observer receipt"):
                MODULE.verify_promotion_final(
                    argparse.Namespace(output_dir=Path(temporary)),
                    mock.Mock(token="token"),
                    intent=intent,
                    merged=merged,
                    final=final,
                    entry=promotion_entry,
                    authority=authority,
                    control_sha=CONTROL_SHA,
                    materialization_label="deny",
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
