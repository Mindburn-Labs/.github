from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_control_plane.py"
SPEC = importlib.util.spec_from_file_location("verify_control_plane", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)


class FakeClient:
    def __init__(
        self,
        *,
        add_reviewer: bool = False,
        deployment_disabled: bool = False,
        disabled_environments: set[str] | None = None,
        ruleset_bypass: bool = False,
    ) -> None:
        self.add_reviewer = add_reviewer
        self.deployment_disabled = deployment_disabled
        self.disabled_environments = disabled_environments or set()
        self.ruleset_bypass = ruleset_bypass

    def get_json(self, path: str):
        if path == "/repos/Mindburn-Labs/.github":
            return {"delete_branch_on_merge": False}
        if path in {
            "/orgs/Mindburn-Labs/rulesets/4242",
            "/orgs/Mindburn-Labs/rulesets/4243",
        }:
            ruleset = (
                MODULE.expected_control_ruleset()
                if path.endswith("/4242")
                else MODULE.expected_control_successor_ruleset()
            )
            if self.ruleset_bypass:
                ruleset = {
                    **ruleset,
                    "bypass_actors": [
                        {"actor_id": 1, "actor_type": "OrganizationAdmin"}
                    ],
                }
            return {"id": 4242, **ruleset}
        if path.endswith("/git/ref/heads/authority/control-v1"):
            return {"object": {"sha": "a" * 40}}
        if "/branches/authority%2Fcontrol-v1" in path:
            return {"protected": True, "commit": {"sha": "a" * 40}}
        if "/contents/.github/workflows/promote-authority.yml" in path:
            return {
                "type": "file",
                "path": ".github/workflows/promote-authority.yml",
                "sha": "b" * 40,
            }
        if path.endswith("/deployment-branch-policies"):
            environment = path.split("/environments/", 1)[1].split("/", 1)[0]
            branch_policies = (
                []
                if self.deployment_disabled or environment in self.disabled_environments
                else [{"name": "authority/control-v1", "type": "branch"}]
            )
            return {
                "total_count": len(branch_policies),
                "branch_policies": branch_policies,
            }
        rules = [{"type": "branch_policy", "id": 1}]
        if self.add_reviewer:
            rules.append({"type": "required_reviewers", "reviewers": [{"id": 7}]})
        return {
            "can_admins_bypass": False,
            "protection_rules": rules,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }

    def get_bytes(self, path: str) -> bytes:
        if path == "/orgs/Mindburn-Labs/rulesets?per_page=100":
            return json.dumps(
                [
                    {"id": 4242, "name": MODULE.CONTROL_RULESET_NAME},
                    {
                        "id": 4243,
                        "name": MODULE.CONTROL_SUCCESSOR_RULESET_NAME,
                    },
                ]
            ).encode()
        if path.endswith("/rules/branches/authority%2Fcontrol-v1"):
            return json.dumps(
                [
                    {"type": "creation"},
                    {"type": "deletion"},
                    {"type": "non_fast_forward"},
                    {
                        "type": "update",
                        "parameters": {"update_allows_fetch_and_merge": False},
                    },
                ]
            ).encode()
        raise AssertionError(f"unexpected bytes path: {path}")


class ControlPlaneTests(unittest.TestCase):
    def load_contract(self):
        return MODULE.load_json(
            ROOT / "config" / "autonomous-release-control-plane.json",
            label="control contract",
        )

    def load_corpus(self):
        return MODULE.load_json(
            ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
            label="adversarial corpus",
        )

    def test_source_contract_covers_exact_environments_and_suite(self) -> None:
        contract = MODULE.validate_contract(self.load_contract(), self.load_corpus())
        self.assertEqual(
            {environment["name"] for environment in contract["environments"]},
            {
                "authority-observer",
                "authority-approval",
                "authority-merge",
                "authority-promotion",
                "authority-control",
            },
        )
        self.assertEqual(len(contract["adversarial_suite"]["cases"]), 8)
        self.assertEqual(
            contract["repository_settings"],
            {"delete_branch_on_merge": False},
        )
        self.assertEqual(
            contract["control_workflow"]["ref"],
            "refs/heads/authority/control-v1",
        )
        self.assertEqual(
            contract["control_workflow"]["successor_app"],
            {
                "app_id": None,
                "installation_id": None,
                "slug": "helm-authority-control-updater",
            },
        )

    def test_control_ruleset_admits_only_the_exact_successor_app(self) -> None:
        contract = self.load_contract()
        contract["control_workflow"]["successor_app"]["app_id"] = 4299000
        contract["control_workflow"]["successor_app"]["installation_id"] = 146590000
        contract["control_workflow"]["successor_ruleset"] = (
            MODULE.expected_control_successor_ruleset(4299000)
        )
        validated = MODULE.validate_contract(contract, self.load_corpus())
        self.assertEqual(
            validated["control_workflow"]["successor_ruleset"]["bypass_actors"],
            [
                {
                    "actor_id": 4299000,
                    "actor_type": "Integration",
                    "bypass_mode": "always",
                }
            ],
        )
        contract["control_workflow"]["successor_ruleset"]["bypass_actors"][0][
            "actor_id"
        ] = 4299001
        with self.assertRaisesRegex(
            MODULE.PermitInputError, "successor ruleset is not exact"
        ):
            MODULE.validate_contract(contract, self.load_corpus())

    def test_live_repository_settings_preserve_recovery_head_ref(self) -> None:
        contract = MODULE.validate_contract(self.load_contract(), self.load_corpus())
        self.assertEqual(
            MODULE.verify_live_repository_settings(contract, FakeClient()),
            {"delete_branch_on_merge": False},
        )

        class Drifted(FakeClient):
            def get_json(self, path: str):
                if path == "/repos/Mindburn-Labs/.github":
                    return {"delete_branch_on_merge": True}
                return super().get_json(path)

        with self.assertRaisesRegex(MODULE.PermitInputError, "settings drifted"):
            MODULE.verify_live_repository_settings(contract, Drifted())

    def test_live_environment_verification_rejects_human_reviewer_drift(self) -> None:
        contract = MODULE.validate_contract(self.load_contract(), self.load_corpus())
        with self.assertRaisesRegex(
            MODULE.PermitInputError, "protection rules drifted"
        ):
            MODULE.verify_live_environments(contract, FakeClient(add_reviewer=True))

    def test_live_environment_verification_accepts_exact_state(self) -> None:
        contract = MODULE.validate_contract(self.load_contract(), self.load_corpus())
        receipts = MODULE.verify_live_environments(contract, FakeClient())
        self.assertEqual(len(receipts), 5)

    def test_disabled_environments_admit_no_branch_during_bootstrap(self) -> None:
        contract = MODULE.validate_contract(self.load_contract(), self.load_corpus())
        receipts = MODULE.verify_live_environments(
            contract,
            FakeClient(deployment_disabled=True),
            deployment_disabled=True,
        )
        self.assertTrue(all(receipt["branch_policies"] == [] for receipt in receipts))

    def test_transition_accepts_only_empty_or_exact_controller_policy(self) -> None:
        contract = MODULE.validate_contract(self.load_contract(), self.load_corpus())
        client = FakeClient(disabled_environments={"authority-observer"})
        receipts = MODULE.verify_live_environments(
            contract,
            client,
            deployment_transition=True,
        )
        self.assertEqual(
            [receipt["branch_policies"] for receipt in receipts],
            [
                [],
                [{"name": "authority/control-v1", "type": "branch"}],
                [{"name": "authority/control-v1", "type": "branch"}],
                [{"name": "authority/control-v1", "type": "branch"}],
                [{"name": "authority/control-v1", "type": "branch"}],
            ],
        )
        with self.assertRaisesRegex(MODULE.PermitInputError, "branch policies drifted"):
            MODULE.verify_live_environments(contract, client)

    def test_live_control_workflow_is_locked_to_the_reviewed_sha(self) -> None:
        contract = MODULE.validate_contract(self.load_contract(), self.load_corpus())
        receipt = MODULE.verify_live_control_workflow(
            contract,
            FakeClient(),
            expected_sha="a" * 40,
        )
        self.assertEqual(receipt["sha"], "a" * 40)
        with self.assertRaisesRegex(MODULE.PermitInputError, "wrong reviewed SHA"):
            MODULE.verify_live_control_workflow(
                contract,
                FakeClient(),
                expected_sha="c" * 40,
            )
        with self.assertRaisesRegex(MODULE.PermitInputError, "policy drifted"):
            MODULE.verify_live_control_workflow(
                contract,
                FakeClient(ruleset_bypass=True),
                expected_sha="a" * 40,
            )


if __name__ == "__main__":
    unittest.main()
