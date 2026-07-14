from __future__ import annotations

import importlib.util
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
    def __init__(self, *, add_reviewer: bool = False) -> None:
        self.add_reviewer = add_reviewer

    def get_json(self, path: str):
        if path == "/repos/Mindburn-Labs/.github":
            return {"delete_branch_on_merge": False}
        if path.endswith("/deployment-branch-policies"):
            return {
                "total_count": 1,
                "branch_policies": [{"name": "main", "type": "branch"}],
            }
        rules = [{"type": "branch_policy", "id": 1}]
        if self.add_reviewer:
            rules.append({"type": "required_reviewers", "reviewers": [{"id": 7}]})
        return {
            "protection_rules": rules,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }


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
            {"authority-observer", "authority-promotion"},
        )
        self.assertEqual(len(contract["adversarial_suite"]["cases"]), 8)
        self.assertEqual(
            contract["repository_settings"],
            {"delete_branch_on_merge": False},
        )

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
        self.assertEqual(len(receipts), 2)


if __name__ == "__main__":
    unittest.main()
