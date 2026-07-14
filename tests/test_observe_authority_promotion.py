from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "observe_authority_promotion.py"
SPEC = importlib.util.spec_from_file_location("observe_authority_promotion", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)


def execution() -> dict[str, object]:
    return {
        "schema": MODULE.EXECUTION_SCHEMA,
        "parent_generation": 1,
        "candidate_generation": 2,
        "parent_base_sha": "1" * 40,
        "parent_workflow_sha": "1" * 40,
        "candidate_workflow_sha": "2" * 40,
        "candidate_workflow_ref": "refs/heads/authority-next",
        "candidate_tree_sha": "3" * 40,
        "candidate_pull_request": 33,
        "merged_workflow_sha": "4" * 40,
        "merged_tree_sha": "3" * 40,
        "ratification_permit_id": "sha256:" + "5" * 64,
        "ratification_run_id": 101,
        "ratification_run_attempt": 1,
        "canary_run_id": 202,
        "canary_run_attempt": 1,
        "canary_permit_id": "sha256:" + "6" * 64,
        "authority_suite_sha256": "7" * 64,
    }


class ObserveAuthorityPromotionTests(unittest.TestCase):
    def test_execution_requires_immediate_lineage_and_exact_tree(self) -> None:
        self.assertEqual(MODULE.validate_execution(execution())["candidate_generation"], 2)
        for field, value in (
            ("candidate_generation", 3),
            ("merged_tree_sha", "7" * 40),
        ):
            with self.subTest(field=field):
                candidate = execution()
                candidate[field] = value
                with self.assertRaises(MODULE.PermitInputError):
                    MODULE.validate_execution(candidate)

    def test_execution_rejects_unknown_fields_and_malformed_permit_ids(self) -> None:
        unknown = execution()
        unknown["executor_claimed_success"] = True
        with self.assertRaises(MODULE.PermitInputError):
            MODULE.validate_execution(unknown)

        malformed = execution()
        malformed["canary_permit_id"] = "sha256:not-a-digest"
        with self.assertRaises(MODULE.PermitInputError):
            MODULE.validate_execution(malformed)


if __name__ == "__main__":
    unittest.main()
