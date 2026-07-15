from __future__ import annotations

import importlib.util
import inspect
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "observe_authority_promotion.py"
SPEC = importlib.util.spec_from_file_location(
    "observe_authority_promotion", MODULE_PATH
)
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
        "control_workflow_sha": "8" * 40,
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
    def test_read_only_observer_requires_exact_effective_stable_rule(self) -> None:
        workflow_sha = "a" * 40
        expected_rule = {
            "ruleset_id": MODULE.STABLE_RULESET_ID,
            "ruleset_source_type": "Organization",
            "ruleset_source": "Mindburn-Labs",
            "type": "workflows",
            "parameters": {
                "do_not_enforce_on_create": False,
                "workflows": [
                    {
                        "path": ".github/workflows/ci.yml",
                        "ref": MODULE.MAIN_REF,
                        "repository_id": MODULE.AUTHORITY_REPOSITORY_ID,
                        "sha": workflow_sha,
                    },
                ],
            },
        }

        class Client:
            def __init__(self, rule):
                self.rule = rule

            def get_bytes(self, _path):
                return json.dumps([self.rule]).encode()

        observed = MODULE.observe_effective_stable_rules(
            Client(expected_rule),
            workflow_sha=workflow_sha,
        )
        self.assertEqual(
            [item["repository"] for item in observed],
            list(MODULE.PUBLIC_STABLE_REPOSITORIES),
        )

        drifted = json.loads(json.dumps(expected_rule))
        drifted["parameters"]["workflows"][0]["sha"] = "b" * 40
        with self.assertRaisesRegex(
            MODULE.PermitInputError,
            "binding drifted",
        ):
            MODULE.observe_effective_stable_rules(
                Client(drifted),
                workflow_sha=workflow_sha,
            )

    def test_observer_explicitly_threads_attestation_token_to_both_permits(
        self,
    ) -> None:
        self.assertIn("attestation_token", inspect.signature(MODULE.observe).parameters)
        source = inspect.getsource(MODULE.observe)
        self.assertEqual(source.count("attestation_token=attestation_token"), 2)

    def test_execution_requires_immediate_lineage_and_exact_tree(self) -> None:
        self.assertEqual(
            MODULE.validate_execution(execution())["candidate_generation"], 2
        )
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
