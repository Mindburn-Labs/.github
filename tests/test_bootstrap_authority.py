from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "bootstrap_authority.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

CANDIDATE_SHA = "2" * 40
BASE_SHA = "1" * 40
MERGE_SHA = "3" * 40
TREE_SHA = "4" * 40
CANDIDATE_REF = "refs/heads/codex/autonomous-release-gen2-bootstrap"


def pull_request(repository: str, number: int, head_sha: str) -> dict[str, object]:
    return {
        "number": number,
        "state": "open",
        "merged": False,
        "draft": False,
        "base": {"ref": "main", "sha": BASE_SHA},
        "head": {
            "ref": f"proof-{number}",
            "sha": head_sha,
            "repo": {"full_name": repository},
        },
    }


class TriggerClient:
    def __init__(self, contract: dict[str, object]) -> None:
        repository = contract["adversarial_suite"]["repository"]
        self.pulls = {
            case["pull_request"]: pull_request(
                repository, case["pull_request"], case["head_sha"]
            )
            for case in contract["adversarial_suite"]["cases"]
        }
        self.patches = 0

    def get(self, path: str):
        return json.loads(json.dumps(self.pulls[int(path.rsplit("/", 1)[1])]))

    def request(self, method: str, path: str, *, payload=None):
        if method != "PATCH" or payload is None:
            raise AssertionError(f"unexpected request {method} {path}")
        value = self.pulls[int(path.rsplit("/", 1)[1])]
        value["state"] = payload["state"]
        self.patches += 1
        return json.loads(json.dumps(value))


class ResumeMergeClient:
    def get(self, path: str):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": MERGE_SHA}}
        if "/pulls/" in path:
            value = pull_request(MODULE.REPOSITORY, 36, CANDIDATE_SHA)
            value.update(
                {
                    "state": "closed",
                    "merged": True,
                    "merge_commit_sha": MERGE_SHA,
                },
            )
            return value
        if path.endswith(f"/git/commits/{MERGE_SHA}"):
            return {
                "parents": [{"sha": BASE_SHA}, {"sha": CANDIDATE_SHA}],
                "tree": {"sha": TREE_SHA},
            }
        raise AssertionError(f"unexpected GET {path}")


class RepositorySettingsClient:
    def __init__(self, delete_branch_on_merge: bool) -> None:
        self.delete_branch_on_merge = delete_branch_on_merge
        self.patches = 0

    def get(self, path: str):
        if path != f"/repos/{MODULE.REPOSITORY}":
            raise AssertionError(path)
        return {"delete_branch_on_merge": self.delete_branch_on_merge}

    def request(self, method: str, path: str, *, payload=None):
        if (
            method != "PATCH"
            or path != f"/repos/{MODULE.REPOSITORY}"
            or payload != {"delete_branch_on_merge": False}
        ):
            raise AssertionError((method, path, payload))
        self.delete_branch_on_merge = False
        self.patches += 1
        return {"delete_branch_on_merge": False}


class BootstrapAuthorityTests(unittest.TestCase):
    def test_bootstrap_preserves_candidate_head_for_fail_closed_recovery(self) -> None:
        for initial, expected_patches in ((True, 1), (False, 0)):
            with self.subTest(initial=initial):
                client = RepositorySettingsClient(initial)
                receipt = MODULE.ensure_recovery_head_ref_policy(client)
                self.assertFalse(receipt["delete_branch_on_merge_after"])
                self.assertEqual(client.patches, expected_patches)

    def test_suite_trigger_reopens_every_exact_permanent_case(self) -> None:
        contract = MODULE.validate_contract(
            MODULE.load_json(
                ROOT / "config" / "autonomous-release-control-plane.json",
                label="contract",
            ),
            MODULE.load_json(
                ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
                label="corpus",
            ),
        )
        client = TriggerClient(contract)
        trigger = MODULE.trigger_suite(contract, client, workflow_sha=CANDIDATE_SHA)
        self.assertEqual(trigger["cases"], contract["adversarial_suite"]["cases"])
        self.assertEqual(client.patches, 16)
        self.assertTrue(
            all(value["state"] == "open" for value in client.pulls.values())
        )

    def test_suite_trigger_rejects_head_drift(self) -> None:
        contract = MODULE.validate_contract(
            MODULE.load_json(
                ROOT / "config" / "autonomous-release-control-plane.json",
                label="contract",
            ),
            MODULE.load_json(
                ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
                label="corpus",
            ),
        )
        client = TriggerClient(contract)
        client.pulls[1]["head"]["sha"] = "f" * 40
        with self.assertRaises(MODULE.PermitInputError):
            MODULE.trigger_suite(contract, client, workflow_sha=CANDIDATE_SHA)

    def test_finalization_can_resume_after_exact_atomic_merge(self) -> None:
        ready = {
            "pull_request": 36,
            "base_sha": BASE_SHA,
            "candidate_sha": CANDIDATE_SHA,
            "merge_sha": MERGE_SHA,
            "merge_tree_sha": TREE_SHA,
        }
        receipt = MODULE.confirmed_or_atomic_merge(ready, ResumeMergeClient())
        self.assertEqual(receipt["merge_sha"], MERGE_SHA)
        self.assertFalse(receipt["force"])

    def test_ready_receipt_rejects_candidate_substitution(self) -> None:
        ready = {
            "schema": MODULE.READY_SCHEMA,
            "repository": MODULE.REPOSITORY,
            "pull_request": 36,
            "base_sha": BASE_SHA,
            "candidate_sha": CANDIDATE_SHA,
            "candidate_ref": CANDIDATE_REF,
            "candidate_tree_sha": TREE_SHA,
            "ratification_permit_id": "sha256:" + "5" * 64,
            "ratification_run_id": 1,
            "liveness_permit_id": "sha256:" + "6" * 64,
            "liveness_run_id": 2,
            "liveness_run_attempt": 1,
            "merge_sha": MERGE_SHA,
            "merge_tree_sha": TREE_SHA,
            "evidence_sha256": {},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ready.json"
            path.write_text(json.dumps(ready), encoding="utf-8")
            args = argparse.Namespace(
                ready=path,
                candidate_sha="9" * 40,
                candidate_pr=36,
            )
            with self.assertRaises(MODULE.PermitInputError):
                MODULE.validate_ready(args)


if __name__ == "__main__":
    unittest.main()
