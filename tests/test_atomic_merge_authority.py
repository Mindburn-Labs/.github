from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "atomic_merge_authority.py"
SPEC = importlib.util.spec_from_file_location("atomic_merge_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)


class FakeClient:
    def __init__(
        self,
        *,
        main_sha: str,
        base_sha: str,
        head_sha: str,
        merge_sha: str,
        tree_sha: str,
    ):
        self.main_sha = main_sha
        self.base_sha = base_sha
        self.head_sha = head_sha
        self.merge_sha = merge_sha
        self.pull_request_merge_sha = merge_sha
        self.tree_sha = tree_sha
        self.graphql_calls = []

    def get(self, path: str):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": self.main_sha}}
        if "/git/commits/" in path:
            return {
                "parents": [{"sha": self.base_sha}, {"sha": self.head_sha}],
                "tree": {"sha": self.tree_sha},
            }
        if "/pulls/" in path:
            merged = self.main_sha == self.merge_sha
            return {
                "number": 36,
                "state": "closed" if merged else "open",
                "draft": False,
                "merged": merged,
                "merge_commit_sha": self.pull_request_merge_sha,
                "base": {"ref": "main", "sha": self.base_sha},
                "head": {
                    "sha": self.head_sha,
                    "repo": {"full_name": MODULE.REPOSITORY},
                },
            }
        raise AssertionError(path)

    def graphql(self, query, variables):
        self.graphql_calls.append((query, variables))
        if "query" in query:
            return {"repository": {"id": "R_repo"}}
        if variables["beforeOid"] != self.main_sha:
            raise MODULE.PermitInputError("beforeOid mismatch")
        self.main_sha = variables["afterOid"]
        return {"updateRefs": {"clientMutationId": None}}


class AtomicMergeTests(unittest.TestCase):
    def args(self):
        return argparse.Namespace(
            pull_request=36,
            base_sha="1" * 40,
            head_sha="2" * 40,
            merge_sha="3" * 40,
            tree_sha="4" * 40,
        )

    def test_atomic_merge_uses_exact_before_and_after_oids_without_force(self) -> None:
        args = self.args()
        client = FakeClient(
            main_sha=args.base_sha,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            merge_sha=args.merge_sha,
            tree_sha=args.tree_sha,
        )
        receipt = MODULE.atomic_merge(args, client)
        self.assertEqual(receipt["merge_sha"], args.merge_sha)
        mutation, variables = client.graphql_calls[1]
        self.assertEqual(variables["beforeOid"], args.base_sha)
        self.assertEqual(variables["afterOid"], args.merge_sha)
        self.assertIn("force: false", mutation)

    def test_atomic_merge_rejects_base_drift_before_mutation(self) -> None:
        args = self.args()
        client = FakeClient(
            main_sha="9" * 40,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            merge_sha=args.merge_sha,
            tree_sha=args.tree_sha,
        )
        with self.assertRaisesRegex(MODULE.PermitInputError, "main moved"):
            MODULE.atomic_merge(args, client)
        self.assertEqual(client.graphql_calls, [])

    def test_atomic_merge_resumes_after_the_exact_merge(self) -> None:
        args = self.args()
        client = FakeClient(
            main_sha=args.merge_sha,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            merge_sha=args.merge_sha,
            tree_sha=args.tree_sha,
        )
        receipt = MODULE.atomic_merge(args, client)
        self.assertEqual(receipt["merge_sha"], args.merge_sha)
        self.assertEqual(receipt["merge_tree_sha"], args.tree_sha)
        self.assertEqual(client.graphql_calls, [])

    def test_atomic_merge_recovery_rejects_a_different_merged_pull_request(
        self,
    ) -> None:
        args = self.args()
        client = FakeClient(
            main_sha=args.merge_sha,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            merge_sha=args.merge_sha,
            tree_sha=args.tree_sha,
        )
        client.pull_request_merge_sha = "9" * 40
        with self.assertRaisesRegex(MODULE.PermitInputError, "exact reviewed commit"):
            MODULE.atomic_merge(args, client)
        self.assertEqual(client.graphql_calls, [])

    def test_atomic_merge_rejects_stale_github_generated_merge(self) -> None:
        args = self.args()
        client = FakeClient(
            main_sha=args.base_sha,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            merge_sha=args.merge_sha,
            tree_sha=args.tree_sha,
        )
        client.pull_request_merge_sha = "9" * 40
        with self.assertRaisesRegex(
            MODULE.PermitInputError, "current GitHub-generated"
        ):
            MODULE.atomic_merge(args, client)
        self.assertEqual(client.graphql_calls, [])


if __name__ == "__main__":
    unittest.main()
