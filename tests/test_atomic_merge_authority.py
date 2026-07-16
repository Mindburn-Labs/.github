from __future__ import annotations

import argparse
from contextlib import redirect_stderr
import importlib.util
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "atomic_merge_authority.py"
SPEC = importlib.util.spec_from_file_location("atomic_merge_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

PERMIT_ID = "sha256:" + "5" * 64


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
        self.repository_names = {MODULE.REPOSITORY}

    def get(self, path: str):
        if "/reviews/" in path:
            return {
                "state": "APPROVED",
                "commit_id": self.head_sha,
                "body": f"HELM signed ALLOW permit {PERMIT_ID}",
                "user": {"login": MODULE.APPROVER_LOGIN},
            }
        if path == "/installation/repositories?per_page=100":
            return {
                "repositories": [
                    {"full_name": name} for name in self.repository_names
                ],
            }
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


class NoNetworkClient:
    def get(self, path: str):
        raise AssertionError(f"unexpected GET {path}")

    def graphql(self, query: str, variables: dict[str, object]):
        raise AssertionError("unexpected GraphQL mutation")


class AtomicMergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.approval_path = Path(self.tmpdir.name) / "approval.json"
        self.permit_path = Path(self.tmpdir.name) / "permit.json"
        permit = {
            "pull_request": 36,
            "head_sha": "2" * 40,
            "workflow_sha": "2" * 40,
            "permit_id": PERMIT_ID,
            "base_sha": "1" * 40,
            "merge_sha": "3" * 40,
            "merge_tree_sha": "4" * 40,
        }
        approval = {
            "schema": MODULE.APPROVAL_SCHEMA,
            "repository": MODULE.REPOSITORY,
            **permit,
            "review_id": 42,
            "review_state": "APPROVED",
            "approver_login": MODULE.APPROVER_LOGIN,
            "approver_app_id": MODULE.APPROVER_APP_ID,
            "approver_installation_id": MODULE.APPROVER_INSTALLATION_ID,
        }
        self.permit_path.write_text(json.dumps(permit), encoding="utf-8")
        self.approval_path.write_text(json.dumps(approval), encoding="utf-8")

    def args(self):
        return argparse.Namespace(
            pull_request=36,
            base_sha="1" * 40,
            head_sha="2" * 40,
            merge_sha="3" * 40,
            tree_sha="4" * 40,
            merger_app_slug="helm-authority-merger",
            merger_installation_id=6000001,
            merger_app_id=5000001,
            approval_receipt=self.approval_path,
            permit=self.permit_path,
        )

    def test_parser_requires_every_authority_input(self) -> None:
        arguments = [
            "--pull-request",
            "36",
            "--base-sha",
            "1" * 40,
            "--head-sha",
            "2" * 40,
            "--merge-sha",
            "3" * 40,
            "--tree-sha",
            "4" * 40,
            "--approval-receipt",
            str(self.approval_path),
            "--permit",
            str(self.permit_path),
            "--merger-app-slug",
            "helm-authority-merger",
            "--merger-installation-id",
            "6000001",
            "--merger-app-id",
            "5000001",
            "--output",
            str(Path(self.tmpdir.name) / "output.json"),
        ]
        for flag in (
            "--approval-receipt",
            "--permit",
            "--merger-app-slug",
            "--merger-installation-id",
            "--merger-app-id",
        ):
            with self.subTest(flag=flag):
                missing = list(arguments)
                index = missing.index(flag)
                del missing[index : index + 2]
                with redirect_stderr(StringIO()):
                    with self.assertRaises(SystemExit):
                        MODULE.build_parser().parse_args(missing)

    def test_atomic_merge_rejects_missing_or_invalid_authority_input_before_network(
        self,
    ) -> None:
        for field, value in (
            ("merger_app_slug", None),
            ("merger_installation_id", None),
            ("merger_app_id", None),
            ("approval_receipt", None),
            ("permit", None),
            ("merger_app_slug", ""),
            ("merger_installation_id", 0),
            ("merger_app_id", 0),
        ):
            with self.subTest(field=field, value=value):
                args = self.args()
                setattr(args, field, value)
                with self.assertRaisesRegex(MODULE.PermitInputError, "required"):
                    MODULE.atomic_merge(args, NoNetworkClient())

    def test_atomic_merge_rejects_stale_approval_before_network(self) -> None:
        approval = json.loads(self.approval_path.read_text(encoding="utf-8"))
        approval["head_sha"] = "9" * 40
        self.approval_path.write_text(json.dumps(approval), encoding="utf-8")
        args = self.args()
        with self.assertRaisesRegex(MODULE.PermitInputError, "head_sha is not exact"):
            MODULE.atomic_merge(args, NoNetworkClient())

    def test_atomic_merge_rejects_wrong_merger_scope_before_mutation(self) -> None:
        args = self.args()
        client = FakeClient(
            main_sha=args.base_sha,
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            merge_sha=args.merge_sha,
            tree_sha=args.tree_sha,
        )
        client.repository_names = {"Mindburn-Labs/another-repository"}
        with self.assertRaisesRegex(MODULE.PermitInputError, "scope is not exact"):
            MODULE.atomic_merge(args, client)
        self.assertEqual(client.graphql_calls, [])

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
