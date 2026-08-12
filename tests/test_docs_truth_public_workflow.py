from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "docs-truth-public.yml"
WORKER = ROOT / "scripts" / "docs_truth_trusted_worker.js"


class DocsTruthTrustedWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.worker_source = WORKER.read_text(encoding="utf-8")

    def test_is_call_only_read_only_and_fixed_runner(self) -> None:
        self.assertIn("workflow_call:", self.source)
        self.assertNotIn("workflow_dispatch:", self.source)
        self.assertNotIn("pull_request_target:", self.source)
        self.assertNotIn("id-token:", self.source)
        self.assertNotRegex(self.source, re.compile(r"\b(?:contents|pull-requests|actions):\s*write\b"))
        self.assertIn("permissions: {}", self.source)
        self.assertIn("      name: docs-truth-trusted", self.source)
        self.assertIn("      deployment: false", self.source)
        self.assertIn("runs-on: ubuntu-latest", self.source)
        self.assertNotIn("runs-on: self-hosted", self.source)
        self.assertIn('workflow_ref = job.get("workflow_ref")', self.source)
        self.assertIn('workflow_file_path = job.get("workflow_file_path")', self.source)
        self.assertIn('expected_path = ".github/workflows/docs-truth-public.yml"', self.source)

    def test_broker_token_is_short_lived_and_not_supplied_by_the_caller(self) -> None:
        self.assertRegex(self.source, re.compile(r"on:\n  workflow_call:\n\njobs:"))
        self.assertNotIn("MINDBURN_ORG_READ_TOKEN", self.source)
        self.assertIn(
            "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
            self.source,
        )
        self.assertIn("client-id: ${{ secrets.DOCS_TRUTH_BROKER_CLIENT_ID }}", self.source)
        self.assertIn("private-key: ${{ secrets.DOCS_TRUTH_BROKER_PRIVATE_KEY }}", self.source)
        for required in (
            "            .github",
            "            app-helm-docs",
            "            docs",
            "            dev-orchestration",
            "permission-actions: read",
            "permission-contents: read",
            "permission-pull-requests: read",
            "permission-statuses: write",
            "repositories: app-helm-docs",
            "github-token: ${{ steps.status-token.outputs.token }}",
            "token: ${{ steps.read-token.outputs.token }}",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.source)
        self.assertNotIn("github-token: ${{ secrets.", self.source)
        status_block = self.source.split("      - name: Mint candidate status token", 1)[1].split(
            "      - name: Load exact trusted worker source", 1
        )[0]
        self.assertNotIn("            .github", status_block)
        self.assertNotIn("            docs", status_block)
        self.assertNotIn("            dev-orchestration", status_block)
        self.assertNotIn("permission-statuses: write", self.source.split("      - name: Mint candidate status token", 1)[0])
        self.assertNotIn("permission-actions: read", self.source.split("      - name: Mint candidate status token", 1)[0])

    def test_every_third_party_action_is_pinned_and_no_artifact_or_cache_is_consumed(self) -> None:
        uses = re.findall(r"^        uses:\s*(\S+)", self.source, flags=re.MULTILINE)
        self.assertGreater(len(uses), 0)
        for reference in uses:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertNotIn("download-artifact", self.source)
        self.assertNotIn("upload-artifact", self.source)
        self.assertNotIn("actions/cache", self.source)

    def test_candidate_is_only_a_bare_object_store_and_inert_data_tree(self) -> None:
        checkout_repositories = re.findall(
            r"^          repository:\s*(\S+)$",
            self.source,
            flags=re.MULTILINE,
        )
        self.assertEqual(
            checkout_repositories,
            ["Mindburn-Labs/.github", "Mindburn-Labs/docs", "Mindburn-Labs/dev-orchestration"],
        )
        self.assertNotIn("repository: Mindburn-Labs/app-helm-docs", self.source)
        self.assertIn("fetch_pull_request_git_objects.py", self.source)
        self.assertIn("verify_workflow_tree.py", self.source)
        self.assertIn("--profile app-helm-docs", self.source)
        self.assertIn("--materialize-directory", self.source)
        self.assertIn("--index-file", self.source)
        self.assertIn("GIT_INDEX_FILE:", self.source)
        self.assertNotIn("git checkout", self.source)
        self.assertNotIn("git clone", self.source)
        self.assertNotRegex(
            self.source,
            re.compile(r"(?:bash|sh|python|ruby|node)\s+[\"']?(?:\$GITHUB_WORKSPACE/)?workspace/app-helm-docs"),
        )

    def test_event_and_api_bindings_are_exact_and_forks_fail_closed(self) -> None:
        for required in (
            'const EXPECTED_WORKFLOW_ID = 305654002;',
            'const EXPECTED_WORKFLOW_NAME = "Docs Truth";',
            'const EXPECTED_WORKFLOW_PATH = ".github/workflows/docs-truth.yml";',
            'context.eventName !== "workflow_run"',
            'run.event !== "pull_request"',
            'run.status !== "completed" || run.conclusion !== "success"',
            "head SHA must identify exactly one open same-repository PR to main",
            "fork pull requests are not admitted",
            "pull.merge_commit_sha",
            'const STATUS_CONTEXT = "docs-truth-trusted";',
            "sameSnapshot(expected, observed)",
            'state: succeeded ? "success" : "failure"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.worker_source)
        self.assertIn("await worker.admit", self.source)
        self.assertIn("await worker.finalize", self.source)
        self.assertIn("if: ${{ always() && steps.admission.outputs.head_sha != '' }}", self.source)

    def test_runner_and_ledger_are_immutable_and_executable_rows_fail_closed(self) -> None:
        self.assertIn("ref: 6f9b686a4db10fed2f968cf2474477051d43c0b0", self.source)
        self.assertIn("ref: 4338b9ae6b76284aeee7a4cfe9f8d6ef9f101156", self.source)
        self.assertIn('row["status"] == "generated"', self.source)
        self.assertIn('row["truth_gate"]', self.source)
        self.assertIn("app-helm-docs ledger contains executable truth_gate semantics", self.source)
        self.assertIn("docs-truth-org.rb", self.source)


if __name__ == "__main__":
    unittest.main()
