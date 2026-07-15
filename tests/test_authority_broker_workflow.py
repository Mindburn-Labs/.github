from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AuthorityBrokerWorkflowTests(unittest.TestCase):
    def test_shadow_broker_is_default_branch_and_data_only(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "authority-broker.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("workflow_run:", workflow)
        self.assertIn("HELM Autonomous Release Permit", workflow)
        self.assertIn("event == 'pull_request'", workflow)
        self.assertIn(
            "test \"$(jq -er '.path' triggering-run.json)\" = \".github/workflows/ci.yml\"",
            workflow,
        )
        self.assertIn(
            "test \"$(jq -er '.run_attempt | tostring' triggering-run.json)\" = \"$TRIGGER_RUN_ATTEMPT\"",
            workflow,
        )
        self.assertIn("test \"$(jq -er '.base.ref' pull-request.json)\" = \"main\"", workflow)
        self.assertIn(
            "test \"$(jq -er '.head.repo.full_name' pull-request.json)\" = \"Mindburn-Labs/.github\"",
            workflow,
        )
        self.assertIn("fetch_pull_request_git_objects.py", workflow)
        self.assertIn("verify_workflow_tree.py", workflow)
        self.assertIn('mode: "shadow-only"', workflow)
        self.assertIn('= "shadow-exact-tree"', workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn("trigger_run_id", workflow)
        self.assertIn("trigger_run_attempt", workflow)
        self.assertIn("broker_run_id", workflow)
        self.assertIn("broker_run_attempt", workflow)
        self.assertNotIn("ref: ${{ github.event.workflow_run.head_sha }}", workflow)
        self.assertNotIn("ref: ${{ steps.metadata.outputs.head_sha }}", workflow)
        self.assertNotIn("environment:", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("attestations: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("create-github-app-token", workflow)

    def test_shadow_broker_pins_all_external_actions(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "authority-broker.yml").read_text(
            encoding="utf-8",
        )
        for line in workflow.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:"):
                reference = stripped.split("@", 1)[1]
                self.assertRegex(reference, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
