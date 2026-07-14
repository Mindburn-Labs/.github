from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AuthorityPromotionWorkflowTests(unittest.TestCase):
    def test_write_and_observer_credentials_are_environment_scoped(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-authority.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("workflow_run:", workflow)
        self.assertNotIn("\n  pull_request:\n", workflow)
        self.assertIn("environment: authority-promotion", workflow)
        self.assertIn("environment: authority-observer", workflow)
        self.assertIn("HELM_AUTHORITY_PROMOTER_PRIVATE_KEY", workflow)
        self.assertEqual(workflow.count("HELM_AUTHORITY_PROMOTER_PRIVATE_KEY"), 3)
        self.assertIn("HELM_AUTHORITY_OBSERVER_PRIVATE_KEY", workflow)
        self.assertEqual(workflow.count("HELM_AUTHORITY_OBSERVER_PRIVATE_KEY"), 2)
        self.assertIn("permission-organization-administration: write", workflow)
        self.assertIn("separate App token is consumed only by the observer's GET-only client", workflow)
        self.assertIn("permission-actions: read", workflow)
        self.assertIn("permission-attestations: read", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertNotIn("permission-contents: write", workflow)
        observer = (ROOT / "scripts" / "observe_authority_promotion.py").read_text(
            encoding="utf-8",
        )
        self.assertNotIn('"PUT"', observer)
        self.assertNotIn('"PATCH"', observer)
        self.assertNotIn('"DELETE"', observer)

    def test_promotion_requires_attested_lineage_observers_and_compensation(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-authority.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("--signer-digest \"$GITHUB_SHA\"", workflow)
        self.assertIn("verify_authority_promotion.py", workflow)
        self.assertIn("wait_for_authority_canary.py", workflow)
        self.assertIn("pull-request 8", workflow)
        self.assertIn("authority_ruleset_broker.py advance", workflow)
        self.assertIn("authority_ruleset_broker.py rebind", workflow)
        self.assertIn("observe_authority_promotion.py", workflow)
        self.assertIn("--phase pre-activation", workflow)
        self.assertIn("--phase final", workflow)
        self.assertIn("authority_ruleset_broker.py activate", workflow)
        self.assertIn("authority_ruleset_broker.py restore", workflow)
        self.assertIn("test \"$merge_tree_sha\"", workflow)
        self.assertIn("Build non-authoritative execution bundle", workflow)
        self.assertNotIn("Attest authority promotion receipt", workflow)
        self.assertIn("Attest independent final promotion receipt", workflow)
        self.assertIn("needs.observe_final.result != 'success'", workflow)
        self.assertNotIn("path: candidate-kernel", workflow)
        self.assertNotIn("candidate-permit-verify", workflow)

    def test_all_external_actions_are_commit_pinned(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-authority.yml").read_text(
            encoding="utf-8",
        )
        for line in workflow.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:"):
                reference = stripped.split("@", 1)[1]
                self.assertRegex(reference, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
