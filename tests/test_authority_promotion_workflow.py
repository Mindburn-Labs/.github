from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AuthorityPromotionWorkflowTests(unittest.TestCase):
    def test_write_and_observer_credentials_are_environment_scoped(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-authority.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("workflow_run:", workflow)
        self.assertNotIn("\n  pull_request:\n", workflow)
        self.assertIn("refs/heads/authority/control-v1", workflow)
        self.assertIn('test "$GITHUB_SHA" = "$GITHUB_WORKFLOW_SHA"', workflow)
        self.assertIn("environment: authority-promotion", workflow)
        self.assertIn("environment: authority-observer", workflow)
        self.assertIn("environment: authority-control", workflow)
        self.assertIn("HELM_AUTHORITY_PROMOTER_PRIVATE_KEY", workflow)
        self.assertEqual(workflow.count("HELM_AUTHORITY_PROMOTER_PRIVATE_KEY"), 5)
        self.assertIn("HELM_AUTHORITY_OBSERVER_PRIVATE_KEY", workflow)
        self.assertEqual(workflow.count("HELM_AUTHORITY_OBSERVER_PRIVATE_KEY"), 4)
        self.assertIn("HELM_AUTHORITY_APPROVER_PRIVATE_KEY", workflow)
        self.assertEqual(workflow.count("HELM_AUTHORITY_APPROVER_PRIVATE_KEY"), 2)
        self.assertEqual(workflow.count("HELM_AUTHORITY_MERGER_PRIVATE_KEY"), 8)
        self.assertEqual(
            workflow.count("HELM_AUTHORITY_CONTROL_UPDATER_PRIVATE_KEY"), 1
        )
        self.assertEqual(workflow.count("Bind exact promoter App identity"), 5)
        self.assertEqual(workflow.count("Bind exact observer App identity"), 4)
        self.assertEqual(workflow.count("Bind exact approval App identity"), 2)
        self.assertEqual(workflow.count("Bind exact merger App identity"), 2)
        self.assertEqual(workflow.count("Bind exact control-updater App identity"), 1)
        self.assertEqual(
            workflow.count("action.yml defines client-id and deprecates app-id"),
            7,
        )
        self.assertEqual(workflow.count("client-id:"), 20)
        self.assertNotIn("app-id:", workflow)
        self.assertEqual(workflow.count('= "helm-authority-promoter"'), 5)
        self.assertEqual(workflow.count('= "helm-authority-observer"'), 4)
        self.assertEqual(workflow.count('= "helm-authority-control-updater"'), 1)
        self.assertEqual(workflow.count('= "146541790"'), 5)
        self.assertEqual(workflow.count('= "146542079"'), 4)
        self.assertEqual(workflow.count('= "146576964"'), 1)
        self.assertEqual(
            workflow.count("permission-organization-administration: write"),
            9,
        )
        self.assertIn(
            "GitHub requires organization Administration write even for ruleset GET",
            workflow,
        )
        self.assertIn("permission-actions: read", workflow)
        self.assertIn("permission-attestations: read", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertEqual(workflow.count("permission-contents: write"), 9)
        merge_job = workflow[workflow.index("  merge:") : workflow.index("  rebind:")]
        self.assertIn("contents: write", merge_job)
        self.assertNotIn("HELM_AUTHORITY_PROMOTER_PRIVATE_KEY", merge_job)
        self.assertNotIn("permission-organization-administration: write", merge_job)
        observer = (ROOT / "scripts" / "observe_authority_promotion.py").read_text(
            encoding="utf-8",
        )
        observer_jobs = (
            workflow[
                workflow.index("  observe_pre_activation:") : workflow.index(
                    "  activate:"
                )
            ]
            + workflow[
                workflow.index("  observe_final:") : workflow.index(
                    "  persist_promotion_final:"
                )
            ]
        )
        self.assertIn("permission-organization-administration: write", observer_jobs)
        self.assertNotIn("permission-contents: write", observer_jobs)
        stage_job = workflow[workflow.index("  stage:") : workflow.index("  merge:")]
        self.assertIn("pull-requests: read", stage_job)
        self.assertNotIn('"PUT"', observer)
        self.assertNotIn('"PATCH"', observer)
        self.assertNotIn('"DELETE"', observer)

    def test_promotion_requires_attested_lineage_observers_and_compensation(
        self,
    ) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-authority.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn(
            '--signer-digest "${{ steps.metadata.outputs.parent_sha }}"',
            workflow,
        )
        self.assertIn('test "$parent_generation" -ge 2', workflow)
        self.assertIn(
            "Generation 1 is admitted exactly once by bootstrap_authority.py", workflow
        )
        self.assertIn("control_workflow_sha", workflow)
        self.assertIn('--signer-digest "$CONTROL_SHA"', workflow)
        self.assertGreaterEqual(workflow.count("--bundle "), 2)
        self.assertGreaterEqual(workflow.count("offline-attest/attest.mjs"), 2)
        self.assertIn("verify_authority_promotion.py", workflow)
        self.assertIn("name: release-permit-input", workflow)
        self.assertIn(
            "--trusted-context promotion/ratification-input/context.json", workflow
        )
        self.assertGreaterEqual(
            workflow.count("promotion/release-permit.attestation.json"), 3
        )
        self.assertGreaterEqual(
            workflow.count("promotion/ratification-input/context.json"), 4
        )
        self.assertIn("wait_for_authority_suite.py", workflow)
        self.assertIn("verify_control_plane.py", workflow)
        self.assertIn("--canary-context promotion/suite/canary-context.json", workflow)
        self.assertEqual(workflow.count("--ratification-context "), 2)
        self.assertEqual(workflow.count("--canary-context "), 2)
        self.assertIn(".adversarial_suite.cases[]", workflow)
        self.assertIn("cmp --silent observed-authority-suite.json", workflow)
        self.assertIn("authority_ruleset_broker.py advance", workflow)
        self.assertIn("authority_ruleset_broker.py rebind", workflow)
        self.assertIn("observe_authority_promotion.py", workflow)
        self.assertIn('--phase "$OBSERVATION_PHASE"', workflow)
        self.assertIn("EXPECTED_OBSERVER_PHASE", workflow)
        self.assertIn("--phase final", workflow)
        self.assertIn("authority_ruleset_broker.py activate", workflow)
        self.assertIn("authority_ruleset_broker.py restore", workflow)
        self.assertIn("atomic_merge_authority.py", workflow)
        self.assertNotIn("repos/Mindburn-Labs/.github/pulls/${{", workflow)
        self.assertIn(
            '[[ "$candidate_ref" =~ ^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$ ]]',
            workflow,
        )
        self.assertIn('git check-ref-format "$candidate_ref"', workflow)
        self.assertNotIn('--candidate-ref "${{', workflow)
        self.assertEqual(workflow.count('--candidate-ref "$CANDIDATE_REF"'), 7)
        self.assertIn(
            '--tree-sha "${{ needs.verify-candidate.outputs.candidate_tree_sha }}"',
            workflow,
        )
        self.assertIn("Build non-authoritative execution bundle", workflow)
        self.assertNotIn("Attest authority promotion receipt", workflow)
        self.assertIn("Sign independent final promotion receipt", workflow)
        self.assertIn("needs.observe_final.result != 'success'", workflow)
        self.assertIn(
            'current_main="$(gh api repos/Mindburn-Labs/.github/git/ref/heads/main',
            workflow,
        )
        self.assertIn('merge_args+=(--merge-sha "$expected_merge_sha")', workflow)
        self.assertIn("Restore parent authority after incomplete promotion", workflow)
        self.assertIn(
            "broker always restores both rulesets to the parent authority", workflow
        )
        self.assertIn('elif [[ "$current_main" = "$merge_sha" ]]', workflow)
        self.assertIn(
            'test "$(jq -er \'.merge_commit_sha\' promotion/pull-request.json)" = "$merge_sha"',
            workflow,
        )
        self.assertIn(
            'test "$(jq -er \'.parents[0].sha\' promotion/merge-commit.json)" = "$base_sha"',
            workflow,
        )
        self.assertIn(
            'test "$(jq -er \'.parents[1].sha\' promotion/merge-commit.json)" = "$candidate_sha"',
            workflow,
        )
        self.assertNotIn('test "$parent_sha" = "$GITHUB_SHA"', workflow)
        promotion_jobs = workflow[workflow.index("  verify-candidate:") :]
        self.assertNotIn("ref: ${{ github.sha }}", promotion_jobs)
        self.assertIn(
            "ref: ${{ steps.metadata.outputs.parent_sha }}",
            workflow,
        )
        self.assertIn(
            "cmp --silent promotion/parent-authority.json promotion/permit-authority.json",
            workflow,
        )
        self.assertLess(
            workflow.index("Download triggering permit artifact"),
            workflow.index("Checkout permit-named immutable parent authority broker"),
        )
        self.assertLess(
            workflow.index("Verify GitHub-signed parent-workflow provenance"),
            workflow.index("Checkout permit-named immutable parent authority broker"),
        )
        self.assertIn(
            "Main is outside the exact parent/ratified-merge states",
            workflow,
        )
        self.assertEqual(workflow.count("path: candidate-kernel"), 2)
        self.assertEqual(workflow.count("candidate-permit-verify"), 4)
        self.assertEqual(workflow.count("--candidate-kernel-verifier"), 2)
        self.assertIn("verify-kernel-transition", workflow)

    def test_promotion_recovery_is_ledger_first_and_phase_ordered(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-authority.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("ledger_generation:", workflow)
        self.assertIn("ledger_merge_sha:", workflow)
        self.assertNotIn(
            '"promotions/generation-${{ inputs.ledger_generation }}', workflow
        )
        self.assertIn(
            '"promotions/generation-$LEDGER_GENERATION/$LEDGER_MERGE_SHA/intent"',
            workflow,
        )
        reconcile = workflow[
            workflow.index("  reconcile:") : workflow.index("  stage:")
        ]
        self.assertIn("- persist_promotion_intent", reconcile)
        merge = workflow[
            workflow.index("  merge:") : workflow.index("  persist_promotion_merged:")
        ]
        self.assertIn("- persist_promotion_intent", merge)
        rebind = workflow[
            workflow.index("  rebind:") : workflow.index("  observe_pre_activation:")
        ]
        self.assertIn("- persist_promotion_merged", rebind)
        final = workflow[
            workflow.index("  persist_promotion_final:") : workflow.index("  recover:")
        ]
        self.assertIn("Verify final observer provenance before persistence", final)
        self.assertIn("--phase final", final)
        recover = workflow[workflow.index("  recover:") :]
        self.assertNotIn("persist_promotion_final.result", recover)
        self.assertNotIn("gh api /installation |", workflow)
        self.assertGreaterEqual(
            workflow.count("gh api /installation/repositories?per_page=100"),
            5,
        )

    def test_all_external_actions_are_commit_pinned(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "promote-authority.yml").read_text(
            encoding="utf-8",
        )
        for line in workflow.splitlines():
            stripped = line.strip()
            if stripped.startswith("uses:"):
                reference = stripped.split("@", 1)[1]
                self.assertRegex(reference, r"^[0-9a-f]{40}$")

    def test_api_authorization_headers_remain_reviewable(self) -> None:
        for relative_path in (
            "scripts/atomic_merge_authority.py",
            "scripts/authority_ruleset_broker.py",
            "scripts/configure_machine_approval_gates.py",
            "scripts/submit_machine_approval.py",
            "scripts/wait_for_authority_canary.py",
        ):
            source = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn('" ".join(("Bearer", self.token))', source)


if __name__ == "__main__":
    unittest.main()
