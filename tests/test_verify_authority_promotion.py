from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_authority_promotion.py"
SPEC = importlib.util.spec_from_file_location("verify_authority_promotion", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

PARENT_SHA = "1" * 40
PARENT_KERNEL_SHA = "2" * 40
CANDIDATE_KERNEL_SHA = "3" * 39 + "a"
CONTEXT_SHA = "4" * 64
RESPONSE_A = "5" * 64
RESPONSE_B = "6" * 64


def git(repository: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *arguments],
        text=True,
    ).strip()


def minimal_semantic_workflow() -> str:
    return f"""name: permit
jobs:
  prepare:
    steps:
      - name: {MODULE.PREPARE_KERNEL_STEP}
        uses: {MODULE.CHECKOUT_ACTION}
        with:
          repository: {MODULE.KERNEL_REPOSITORY}
          ref: {CANDIDATE_KERNEL_SHA}
          persist-credentials: false
          path: {MODULE.PREPARE_KERNEL_PATH}
          sparse-checkout: |
            core/pkg/releasepermit
            core/cmd/release-permit-verify
      - name: {MODULE.PREPARE_BUNDLE_STEP}
        env:
          KERNEL_SHA: {CANDIDATE_KERNEL_SHA}
        run: |
          set -euo pipefail
          python3 policy/scripts/autonomous_release_permit.py prepare \\
            --repository "$REPOSITORY" \\
            --pull-request "$PULL_REQUEST" \\
            --base-ref "$BASE_REF" \\
            --base-sha "$BASE_SHA" \\
            --head-sha "$HEAD_SHA" \\
            --merge-sha "$MERGE_SHA" \\
            --workflow-repository "$WORKFLOW_REPOSITORY" \\
            --workflow-path "$WORKFLOW_PATH" \\
            --workflow-ref "$WORKFLOW_REF" \\
            --workflow-sha "$WORKFLOW_SHA" \\
            --run-id "$RUN_ID" \\
            --run-attempt "$RUN_ATTEMPT" \\
            --issued-at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \\
            --anthropic-model "$ANTHROPIC_MODEL" \\
            --openai-model "$OPENAI_MODEL" \\
            --authority-manifest policy/config/autonomous-release-authority.json \\
            --kernel-sha "$KERNEL_SHA" \\
            --gate-profiles policy/config/autonomous-release-gates.json \\
            --adversarial-corpus policy/tests/fixtures/autonomous-release-adversarial.json \\
            --target-dir target \\
            --output-dir permit-input \\
            --max-patch-bytes "$MAX_PATCH_BYTES" \\
            --max-changed-blob-bytes "$MAX_CHANGED_BLOB_BYTES"
  permit:
    steps:
      - name: {MODULE.PERMIT_KERNEL_STEP}
        uses: {MODULE.CHECKOUT_ACTION}
        with:
          repository: {MODULE.KERNEL_REPOSITORY}
          ref: {CANDIDATE_KERNEL_SHA}
          persist-credentials: false
          path: {MODULE.PERMIT_KERNEL_PATH}
"""


def legacy_lexical_workflow() -> str:
    return f"""name: permit
steps:
  - ref: {CANDIDATE_KERNEL_SHA}
  - ref: {CANDIDATE_KERNEL_SHA}
  - ref: {CANDIDATE_KERNEL_SHA}
  - run: python script.py --authority-manifest policy/config/autonomous-release-authority.json
"""


def build_candidate(
    root: Path,
    *,
    workflow: str | None = None,
) -> tuple[Path, str, str]:
    repository = root / "candidate"
    (repository / "config").mkdir(parents=True)
    (repository / "tests" / "fixtures").mkdir(parents=True)
    (repository / ".github" / "workflows").mkdir(parents=True)
    gates = b'{"profiles":{}}\n'
    corpus = b'{"schema":"mindburn.release-permit-adversarial/v1","cases":[]}\n'
    (repository / "config" / "autonomous-release-gates.json").write_bytes(gates)
    (
        repository / "tests" / "fixtures" / "autonomous-release-adversarial.json"
    ).write_bytes(corpus)
    authority = {
        "schema": "mindburn.release-authority/v1",
        "generation": 2,
        "kernel_sha": CANDIDATE_KERNEL_SHA,
        "gate_profiles_sha256": hashlib.sha256(gates).hexdigest(),
        "adversarial_corpus_sha256": hashlib.sha256(corpus).hexdigest(),
        "parent": {"generation": 1, "workflow_sha": PARENT_SHA},
    }
    (repository / "config" / "autonomous-release-authority.json").write_text(
        json.dumps(authority, indent=2) + "\n",
        encoding="utf-8",
    )
    (repository / ".github" / "workflows" / "ci.yml").write_text(
        workflow or minimal_semantic_workflow(),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repository), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Permit Test"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "permit@example.test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", "candidate"], check=True
    )
    candidate_sha = git(repository, "rev-parse", "HEAD")
    return repository, candidate_sha, git(repository, "rev-parse", "HEAD^{tree}")


def build_permit(candidate_sha: str, candidate_tree: str) -> dict[str, object]:
    permit: dict[str, object] = {
        "schema": "mindburn.release-permit/v2",
        "permit_id": "",
        "decision": "ALLOW",
        "repository": "Mindburn-Labs/.github",
        "pull_request": 33,
        "base_ref": "refs/heads/main",
        "base_sha": "7" * 40,
        "head_sha": candidate_sha,
        "merge_sha": "8" * 40,
        "merge_tree_sha": candidate_tree,
        "workflow_repository": "Mindburn-Labs/.github",
        "workflow_path": ".github/workflows/ci.yml",
        "workflow_ref": "Mindburn-Labs/.github/.github/workflows/ci.yml@refs/heads/main",
        "workflow_sha": PARENT_SHA,
        "run_id": 101,
        "run_attempt": 1,
        "issued_at": "2026-07-14T10:00:00Z",
        "authority": {
            "schema": "mindburn.release-authority/v1",
            "generation": 1,
            "kernel_sha": PARENT_KERNEL_SHA,
            "gate_profiles_sha256": "9" * 64,
            "adversarial_corpus_sha256": "a" * 64,
            "parent": None,
        },
        "context_sha256": CONTEXT_SHA,
        "reviews": [
            {
                "reviewer": {"provider": "anthropic", "model": "claude-fable-5"},
                "verdict": "ALLOW",
                "response_sha256": RESPONSE_A,
                "blocking_findings": 0,
                "advisory_findings": 0,
            },
            {
                "reviewer": {"provider": "openai", "model": "gpt-5.6-sol"},
                "verdict": "ALLOW",
                "response_sha256": RESPONSE_B,
                "blocking_findings": 0,
                "advisory_findings": 1,
            },
        ],
        "reasons": [],
    }
    permit["permit_id"] = "sha256:" + "b" * 64
    return permit


def build_fake_verifier(root: Path, *, succeeds: bool = True) -> Path:
    verifier = root / "release-permit-verify"
    verifier.write_text(
        "#!/bin/sh\n" + ("exit 0\n" if succeeds else "echo rejected >&2\nexit 2\n"),
        encoding="utf-8",
    )
    verifier.chmod(0o700)
    return verifier


def verify_args(
    repository: Path,
    candidate_sha: str,
    permit_path: Path,
    verifier: Path,
) -> argparse.Namespace:
    trusted_context = permit_path.parent / "context.json"
    trusted_context.write_text("{}\n", encoding="utf-8")
    return argparse.Namespace(
        permit=permit_path,
        permit_verifier=verifier,
        trusted_context=trusted_context,
        candidate_repository=repository,
        candidate_sha=candidate_sha,
        candidate_pr=33,
        expected_run_id=101,
        expected_run_attempt=1,
        expected_parent_generation=1,
        expected_parent_workflow_sha=PARENT_SHA,
        output=None,
    )


class AuthorityPromotionTests(unittest.TestCase):
    def test_previous_generation_permit_ratifies_exact_successor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repository, candidate_sha, candidate_tree = build_candidate(root)
            permit_path = root / "permit.json"
            permit_path.write_text(
                json.dumps(build_permit(candidate_sha, candidate_tree), indent=2)
                + "\n",
                encoding="utf-8",
            )
            result = MODULE.verify(
                verify_args(
                    repository, candidate_sha, permit_path, build_fake_verifier(root)
                ),
            )
        self.assertEqual(result["candidate_generation"], 2)
        self.assertEqual(result["parent_workflow_sha"], PARENT_SHA)

    def test_tree_or_permit_substitution_fails_closed(self) -> None:
        for mutation, message in (
            ("tree", "merge tree"),
            ("permit", "permit_id"),
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as tmpdir,
            ):
                root = Path(tmpdir)
                repository, candidate_sha, candidate_tree = build_candidate(root)
                permit = build_permit(candidate_sha, candidate_tree)
                if mutation == "tree":
                    permit["merge_tree_sha"] = "b" * 40
                else:
                    permit["permit_id"] = "invalid"
                permit_path = root / "permit.json"
                permit_path.write_text(json.dumps(permit) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(MODULE.PermitInputError, message):
                    MODULE.verify(
                        verify_args(
                            repository,
                            candidate_sha,
                            permit_path,
                            build_fake_verifier(root),
                        ),
                    )

    def test_kernel_rejection_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repository, candidate_sha, candidate_tree = build_candidate(root)
            permit_path = root / "permit.json"
            permit_path.write_text(
                json.dumps(build_permit(candidate_sha, candidate_tree)) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.PermitInputError, "pinned Kernel rejected"
            ):
                    MODULE.verify(
                        verify_args(
                            repository,
                            candidate_sha,
                            permit_path,
                            build_fake_verifier(root, succeeds=False),
                        ),
                    )


class CandidateWorkflowSemanticsTests(unittest.TestCase):
    def test_valid_minimal_semantic_fixture(self) -> None:
        MODULE.validate_candidate_workflow(
            minimal_semantic_workflow(),
            kernel_sha=CANDIDATE_KERNEL_SHA,
        )

    def test_repository_candidate_workflow_is_semantically_valid(self) -> None:
        authority = json.loads(
            (ROOT / "config" / "autonomous-release-authority.json").read_text(
                encoding="utf-8"
            )
        )
        MODULE.validate_candidate_workflow(
            (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"),
            kernel_sha=authority["kernel_sha"],
        )

    def test_legacy_lexical_fixture_cannot_satisfy_semantic_validation(self) -> None:
        with self.assertRaisesRegex(MODULE.PermitInputError, "workflow jobs"):
            MODULE.validate_candidate_workflow(
                legacy_lexical_workflow(),
                kernel_sha=CANDIDATE_KERNEL_SHA,
            )

    def test_comments_cannot_supply_kernel_pin_evidence(self) -> None:
        wrong_ref = minimal_semantic_workflow().replace(
            f"ref: {CANDIDATE_KERNEL_SHA}",
            f"ref: {'d' * 40}",
            1,
        )
        comment_padded = (
            wrong_ref
            + f"# ref: {CANDIDATE_KERNEL_SHA}\n"
            + f"# ref: {CANDIDATE_KERNEL_SHA}\n"
        )
        with self.assertRaisesRegex(
            MODULE.PermitInputError,
            "prepare Kernel checkout ref",
        ):
            MODULE.validate_candidate_workflow(
                comment_padded,
                kernel_sha=CANDIDATE_KERNEL_SHA,
            )

    def test_wrong_kernel_checkout_semantics_fail_closed(self) -> None:
        cases = (
            (
                "action",
                minimal_semantic_workflow().replace(
                    f"uses: {MODULE.CHECKOUT_ACTION}",
                    "uses: actions/checkout@v4",
                    1,
                ),
                "prepare Kernel checkout must use the pinned checkout action",
            ),
            (
                "repository",
                minimal_semantic_workflow().replace(
                    f"repository: {MODULE.KERNEL_REPOSITORY}",
                    "repository: Mindburn-Labs/not-the-kernel",
                    1,
                ),
                "prepare Kernel checkout repository",
            ),
            (
                "ref",
                minimal_semantic_workflow().replace(
                    f"ref: {CANDIDATE_KERNEL_SHA}",
                    f"ref: {'d' * 40}",
                    1,
                ),
                "prepare Kernel checkout ref",
            ),
            (
                "persisted credentials",
                minimal_semantic_workflow().replace(
                    "persist-credentials: false",
                    "persist-credentials: true",
                    1,
                ),
                "prepare Kernel checkout must disable persisted credentials",
            ),
            (
                "path",
                minimal_semantic_workflow().replace(
                    f"path: {MODULE.PREPARE_KERNEL_PATH}",
                    "path: rogue-kernel",
                    1,
                ),
                "prepare Kernel checkout path",
            ),
            (
                "permit path",
                minimal_semantic_workflow().replace(
                    f"path: {MODULE.PERMIT_KERNEL_PATH}",
                    "path: rogue-permit-kernel",
                    1,
                ),
                "permit Kernel checkout path",
            ),
            (
                "sparse paths",
                minimal_semantic_workflow().replace(
                    "core/cmd/release-permit-verify",
                    "core/cmd/not-the-verifier",
                    1,
                ),
                "prepare Kernel checkout sparse checkout paths",
            ),
        )
        for name, workflow, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(MODULE.PermitInputError, message):
                    MODULE.validate_candidate_workflow(
                        workflow,
                        kernel_sha=CANDIDATE_KERNEL_SHA,
                    )

    def test_prepare_kernel_sha_environment_is_bound_to_authority(self) -> None:
        workflow = minimal_semantic_workflow().replace(
            f"KERNEL_SHA: {CANDIDATE_KERNEL_SHA}",
            f"KERNEL_SHA: {'d' * 40}",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.PermitInputError,
            "prepare KERNEL_SHA is not the authority Kernel SHA",
        ):
            MODULE.validate_candidate_workflow(
                workflow,
                kernel_sha=CANDIDATE_KERNEL_SHA,
            )

    def test_missing_authority_manifest_binding_fails_closed(self) -> None:
        workflow = minimal_semantic_workflow().replace(
            "--authority-manifest policy/config/autonomous-release-authority.json",
            "--missing-authority-manifest",
            1,
        )
        with self.assertRaisesRegex(
            MODULE.PermitInputError,
            "prepare command has an unexpected semantic shape",
        ):
            MODULE.validate_candidate_workflow(
                workflow,
                kernel_sha=CANDIDATE_KERNEL_SHA,
            )

    def test_duplicate_keys_and_aliases_fail_before_semantic_lookup(self) -> None:
        duplicate = minimal_semantic_workflow().replace(
            "  permit:\n",
            "  prepare:\n    steps: []\n  permit:\n",
            1,
        )
        alias = (
            "shared: &shared\n"
            "  ignored: true\n"
            "alias: *shared\n"
            + minimal_semantic_workflow()
        )
        for name, workflow, message in (
            ("duplicate", duplicate, "duplicate YAML key: prepare"),
            ("alias", alias, "YAML aliases or anchors"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(MODULE.PermitInputError, message):
                    MODULE.validate_candidate_workflow(
                        workflow,
                        kernel_sha=CANDIDATE_KERNEL_SHA,
                    )

    def test_malformed_prepare_command_and_alternate_execution_fail_closed(self) -> None:
        malformed = minimal_semantic_workflow().replace(
            "policy/scripts/autonomous_release_permit.py prepare",
            "policy/scripts/not-the-permit-builder.py prepare",
            1,
        )
        alternate_kernel = minimal_semantic_workflow().replace(
            "  permit:\n",
            f"""      - name: Rogue Kernel checkout
        uses: {MODULE.CHECKOUT_ACTION}
        with:
          repository: {MODULE.KERNEL_REPOSITORY}
          ref: {CANDIDATE_KERNEL_SHA}
          persist-credentials: false
          path: rogue-kernel
  permit:
""",
            1,
        )
        alternate_command = minimal_semantic_workflow().replace(
            "  permit:\n",
            """      - name: Rogue permit builder
        run: |
          bash -c 'python3 policy/scripts/autonomous_release_permit.py prepare'
  permit:
""",
            1,
        )
        copy_injection = minimal_semantic_workflow().replace(
            "  permit:\n",
            """      - name: Package immutable read-only review runtime
        run: |
          cp policy/scripts/autonomous_release_permit.py autonomous-review-runtime/policy/scripts/autonomous_release_permit.py; bash -c 'python3 policy/scripts/autonomous_release_permit.py prepare'
  permit:
""",
            1,
        )
        for name, workflow, message in (
            ("malformed", malformed, "prepare command has an unexpected semantic shape"),
            ("alternate kernel", alternate_kernel, "alternate Kernel checkout"),
            (
                "alternate command",
                alternate_command,
                "alternate permit-builder command",
            ),
            (
                "copy injection",
                copy_injection,
                "alternate permit-builder command",
            ),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(MODULE.PermitInputError, message):
                    MODULE.validate_candidate_workflow(
                        workflow,
                        kernel_sha=CANDIDATE_KERNEL_SHA,
                    )


if __name__ == "__main__":
    unittest.main()
