from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
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


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise AssertionError(f"expected exactly one occurrence of {old!r}")
    return source.replace(old, new, 1)


def replace_after(source: str, anchor: str, old: str, new: str) -> str:
    before, separator, after = source.partition(anchor)
    if not separator:
        raise AssertionError(f"missing anchor {anchor!r}")
    if old not in after:
        raise AssertionError(f"missing text after anchor {old!r}")
    return before + separator + after.replace(old, new, 1)


def authority_workflow_fixture(kernel_sha: str = CANDIDATE_KERNEL_SHA) -> str:
    authority = json.loads(
        (ROOT / "config" / "autonomous-release-authority.json").read_text(
            encoding="utf-8"
        )
    )
    parent_kernel_sha = authority["kernel_sha"]
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    if workflow.count(parent_kernel_sha) != 4:
        raise AssertionError("authority workflow must expose exactly four Kernel bindings")
    return workflow.replace(parent_kernel_sha, kernel_sha)


def build_candidate(
    root: Path,
    *,
    workflow: str | None = None,
) -> tuple[Path, str, str]:
    repository = root / "candidate"
    (repository / "config").mkdir(parents=True)
    (repository / "tests" / "fixtures").mkdir(parents=True)
    shutil.copytree(
        ROOT / ".github" / "workflows",
        repository / ".github" / "workflows",
    )
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
        workflow or authority_workflow_fixture(),
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repository), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Permit Test"],
        check=True,
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


def commit_candidate(repository: Path, *, message: str = "candidate mutation") -> tuple[str, str]:
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", message],
        check=True,
    )
    return (
        git(repository, "rev-parse", "HEAD"),
        git(repository, "rev-parse", "HEAD^{tree}"),
    )


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
    def assert_inventory_rejected(self, mutation) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repository, _, _ = build_candidate(root)
            mutation(repository)
            candidate_sha, candidate_tree = commit_candidate(repository)
            permit_path = root / "permit.json"
            permit_path.write_text(
                json.dumps(build_permit(candidate_sha, candidate_tree)) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.PermitInputError,
                "workflow inventory|non-authority workflow",
            ):
                MODULE.verify(
                    verify_args(
                        repository,
                        candidate_sha,
                        permit_path,
                        build_fake_verifier(root),
                    ),
                )

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

    def test_candidate_exact_ci_cannot_add_unreviewed_authority_workflow(self) -> None:
        def add_unreviewed_workflow(repository: Path) -> None:
            workflow = repository / ".github" / "workflows" / "unreviewed-main.yml"
            workflow.write_text(
                "name: Unreviewed authority surface\n"
                "on:\n"
                "  push:\n"
                "    branches: [main]\n"
                "jobs:\n"
                "  execute:\n"
                "    runs-on: ubuntu-latest\n"
                "    environment: authority-promotion\n"
                "    steps:\n"
                "      - run: true\n",
                encoding="utf-8",
            )

        self.assert_inventory_rejected(add_unreviewed_workflow)

    def test_candidate_workflow_inventory_rejects_add_delete_mutation_and_symlink(self) -> None:
        def add_nested_workflow(repository: Path) -> None:
            nested = repository / ".github" / "workflows" / "nested"
            nested.mkdir()
            (nested / "unreviewed.yml").write_text("name: unreviewed\n", encoding="utf-8")

        def delete_workflow(repository: Path) -> None:
            (repository / ".github" / "workflows" / "docs-truth.yml").unlink()

        def mutate_workflow(repository: Path) -> None:
            workflow = repository / ".github" / "workflows" / "docs-truth.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8") + "\n# candidate mutation\n",
                encoding="utf-8",
            )

        def symlink_workflow(repository: Path) -> None:
            workflow = repository / ".github" / "workflows" / "docs-truth.yml"
            workflow.unlink()
            workflow.symlink_to("docs-truth-public.yml")

        for name, mutation in (
            ("nested", add_nested_workflow),
            ("delete", delete_workflow),
            ("mutation", mutate_workflow),
            ("symlink", symlink_workflow),
        ):
            with self.subTest(name=name):
                self.assert_inventory_rejected(mutation)

    def test_candidate_workflow_inventory_rejects_gitlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repository, _, _ = build_candidate(root)
            path = ".github/workflows/promote-authority.yml"
            subprocess.run(
                ["git", "-C", str(repository), "rm", "--cached", path],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    f"160000,{'f' * 40},{path}",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-m", "candidate gitlink"],
                check=True,
            )
            candidate_sha = git(repository, "rev-parse", "HEAD")
            candidate_tree = git(repository, "rev-parse", "HEAD^{tree}")
            permit_path = root / "permit.json"
            permit_path.write_text(
                json.dumps(build_permit(candidate_sha, candidate_tree)) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.PermitInputError, "workflow inventory"):
                MODULE.verify(
                    verify_args(
                        repository,
                        candidate_sha,
                        permit_path,
                        build_fake_verifier(root),
                    ),
                )


class CandidateWorkflowContractTests(unittest.TestCase):
    def assert_rejected(self, workflow: str) -> None:
        with self.assertRaisesRegex(
            MODULE.PermitInputError,
            "(authority contract|machine-approval|triggers|isolated App token)",
        ):
            MODULE.validate_candidate_workflow(
                workflow,
                kernel_sha=CANDIDATE_KERNEL_SHA,
            )

    def test_valid_complete_parent_owned_fixture(self) -> None:
        MODULE.validate_candidate_workflow(
            authority_workflow_fixture(),
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

    def test_only_declared_kernel_bindings_may_differ(self) -> None:
        wrong_kernel = authority_workflow_fixture().replace(
            CANDIDATE_KERNEL_SHA,
            "d" * 40,
            1,
        )
        self.assert_rejected(wrong_kernel)

    def test_comments_cannot_supply_authority_evidence(self) -> None:
        wrong_kernel = authority_workflow_fixture().replace(
            CANDIDATE_KERNEL_SHA,
            "d" * 40,
            1,
        )
        self.assert_rejected(wrong_kernel + f"# ref: {CANDIDATE_KERNEL_SHA}\n")

    def test_strict_yaml_rejects_duplicate_keys_aliases_and_tags(self) -> None:
        workflow = authority_workflow_fixture()
        duplicate = workflow.replace(
            "  permit:\n",
            "  prepare:\n    steps: []\n  permit:\n",
            1,
        )
        alias = "shared: &shared\n  ignored: true\nalias: *shared\n" + workflow
        tagged = workflow.replace(
            "name: HELM Autonomous Release Permit",
            'name: !unsafe "HELM Autonomous Release Permit"',
            1,
        )
        for name, malformed, message in (
            ("duplicate", duplicate, "duplicate YAML key: prepare"),
            ("alias", alias, "YAML aliases or anchors"),
            ("tag", tagged, "YAML tags are not allowed"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(MODULE.PermitInputError, message):
                    MODULE.validate_candidate_workflow(
                        malformed,
                        kernel_sha=CANDIDATE_KERNEL_SHA,
                    )

    def test_strict_yaml_rejects_mapping_and_sequence_tags(self) -> None:
        for name, malformed in (
            ("mapping", "!unsafe {name: authority}\n"),
            ("sequence", "!unsafe [authority]\n"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(MODULE.PermitInputError, "YAML tags are not allowed"):
                    MODULE.parse_strict_workflow_yaml(malformed)

    def test_yaml_on_key_is_not_coerced_to_boolean(self) -> None:
        self.assert_rejected(
            replace_once(authority_workflow_fixture(), "\non:\n", "\ntrue:\n")
        )

    def test_complete_contract_rejects_reviewed_bypass_mutations(self) -> None:
        workflow = authority_workflow_fixture()
        policy_anchor = "      - name: Checkout pinned policy helpers\n"
        approval_broker_anchor = "      - name: Checkout immutable approval broker\n"
        permit_anchor = "  permit:\n    name: HELM Autonomous Release Permit\n"
        machine_anchor = "  machine-approval:\n"
        approval_step = "      - name: Approve only the exact signed head\n"
        cases = {
            "top-level permission escalation": replace_once(
                workflow,
                "permissions: {}\n",
                "permissions:\n  contents: write\n",
            ),
            "top-level defaults": replace_once(
                workflow,
                "permissions: {}\n",
                "permissions: {}\n"
                "defaults:\n"
                "  run:\n"
                "    shell: /bin/zsh\n",
            ),
            "top-level concurrency": replace_once(
                workflow,
                "permissions: {}\n",
                "permissions: {}\n"
                "concurrency:\n"
                "  group: authority-bypass\n",
            ),
            "false condition": replace_once(
                workflow,
                "needs.model-review.result == 'success'",
                "false",
            ),
            "job graph rebind": replace_after(
                workflow,
                machine_anchor,
                "    needs: permit\n",
                "    needs: prepare\n",
            ),
            "job working directory": replace_after(
                workflow,
                permit_anchor,
                "    runs-on: ubuntu-latest\n",
                "    runs-on: ubuntu-latest\n"
                "    defaults:\n"
                "      run:\n"
                "        working-directory: /tmp\n",
            ),
            "step working directory": replace_after(
                workflow,
                "  permit:\n",
                "        working-directory: kernel/core\n",
                "        working-directory: /tmp\n",
            ),
            "custom shell": replace_after(
                workflow,
                "  permit:\n",
                '        run: go build -trimpath -o "$GITHUB_WORKSPACE/release-permit-verify" ./cmd/release-permit-verify\n',
                "        shell: /bin/zsh\n"
                '        run: go build -trimpath -o "$GITHUB_WORKSPACE/release-permit-verify" ./cmd/release-permit-verify\n',
            ),
            "continue on error": replace_after(
                workflow,
                "      - name: Validate repository contract and workspace truth\n",
                "        run: REQUIRE_WORKSPACE_CONTEXT=0 make lint test\n",
                "        continue-on-error: true\n"
                "        run: REQUIRE_WORKSPACE_CONTEXT=0 make lint test\n",
            ),
            "policy checkout repoint": replace_after(
                workflow,
                policy_anchor,
                "          repository: Mindburn-Labs/.github\n",
                "          repository: Mindburn-Labs/attacker-policy\n",
            ),
            "workflow SHA rebind": replace_after(
                workflow,
                approval_broker_anchor,
                "          ref: ${{ github.workflow_sha }}\n",
                "          ref: ${{ github.sha }}\n",
            ),
            "caps rebind": replace_once(
                workflow,
                '          MAX_PATCH_BYTES: "524288"\n',
                '          MAX_PATCH_BYTES: "999999"\n',
            ),
            "approval Kernel repoint": replace_after(
                workflow,
                machine_anchor,
                f"          ref: {CANDIDATE_KERNEL_SHA}\n",
                f"          ref: {'d' * 40}\n",
            ),
            "approval verifier build redirect": replace_after(
                workflow,
                machine_anchor,
                "        working-directory: kernel/core\n",
                "        working-directory: /tmp\n",
            ),
            "raw approval after App token": replace_after(
                workflow,
                "      - name: Bind exact approval App identity\n",
                '          test "$INSTALLATION_ID" = "146576964"\n',
                '          test "$INSTALLATION_ID" = "146576964"\n'
                '          gh pr review --approve "$GITHUB_REPOSITORY"\n',
            ),
            "extra approval step": replace_once(
                workflow,
                approval_step,
                "      - name: Extra approval bypass\n"
                "        run: echo unexpected\n"
                + approval_step,
            ),
            "extra trigger": replace_once(
                workflow,
                "  push:\n",
                "  workflow_dispatch:\n  push:\n",
            ),
            "extra job": workflow
            + "\n  rogue:\n    runs-on: ubuntu-latest\n    steps: []\n",
            "git clone": replace_once(
                workflow,
                "        run: REQUIRE_WORKSPACE_CONTEXT=0 make lint test\n",
                "        run: |\n"
                "          REQUIRE_WORKSPACE_CONTEXT=0 make lint test\n"
                "          git clone https://example.invalid/rogue.git\n",
            ),
            "escaped permit filename": replace_once(
                workflow,
                "            --permit approval/release-permit.json \\\n",
                "            --permit ../approval/release-permit.json \\\n",
            ),
            "action SHA rebind": replace_after(
                workflow,
                "      - name: Checkout repository\n",
                f"        uses: {MODULE.CHECKOUT_ACTION}\n",
                "        uses: actions/checkout@v4\n",
            ),
            "environment rebind": replace_once(
                workflow,
                '          CI: "true"\n',
                '          CI: "false"\n',
            ),
        }
        for name, mutated in cases.items():
            with self.subTest(name=name):
                self.assert_rejected(mutated)

    def test_machine_app_token_has_exactly_one_approval_consumer(self) -> None:
        self.assert_rejected(
            replace_after(
                authority_workflow_fixture(),
                "      - name: Bind exact approval App identity\n",
                "          APP_SLUG: ${{ steps.approver-token.outputs.app-slug }}\n",
                "          APP_SLUG: ${{ steps.approver-token.outputs.app-slug }}\n"
                "          TOKEN: ${{ steps.approver-token.outputs.token }}\n",
            )
        )

    def test_minimal_or_lexical_fixture_cannot_satisfy_complete_contract(self) -> None:
        with self.assertRaisesRegex(MODULE.PermitInputError, "authority contract"):
            MODULE.validate_candidate_workflow(
                "name: permit\njobs: {}\n",
                kernel_sha=CANDIDATE_KERNEL_SHA,
            )


if __name__ == "__main__":
    unittest.main()
