from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_workflow_tree.py"
SPEC = importlib.util.spec_from_file_location("verify_workflow_tree", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def git(repository: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(repository), *arguments], text=True).strip()


def run(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def commit(repository: Path, message: str, *, stage: bool = True) -> str:
    if stage:
        run(repository, "add", "-A")
    run(repository, "commit", "-m", message)
    return git(repository, "rev-parse", "HEAD")


def create_pull_request_graph(
    root: Path,
    candidate_mutation: Callable[[Path], bool] | None = None,
    *,
    include_ci: bool = True,
) -> tuple[Path, str, str, str]:
    source = root / "source"
    workflows = source / ".github" / "workflows"
    workflows.mkdir(parents=True)
    run(source, "init", "-b", "main")
    run(source, "config", "user.name", "Workflow Test")
    run(source, "config", "user.email", "workflow@example.test")
    if include_ci:
        (workflows / "ci.yml").write_text("name: candidate\n", encoding="utf-8")
    (workflows / "docs-truth.yml").write_text("name: docs\n", encoding="utf-8")
    commit(source, "initial")

    run(source, "checkout", "-b", "candidate")
    stage = True
    if candidate_mutation is None:
        (source / "candidate.md").write_text("candidate\n", encoding="utf-8")
    else:
        stage = candidate_mutation(source)
    head_sha = commit(source, "candidate", stage=stage)

    run(source, "checkout", "main")
    (source / "base.md").write_text("base\n", encoding="utf-8")
    base_sha = commit(source, "base")
    run(source, "merge", "--no-ff", "candidate", "-m", "merge candidate")
    merge_sha = git(source, "rev-parse", "HEAD")
    return source, base_sha, head_sha, merge_sha


def bare_store(root: Path, source: Path, *, head_ref: str = "main") -> Path:
    store = root / f"{head_ref}.git"
    subprocess.run(
        ["git", "clone", "--bare", str(source), str(store)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    run(store, "symbolic-ref", "HEAD", f"refs/heads/{head_ref}")
    return store


def object_receipt(
    *,
    base_sha: str,
    head_sha: str,
    merge_sha: str,
    repository: str = "Mindburn-Labs/.github",
) -> dict[str, object]:
    return {
        "schema": "mindburn.authority-bare-git-input/v2",
        "admission": {
            "schema": "mindburn.authority-pr-admission/v1",
            "repository": repository,
            "pr_number": 7,
            "base": {"ref": "main", "sha": base_sha},
            "head": {"repository": repository, "sha": head_sha},
            "merge_sha": merge_sha,
            "workflow_run_head_sha": head_sha,
        },
        "merge_parents": [base_sha, head_sha],
    }


class WorkflowTreeTests(unittest.TestCase):
    def test_source_only_reads_git_objects_without_checkout_or_shell_execution(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn('"checkout"', source)
        self.assertNotIn('"clone"', source)
        self.assertNotIn("shell=True", source)
        self.assertIn('"ls-tree"', source)
        self.assertIn('"show"', source)
        self.assertIn('"rev-parse"', source)
        self.assertIn('"--is-bare-repository"', source)

    def test_exact_bound_merge_is_admitted_in_shadow_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source, base_sha, head_sha, merge_sha = create_pull_request_graph(Path(temporary))
            store = bare_store(Path(temporary), source)
            result = MODULE.verify(
                parent_repository=source,
                parent_sha=base_sha,
                candidate_repository=store,
                candidate_sha=head_sha,
                merge_sha=merge_sha,
            )
        self.assertEqual(result["mode"], "shadow-exact-tree")
        self.assertEqual(result["candidate_sha"], head_sha)
        self.assertEqual(result["merge_sha"], merge_sha)
        self.assertEqual(result["workflow_paths"], [".github/workflows/ci.yml", ".github/workflows/docs-truth.yml"])

    def test_app_docs_profile_requires_docs_truth_anchor_and_entire_tree_equality(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base_sha, head_sha, merge_sha = create_pull_request_graph(
                root,
                include_ci=False,
            )
            store = bare_store(root, source)
            receipt_path = root / "object-receipt.json"
            receipt_path.write_text(
                json.dumps(
                    object_receipt(
                        base_sha=base_sha,
                        head_sha=head_sha,
                        merge_sha=merge_sha,
                        repository="Mindburn-Labs/app-helm-docs",
                    ),
                ),
                encoding="utf-8",
            )
            result = MODULE.verify_object_receipt(
                parent_repository=store,
                candidate_repository=store,
                object_receipt=receipt_path,
                profile="app-helm-docs",
            )
            self.assertEqual(result["profile"], "app-helm-docs")
            self.assertEqual(result["workflow_paths"], [".github/workflows/docs-truth.yml"])

            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify_object_receipt(
                    parent_repository=store,
                    candidate_repository=store,
                    object_receipt=receipt_path,
                    profile=".github",
                )

    def test_app_docs_profile_rejects_candidate_ignore_configuration(self) -> None:
        def inject_ignore(repository: Path) -> bool:
            (repository / "docs-truth.yaml").write_text(
                "ignored_paths:\n  - '**'\n",
                encoding="utf-8",
            )
            return True

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base_sha, head_sha, merge_sha = create_pull_request_graph(
                root,
                inject_ignore,
                include_ci=False,
            )
            store = bare_store(root, source)
            receipt_path = root / "object-receipt.json"
            receipt_path.write_text(
                json.dumps(
                    object_receipt(
                        base_sha=base_sha,
                        head_sha=head_sha,
                        merge_sha=merge_sha,
                        repository="Mindburn-Labs/app-helm-docs",
                    ),
                ),
                encoding="utf-8",
            )
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify_object_receipt(
                    parent_repository=store,
                    candidate_repository=store,
                    object_receipt=receipt_path,
                    profile="app-helm-docs",
                )

    def test_inert_materialization_rejects_candidate_execution_modes_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base_sha, head_sha, merge_sha = create_pull_request_graph(root)
            store = bare_store(root, source)
            receipt_path = root / "object-receipt.json"
            receipt_path.write_text(
                json.dumps(object_receipt(base_sha=base_sha, head_sha=head_sha, merge_sha=merge_sha)),
                encoding="utf-8",
            )
            destination = root / "materialized"
            index_file = root / "candidate.index"
            result = MODULE.verify_object_receipt(
                parent_repository=store,
                candidate_repository=store,
                object_receipt=receipt_path,
                materialize_directory=destination,
                index_file=index_file,
            )
            self.assertGreater(result["materialized"]["file_count"], 0)
            self.assertEqual((destination / "candidate.md").read_text(encoding="utf-8"), "candidate\n")
            self.assertEqual((destination / "candidate.md").stat().st_mode & 0o777, 0o600)
            self.assertFalse((destination / ".git").exists())
            self.assertEqual(result["index"], "trusted-read-tree")
            environment = os.environ.copy()
            environment.update(
                {
                    "GIT_DIR": str(store),
                    "GIT_INDEX_FILE": str(index_file),
                    "GIT_WORK_TREE": str(destination),
                },
            )
            tracked = subprocess.check_output(
                ["git", "ls-files", "--", "*.md"],
                env=environment,
                text=True,
            ).splitlines()
            self.assertEqual(tracked, ["base.md", "candidate.md"])

        def executable(repository: Path) -> bool:
            script = repository / "candidate.sh"
            script.write_text("exit 0\n", encoding="utf-8")
            script.chmod(0o755)
            return True

        def symlink(repository: Path) -> bool:
            (repository / "candidate-link").symlink_to("candidate.md")
            return True

        for name, mutation in (("executable", executable), ("symlink", symlink)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, base_sha, head_sha, merge_sha = create_pull_request_graph(root, mutation)
                store = bare_store(root, source)
                receipt_path = root / "object-receipt.json"
                receipt_path.write_text(
                    json.dumps(object_receipt(base_sha=base_sha, head_sha=head_sha, merge_sha=merge_sha)),
                    encoding="utf-8",
                )
                with self.assertRaises(MODULE.WorkflowTreeError):
                    MODULE.verify_object_receipt(
                        parent_repository=store,
                        candidate_repository=store,
                        object_receipt=receipt_path,
                        materialize_directory=root / "materialized",
                    )

    def test_single_object_receipt_rejects_mixed_snapshot_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base_sha, head_sha, merge_sha = create_pull_request_graph(root)
            store = bare_store(root, source)
            receipt_path = root / "object-receipt.json"
            receipt = object_receipt(base_sha=base_sha, head_sha=head_sha, merge_sha=merge_sha)
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            result = MODULE.verify_object_receipt(
                parent_repository=source,
                candidate_repository=store,
                object_receipt=receipt_path,
            )
            self.assertEqual(result["admission"]["workflow_run_head_sha"], head_sha)
            self.assertEqual(result["object_receipt_schema"], "mindburn.authority-bare-git-input/v2")

            invalid_cases = []
            mismatched_run = json.loads(json.dumps(receipt))
            mismatched_run["admission"]["workflow_run_head_sha"] = "a" * 40
            invalid_cases.append(mismatched_run)
            fork = json.loads(json.dumps(receipt))
            fork["admission"]["head"]["repository"] = "Mindburn-Labs/fork"
            invalid_cases.append(fork)
            wrong_parents = json.loads(json.dumps(receipt))
            wrong_parents["merge_parents"] = [head_sha, base_sha]
            invalid_cases.append(wrong_parents)
            unknown = json.loads(json.dumps(receipt))
            unknown["unexpected"] = True
            invalid_cases.append(unknown)
            for index, invalid in enumerate(invalid_cases):
                with self.subTest(index=index):
                    receipt_path.write_text(json.dumps(invalid), encoding="utf-8")
                    with self.assertRaises(MODULE.WorkflowTreeError):
                        MODULE.verify_object_receipt(
                            parent_repository=source,
                            candidate_repository=store,
                            object_receipt=receipt_path,
                        )

            receipt_path.write_text('{"schema": "one", "schema": "two"}', encoding="utf-8")
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify_object_receipt(
                    parent_repository=source,
                    candidate_repository=store,
                    object_receipt=receipt_path,
                )
            receipt_path.write_bytes(b"x" * (MODULE.MAX_OBJECT_RECEIPT_BYTES + 1))
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify_object_receipt(
                    parent_repository=source,
                    candidate_repository=store,
                    object_receipt=receipt_path,
                )

    def test_candidate_workflow_add_delete_mutation_symlink_and_gitlink_fail_closed(self) -> None:
        def add(repository: Path) -> bool:
            (repository / ".github" / "workflows" / "unreviewed.yml").write_text("name: unsafe\n", encoding="utf-8")
            return True

        def delete(repository: Path) -> bool:
            (repository / ".github" / "workflows" / "docs-truth.yml").unlink()
            return True

        def mutate(repository: Path) -> bool:
            (repository / ".github" / "workflows" / "ci.yml").write_text("name: altered\n", encoding="utf-8")
            return True

        def inject_secret_environment(repository: Path) -> bool:
            (repository / ".github" / "workflows" / "docs-truth.yml").write_text(
                "name: docs\nenv:\n  TOKEN: ${{ secrets.MINDBURN_ORG_READ_TOKEN }}\n",
                encoding="utf-8",
            )
            return True

        def substitute_runner(repository: Path) -> bool:
            (repository / ".github" / "workflows" / "docs-truth.yml").write_text(
                "name: docs\njobs:\n  docs:\n    runs-on: self-hosted\n",
                encoding="utf-8",
            )
            return True

        def symlink(repository: Path) -> bool:
            path = repository / ".github" / "workflows" / "docs-truth.yml"
            path.unlink()
            path.symlink_to("ci.yml")
            return True

        def gitlink(repository: Path) -> bool:
            path = ".github/workflows/docs-truth.yml"
            run(repository, "add", "-A")
            run(repository, "rm", "--cached", path)
            run(
                repository,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{'f' * 40},{path}",
            )
            return False

        for name, mutation in (
            ("add", add),
            ("delete", delete),
            ("mutate", mutate),
            ("secret-environment", inject_secret_environment),
            ("runner-substitution", substitute_runner),
            ("symlink", symlink),
            ("gitlink", gitlink),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                source, base_sha, head_sha, merge_sha = create_pull_request_graph(Path(temporary), mutation)
                store = bare_store(Path(temporary), source)
                with self.assertRaises(MODULE.WorkflowTreeError):
                    MODULE.verify(
                        parent_repository=source,
                        parent_sha=base_sha,
                        candidate_repository=store,
                        candidate_sha=head_sha,
                        merge_sha=merge_sha,
                    )

    def test_forged_merge_tree_with_correct_parents_but_changed_workflow_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base_sha, head_sha, _ = create_pull_request_graph(root)
            run(source, "checkout", "--detach", base_sha)
            (source / ".github" / "workflows" / "ci.yml").write_text("name: forged\n", encoding="utf-8")
            run(source, "add", ".github/workflows/ci.yml")
            tree_sha = git(source, "write-tree")
            forged_merge = subprocess.check_output(
                ["git", "-C", str(source), "commit-tree", tree_sha, "-p", base_sha, "-p", head_sha],
                input="forged merge\n",
                text=True,
            ).strip()
            run(source, "update-ref", "refs/heads/forged", forged_merge)
            store = bare_store(root, source, head_ref="forged")
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify(
                    parent_repository=source,
                    parent_sha=base_sha,
                    candidate_repository=store,
                    candidate_sha=head_sha,
                    merge_sha=forged_merge,
                )

    def test_nonbare_store_wrong_head_wrong_parent_order_and_non_sha_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, base_sha, head_sha, merge_sha = create_pull_request_graph(root)
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify(
                    parent_repository=source,
                    parent_sha=base_sha,
                    candidate_repository=source,
                    candidate_sha=head_sha,
                    merge_sha=merge_sha,
                )

            store = bare_store(root, source)
            run(store, "symbolic-ref", "HEAD", "refs/heads/candidate")
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify(
                    parent_repository=source,
                    parent_sha=base_sha,
                    candidate_repository=store,
                    candidate_sha=head_sha,
                    merge_sha=merge_sha,
                )

            tree_sha = git(source, "rev-parse", f"{merge_sha}^{{tree}}")
            swapped_merge = subprocess.check_output(
                ["git", "-C", str(source), "commit-tree", tree_sha, "-p", head_sha, "-p", base_sha],
                input="swapped merge\n",
                text=True,
            ).strip()
            run(source, "update-ref", "refs/heads/swapped", swapped_merge)
            swapped_store = bare_store(root, source, head_ref="swapped")
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify(
                    parent_repository=source,
                    parent_sha=base_sha,
                    candidate_repository=swapped_store,
                    candidate_sha=head_sha,
                    merge_sha=swapped_merge,
                )
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify(
                    parent_repository=source,
                    parent_sha=base_sha,
                    candidate_repository=swapped_store,
                    candidate_sha=head_sha,
                    merge_sha="main",
                )


if __name__ == "__main__":
    unittest.main()
