from __future__ import annotations

import importlib.util
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
) -> tuple[Path, str, str, str]:
    source = root / "source"
    workflows = source / ".github" / "workflows"
    workflows.mkdir(parents=True)
    run(source, "init", "-b", "main")
    run(source, "config", "user.name", "Workflow Test")
    run(source, "config", "user.email", "workflow@example.test")
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

        for name, mutation in (("add", add), ("delete", delete), ("mutate", mutate), ("symlink", symlink), ("gitlink", gitlink)):
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
