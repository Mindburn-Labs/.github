from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


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


def commit(repository: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-m", message], check=True)
    return git(repository, "rev-parse", "HEAD")


def initialize_repository(root: Path, name: str) -> tuple[Path, str]:
    repository = root / name
    workflows = repository / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: candidate\n", encoding="utf-8")
    (workflows / "docs-truth.yml").write_text("name: docs\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "init", "-b", "main"], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Workflow Test"], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.email", "workflow@example.test"], check=True)
    return repository, commit(repository, "parent")


class WorkflowTreeTests(unittest.TestCase):
    def test_exact_candidate_is_admitted_in_shadow_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, parent_sha = initialize_repository(root, "parent")
            candidate = root / "candidate"
            shutil.copytree(parent, candidate, ignore=shutil.ignore_patterns(".git"))
            subprocess.run(["git", "-C", str(candidate), "init", "-b", "main"], check=True)
            subprocess.run(["git", "-C", str(candidate), "config", "user.name", "Workflow Test"], check=True)
            subprocess.run(["git", "-C", str(candidate), "config", "user.email", "workflow@example.test"], check=True)
            candidate_sha = commit(candidate, "candidate")
            result = MODULE.verify(
                parent_repository=parent,
                parent_sha=parent_sha,
                candidate_repository=candidate,
                candidate_sha=candidate_sha,
            )
        self.assertEqual(result["mode"], "shadow-exact-tree")
        self.assertEqual(result["workflow_paths"], [".github/workflows/ci.yml", ".github/workflows/docs-truth.yml"])

    def test_add_delete_mutation_symlink_and_gitlink_fail_closed(self) -> None:
        def add(repository: Path) -> None:
            (repository / ".github" / "workflows" / "unreviewed.yml").write_text("name: unsafe\n", encoding="utf-8")

        def delete(repository: Path) -> None:
            (repository / ".github" / "workflows" / "docs-truth.yml").unlink()

        def mutate(repository: Path) -> None:
            path = repository / ".github" / "workflows" / "docs-truth.yml"
            path.write_text("name: altered\n", encoding="utf-8")

        def symlink(repository: Path) -> None:
            path = repository / ".github" / "workflows" / "docs-truth.yml"
            path.unlink()
            path.symlink_to("ci.yml")

        for name, mutation in (("add", add), ("delete", delete), ("mutate", mutate), ("symlink", symlink)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                parent, parent_sha = initialize_repository(root, "parent")
                candidate = root / "candidate"
                shutil.copytree(parent, candidate, ignore=shutil.ignore_patterns(".git"))
                subprocess.run(["git", "-C", str(candidate), "init", "-b", "main"], check=True)
                subprocess.run(["git", "-C", str(candidate), "config", "user.name", "Workflow Test"], check=True)
                subprocess.run(["git", "-C", str(candidate), "config", "user.email", "workflow@example.test"], check=True)
                mutation(candidate)
                candidate_sha = commit(candidate, name)
                with self.assertRaises(MODULE.WorkflowTreeError):
                    MODULE.verify(
                        parent_repository=parent,
                        parent_sha=parent_sha,
                        candidate_repository=candidate,
                        candidate_sha=candidate_sha,
                    )

    def test_gitlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, parent_sha = initialize_repository(root, "parent")
            candidate = root / "candidate"
            shutil.copytree(parent, candidate, ignore=shutil.ignore_patterns(".git"))
            subprocess.run(["git", "-C", str(candidate), "init", "-b", "main"], check=True)
            subprocess.run(["git", "-C", str(candidate), "config", "user.name", "Workflow Test"], check=True)
            subprocess.run(["git", "-C", str(candidate), "config", "user.email", "workflow@example.test"], check=True)
            path = ".github/workflows/docs-truth.yml"
            subprocess.run(["git", "-C", str(candidate), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(candidate), "rm", "--cached", path], check=True)
            subprocess.run(
                ["git", "-C", str(candidate), "update-index", "--add", "--cacheinfo", f"160000,{'f' * 40},{path}"],
                check=True,
            )
            subprocess.run(["git", "-C", str(candidate), "commit", "-m", "gitlink"], check=True)
            candidate_sha = git(candidate, "rev-parse", "HEAD")
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify(
                    parent_repository=parent,
                    parent_sha=parent_sha,
                    candidate_repository=candidate,
                    candidate_sha=candidate_sha,
                )

    def test_non_sha_revisions_fail_before_git_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent, parent_sha = initialize_repository(root, "parent")
            candidate, candidate_sha = initialize_repository(root, "candidate")
            with self.assertRaises(MODULE.WorkflowTreeError):
                MODULE.verify(
                    parent_repository=parent,
                    parent_sha="main",
                    candidate_repository=candidate,
                    candidate_sha=candidate_sha,
                )
            self.assertEqual(len(parent_sha), 40)


if __name__ == "__main__":
    unittest.main()
