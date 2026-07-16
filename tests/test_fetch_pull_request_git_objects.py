from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "fetch_pull_request_git_objects.py"
SPEC = importlib.util.spec_from_file_location("fetch_pull_request_git_objects", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PullRequestObjectTests(unittest.TestCase):
    def test_repository_and_sha_inputs_are_narrow(self) -> None:
        self.assertEqual(MODULE.require_repository("Mindburn-Labs/.github"), "Mindburn-Labs/.github")
        self.assertEqual(MODULE.require_sha("a" * 40, label="head"), "a" * 40)
        for value in ("github.com/Mindburn-Labs/.github", "Other/.github", "Mindburn-Labs/a/b"):
            with self.subTest(value=value):
                with self.assertRaises(MODULE.PullRequestObjectError):
                    MODULE.require_repository(value)
        for value in ("A" * 40, "a" * 39, "a" * 41, "a;git"):
            with self.subTest(value=value):
                with self.assertRaises(MODULE.PullRequestObjectError):
                    MODULE.require_sha(value, label="head")

    def test_fetch_refspec_and_remote_are_fixed_format(self) -> None:
        self.assertEqual(
            MODULE.fetch_refspec("b" * 40, label="head"),
            f"{'b' * 40}:refs/authority-input/head",
        )
        self.assertEqual(
            MODULE.remote_url("Mindburn-Labs/.github"),
            "https://github.com/Mindburn-Labs/.github.git",
        )
        self.assertEqual(
            MODULE.fetch_arguments("c" * 40, label="base"),
            (
                "fetch",
                "--no-tags",
                "--no-recurse-submodules",
                "--depth=1",
                "origin",
                f"{'c' * 40}:refs/authority-input/base",
            ),
        )
        self.assertIn("--depth=2", MODULE.fetch_arguments("d" * 40, label="merge"))
        with self.assertRaises(MODULE.PullRequestObjectError):
            MODULE.fetch_arguments("e" * 40, label="unexpected")

    def test_git_environment_drops_ambient_git_state(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": "/untrusted",
                "GIT_CONFIG_COUNT": "99",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/untrusted/objects",
                "GIT_SSH_COMMAND": "untrusted-ssh",
                "UNRELATED_TEST_SECRET": "must-not-reach-git",
            },
            clear=False,
        ):
            environment = MODULE.git_environment("test-token")
        self.assertNotIn("GIT_DIR", environment)
        self.assertNotIn("GIT_ALTERNATE_OBJECT_DIRECTORIES", environment)
        self.assertNotIn("GIT_SSH_COMMAND", environment)
        self.assertNotIn("UNRELATED_TEST_SECRET", environment)
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "10")
        self.assertNotEqual(environment["GIT_CONFIG_COUNT"], "99")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_CONFIG_KEY_0"], "core.hooksPath")
        self.assertIn("protocol.https.allow", environment.values())

    def test_source_never_checks_out_or_embeds_credentials_in_a_remote_url(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn('"checkout"', source)
        self.assertNotIn('"clone"', source)
        self.assertNotIn("x-access-token:@github.com", source)
        self.assertIn("http.https://github.com/.extraheader", source)
        self.assertIn("core.hooksPath", source)
        self.assertIn("protocol.file.allow", source)
        self.assertIn("protocol.https.allow", source)
        self.assertNotIn('"--token-env"', source)

    def test_depth_two_merge_fetch_keeps_exact_parent_binding_visible(self) -> None:
        """A depth-one merge hides parents; the broker must reject that state."""

        def git(repository: Path, *arguments: str) -> str:
            return subprocess.check_output(
                ["git", "-C", str(repository), *arguments],
                text=True,
            ).strip()

        def run(repository: Path, *arguments: str) -> None:
            subprocess.run(
                ["git", "-C", str(repository), *arguments],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        original_git_environment = MODULE.git_environment

        def local_file_environment(token: str) -> dict[str, str]:
            environment = original_git_environment(token)
            count = int(environment["GIT_CONFIG_COUNT"])
            environment[f"GIT_CONFIG_KEY_{count}"] = "protocol.file.allow"
            environment[f"GIT_CONFIG_VALUE_{count}"] = "always"
            environment["GIT_CONFIG_COUNT"] = str(count + 1)
            return environment

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            remote = root / "remote.git"
            source.mkdir()
            run(source, "init", "-b", "main")
            run(source, "config", "user.name", "Broker Test")
            run(source, "config", "user.email", "broker@example.test")
            workflows = source / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "ci.yml").write_text("name: candidate\n", encoding="utf-8")
            (workflows / "docs-truth.yml").write_text("name: docs\n", encoding="utf-8")
            (source / "base.txt").write_text("base\n", encoding="utf-8")
            run(source, "add", "-A")
            run(source, "commit", "-m", "base")
            run(source, "checkout", "-b", "candidate")
            (source / "candidate.txt").write_text("candidate\n", encoding="utf-8")
            run(source, "add", "candidate.txt")
            run(source, "commit", "-m", "candidate")
            head_sha = git(source, "rev-parse", "HEAD")
            run(source, "checkout", "main")
            (source / "main.txt").write_text("main\n", encoding="utf-8")
            run(source, "add", "main.txt")
            run(source, "commit", "-m", "main")
            base_sha = git(source, "rev-parse", "HEAD")
            run(source, "merge", "--no-ff", "candidate", "-m", "merge")
            merge_sha = git(source, "rev-parse", "HEAD")
            subprocess.run(
                ["git", "init", "--bare", str(remote)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            run(source, "remote", "add", "origin", remote.as_uri())
            run(source, "push", "--all", "origin")

            with mock.patch.object(MODULE, "remote_url", return_value=remote.as_uri()), mock.patch.object(
                MODULE,
                "git_environment",
                side_effect=local_file_environment,
            ):
                receipt = MODULE.prepare_store(
                    repository="Mindburn-Labs/.github",
                    base_sha=base_sha,
                    head_sha=head_sha,
                    merge_sha=merge_sha,
                    output=root / "candidate.git",
                    token="test-token",
                )
            verification = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "verify_workflow_tree.py"),
                    "--parent-repository",
                    str(source),
                    "--parent-sha",
                    base_sha,
                    "--candidate-repository",
                    str(root / "candidate.git"),
                    "--candidate-sha",
                    head_sha,
                    "--merge-sha",
                    merge_sha,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(verification.returncode, 0, verification.stderr)
            admission = json.loads(verification.stdout)
            self.assertEqual(admission["parent_sha"], base_sha)
            self.assertEqual(admission["candidate_sha"], head_sha)
            self.assertEqual(admission["merge_sha"], merge_sha)

        self.assertEqual(receipt["merge_parents"], [base_sha, head_sha])


if __name__ == "__main__":
    unittest.main()
