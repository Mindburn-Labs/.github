from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "run_autonomous_release_gates.py"
SPEC = importlib.util.spec_from_file_location("run_autonomous_release_gates", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AutonomousReleaseGateTests(unittest.TestCase):
    def test_source_profiles_cover_all_non_make_repositories(self) -> None:
        profiles = MODULE.load_profiles(ROOT / "config" / "autonomous-release-gates.json")
        self.assertEqual(
            set(profiles),
            {
                "Mindburn-Labs/app-helm-console",
                "Mindburn-Labs/app-helm-docs",
                "Mindburn-Labs/app-mindburn-web",
                "Mindburn-Labs/helm-agent-integrations",
                "Mindburn-Labs/helm-desktop",
                "Mindburn-Labs/pkg-mindburn-helm-ds",
                "Mindburn-Labs/tempora",
            },
        )

    def test_profile_parser_rejects_duplicate_keys_and_shell_executables(self) -> None:
        for content, message in (
            (
                '{"schema":"mindburn.autonomous-release-gates/v1","profiles":{},"profiles":{}}',
                "duplicate JSON key",
            ),
            (
                json.dumps(
                    {
                        "schema": "mindburn.autonomous-release-gates/v1",
                        "profiles": {
                            "Mindburn-Labs/example": {"commands": [["./target-script"]]},
                        },
                    },
                ),
                "PATH executable",
            ),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "profiles.json"
                path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(MODULE.GateProfileError, message):
                    MODULE.load_profiles(path)

    def test_default_profile_requires_make_lint_and_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "Makefile").write_text("lint:\n\t@true\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.GateProfileError, "test"):
                MODULE.default_make_commands(target)

    def test_explicit_profile_runs_argv_without_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            profiles_path = root / "profiles.json"
            profiles_path.write_text(
                json.dumps(
                    {
                        "schema": "mindburn.autonomous-release-gates/v1",
                        "profiles": {
                            "Mindburn-Labs/example": {"commands": [["tool", "check"]]},
                        },
                    },
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                repository="Mindburn-Labs/example",
                target=root,
                profiles=profiles_path,
            )
            completed = mock.Mock(returncode=0)
            with mock.patch.object(MODULE.subprocess, "run", return_value=completed) as execute:
                MODULE.run(args)
            execute.assert_called_once()
            self.assertEqual(execute.call_args.args[0], ["tool", "check"])
            self.assertNotIn("shell", execute.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
