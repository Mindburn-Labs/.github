from __future__ import annotations

import argparse
import hashlib
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
    def test_source_profiles_cover_public_authority_and_product_repositories(self) -> None:
        profiles = MODULE.load_profiles(ROOT / "config" / "autonomous-release-gates.json")
        self.assertEqual(
            set(profiles),
            {
                "Mindburn-Labs/.github",
                "Mindburn-Labs/app-helm-console",
                "Mindburn-Labs/app-helm-docs",
                "Mindburn-Labs/app-mindburn-web",
                "Mindburn-Labs/helm-agent-integrations",
                "Mindburn-Labs/helm-ai-kernel",
                "Mindburn-Labs/helm-desktop",
                "Mindburn-Labs/contracts-autonomous-release-lab",
                "Mindburn-Labs/pkg-mindburn-helm-ds",
                "Mindburn-Labs/tempora",
            },
        )

    def test_profile_parser_rejects_duplicate_keys_and_shell_executables(self) -> None:
        for content, message in (
            (
                '{"schema":"mindburn.autonomous-release-gates/v2","profiles":{},"profiles":{}}',
                "duplicate JSON key",
            ),
            (
                json.dumps(
                    {
                        "schema": "mindburn.autonomous-release-gates/v2",
                        "profiles": {
                            "Mindburn-Labs/example": {
                                "commands": [["./target-script"]],
                                "protected_files": {"Makefile": "0" * 64},
                            },
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

    def test_repository_without_source_owned_profile_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            (target / "Makefile").write_text(
                "lint:\n\t@true\ntest:\n\t@true\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.GateProfileError, "fallback is forbidden"):
                MODULE.resolve_commands("Mindburn-Labs/example", target, {})

    def test_changed_or_symlinked_gate_definition_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            makefile = target / "Makefile"
            makefile.write_text("lint:\n\t@true\n", encoding="utf-8")
            expected = {"Makefile": "0" * 64}
            with self.assertRaisesRegex(MODULE.GateProfileError, "changed"):
                MODULE.verify_protected_files(target, expected)
            makefile.unlink()
            makefile.symlink_to("outside")
            with self.assertRaisesRegex(MODULE.GateProfileError, "not regular"):
                MODULE.verify_protected_files(target, expected)

    def test_explicit_profile_runs_argv_without_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            profiles_path = root / "profiles.json"
            gate_definition = root / "gate.json"
            gate_definition.write_text("{}\n", encoding="utf-8")
            gate_digest = hashlib.sha256(gate_definition.read_bytes()).hexdigest()
            profiles_path.write_text(
                json.dumps(
                    {
                        "schema": "mindburn.autonomous-release-gates/v2",
                        "profiles": {
                            "Mindburn-Labs/example": {
                                "commands": [["tool", "check"]],
                                "protected_files": {"gate.json": gate_digest},
                            },
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
