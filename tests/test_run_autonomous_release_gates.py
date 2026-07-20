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
        authority_inventory = profiles["Mindburn-Labs/.github"]["workflow_inventory"]
        self.assertIsNotNone(authority_inventory)
        self.assertEqual(
            set(authority_inventory["files"]),
            {
                ".github/workflows/ci.yml",
                ".github/workflows/docs-truth-public.yml",
                ".github/workflows/docs-truth.yml",
                ".github/workflows/promote-authority.yml",
            },
        )

    def workflow_inventory_fixture(self, target: Path) -> dict[str, object]:
        workflows = target / ".github" / "workflows"
        workflows.mkdir(parents=True)
        ci = workflows / "ci.yml"
        immutable = workflows / "docs-truth.yml"
        ci.write_text("name: ci\n", encoding="utf-8")
        immutable.write_text("name: docs truth\n", encoding="utf-8")
        return {
            "root": ".github/workflows",
            "files": {
                ".github/workflows/ci.yml": {"mode": "100644", "semantic": True},
                ".github/workflows/docs-truth.yml": {
                    "mode": "100644",
                    "sha256": hashlib.sha256(immutable.read_bytes()).hexdigest(),
                },
            },
        }

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

    def test_profile_parser_rejects_malformed_or_duplicate_workflow_inventory(self) -> None:
        malformed = {
            "schema": "mindburn.autonomous-release-gates/v2",
            "profiles": {
                "Mindburn-Labs/example": {
                    "commands": [["tool", "check"]],
                    "protected_files": {"gate.json": "0" * 64},
                    "workflow_inventory": {
                        "root": ".github/workflows",
                        "files": {
                            ".github/workflows/other.yml": {
                                "mode": "100644",
                                "semantic": True,
                            },
                        },
                    },
                },
            },
        }
        duplicate = (
            '{"schema":"mindburn.autonomous-release-gates/v2","profiles":'
            '{"Mindburn-Labs/example":{"commands":[["tool"]],'
            '"protected_files":{"gate.json":"'
            + "0" * 64
            + '"},"workflow_inventory":{"root":".github/workflows",'
            '"files":{".github/workflows/ci.yml":{"mode":"100644",'
            '"semantic":true},".github/workflows/ci.yml":{"mode":"100644",'
            '"semantic":true}}}}}'
        )
        for content, message in (
            (json.dumps(malformed), "may make only"),
            (duplicate, "duplicate JSON key"),
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

    def test_workflow_inventory_allows_exact_tree_and_rejects_extra_mode_hash_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            inventory = self.workflow_inventory_fixture(target)
            MODULE.verify_workflow_inventory(target, inventory)

            extra = target / ".github" / "workflows" / "unreviewed.yml"
            extra.write_text("name: unreviewed\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.GateProfileError, "unexpected"):
                MODULE.verify_workflow_inventory(target, inventory)
            extra.unlink()

            immutable = target / ".github" / "workflows" / "docs-truth.yml"
            immutable.write_text("name: changed\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.GateProfileError, "file changed"):
                MODULE.verify_workflow_inventory(target, inventory)
            immutable.write_text("name: docs truth\n", encoding="utf-8")
            immutable.chmod(0o755)
            with self.assertRaisesRegex(MODULE.GateProfileError, "file mode changed"):
                MODULE.verify_workflow_inventory(target, inventory)
            immutable.chmod(0o644)
            immutable.unlink()
            immutable.symlink_to("ci.yml")
            with self.assertRaisesRegex(MODULE.GateProfileError, "not regular"):
                MODULE.verify_workflow_inventory(target, inventory)

    def test_workflow_inventory_extra_fails_before_any_gate_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            inventory = self.workflow_inventory_fixture(target)
            (target / ".github" / "workflows" / "unreviewed.yml").write_text(
                "name: unreviewed\n",
                encoding="utf-8",
            )
            profiles = {
                "Mindburn-Labs/example": {
                    "commands": [["tool", "check"]],
                    "protected_files": {"gate.json": "0" * 64},
                    "workflow_inventory": inventory,
                },
            }
            with self.assertRaisesRegex(MODULE.GateProfileError, "unexpected"):
                MODULE.resolve_commands("Mindburn-Labs/example", target, profiles)

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
