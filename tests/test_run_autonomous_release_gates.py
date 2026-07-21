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


def tree_descriptor(
    target: Path,
    relative_tree: str,
    exclusions: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "exclude": list(exclusions),
        "sha256": MODULE.canonical_tree_sha256(target, relative_tree, exclusions),
    }


class AutonomousReleaseGateTests(unittest.TestCase):
    def test_source_profiles_close_only_audited_repositories(self) -> None:
        profiles_path = ROOT / "config" / "autonomous-release-gates.json"
        profiles = MODULE.load_profiles(profiles_path)
        self.assertEqual(
            set(profiles),
            {
                "Mindburn-Labs/.github",
                "Mindburn-Labs/contracts-autonomous-release-lab",
                "Mindburn-Labs/helm-ai-kernel",
            },
        )
        self.assertEqual(
            profiles["Mindburn-Labs/.github"]["protected_trees"]["config"]["exclude"],
            MODULE.CONFIG_BINDING_EXCLUSIONS,
        )
        self.assertEqual(
            set(profiles["Mindburn-Labs/.github"]["protected_trees"]),
            {"config", "scripts", "tests"},
        )
        self.assertEqual(
            set(profiles["Mindburn-Labs/.github"]["protected_files"]),
            {"Makefile"},
        )
        self.assertEqual(
            set(profiles["Mindburn-Labs/contracts-autonomous-release-lab"]["protected_trees"]),
            {"scripts", "tests"},
        )
        self.assertEqual(
            profiles["Mindburn-Labs/contracts-autonomous-release-lab"]["protected_files"],
            {},
        )
        kernel_profile = profiles["Mindburn-Labs/helm-ai-kernel"]
        self.assertEqual(
            kernel_profile["commands"],
            [
                ["make", "lint"],
                ["make", "test"],
                ["make", "build"],
                ["make", "verify-fixtures"],
                ["make", "verify-boundary"],
                ["make", "crucible"],
                ["go", "test", "./tests/conformance/..."],
            ],
        )
        self.assertEqual(
            set(kernel_profile["protected_files"]),
            {"Makefile", "core/go.mod", "core/go.sum", "go.work"},
        )
        self.assertEqual(
            set(kernel_profile["protected_trees"]),
            {"protocols", "reference_packs", "schemas", "scripts", "tests", "tools"},
        )
        authority = json.loads(
            (ROOT / "config" / "autonomous-release-authority.json").read_text(
                encoding="utf-8",
            ),
        )
        self.assertEqual(
            authority["gate_profiles_sha256"],
            hashlib.sha256(profiles_path.read_bytes()).hexdigest(),
        )

    def test_profile_parser_rejects_duplicate_keys_and_shell_executables(self) -> None:
        for content, message in (
            (
                '{"schema":"mindburn.autonomous-release-gates/v3","profiles":{},"profiles":{}}',
                "duplicate JSON key",
            ),
            (
                json.dumps(
                    {
                        "schema": "mindburn.autonomous-release-gates/v3",
                        "profiles": {
                            "Mindburn-Labs/example": {
                                "commands": [["./target-script"]],
                                "protected_trees": {
                                    "tests": {"exclude": [], "sha256": "0" * 64},
                                },
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

    def test_profile_parser_rejects_expanded_or_malformed_tree_exclusions(self) -> None:
        cases = (
            (
                "Mindburn-Labs/.github",
                "config",
                ["autonomous-release-authority.json"],
                "reserved",
            ),
            (
                "Mindburn-Labs/.github",
                "config",
                [
                    *MODULE.CONFIG_BINDING_EXCLUSIONS,
                    "unexpected.json",
                ],
                "bounded",
            ),
            (
                "Mindburn-Labs/.github",
                "config",
                ["../authority.json"],
                "traversal",
            ),
            (
                "Mindburn-Labs/example",
                "tests",
                ["ignored.py"],
                "reserved",
            ),
        )
        for repository, protected_tree, exclusions, message in cases:
            with (
                self.subTest(repository=repository, exclusions=exclusions),
                tempfile.TemporaryDirectory() as tmpdir,
            ):
                path = Path(tmpdir) / "profiles.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema": "mindburn.autonomous-release-gates/v3",
                            "profiles": {
                                repository: {
                                    "commands": [["tool", "check"]],
                                    "protected_trees": {
                                        protected_tree: {
                                            "exclude": exclusions,
                                            "sha256": "0" * 64,
                                        },
                                    },
                                },
                            },
                        },
                    ),
                    encoding="utf-8",
                )
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

    def test_protected_tree_fails_closed_on_changed_deleted_added_or_symlinked_members(self) -> None:
        mutations = {
            "changed": lambda tree: (tree / "nested" / "gate.py").write_text(
                "changed\n",
                encoding="utf-8",
            ),
            "deleted": lambda tree: (tree / "nested" / "gate.py").unlink(),
            "added": lambda tree: (tree / "nested" / "added.py").write_text(
                "added\n",
                encoding="utf-8",
            ),
            "symlinked": lambda tree: (
                (tree / "nested" / "gate.py").unlink(),
                (tree / "nested" / "gate.py").symlink_to("outside"),
            ),
        }
        for mutation, apply_mutation in mutations.items():
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmpdir:
                target = Path(tmpdir)
                tree = target / "scripts"
                tree.mkdir()
                nested = tree / "nested"
                nested.mkdir()
                (nested / "gate.py").write_text("trusted\n", encoding="utf-8")
                expected = {"scripts": tree_descriptor(target, "scripts")}
                MODULE.verify_protected_trees(target, expected)
                apply_mutation(tree)
                with self.assertRaisesRegex(MODULE.GateProfileError, "changed|symlink"):
                    MODULE.verify_protected_trees(target, expected)

    def test_config_tree_additions_fail_outside_the_two_separately_bound_documents(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            config = target / "config"
            config.mkdir()
            for name in MODULE.CONFIG_BINDING_EXCLUSIONS:
                (config / name).write_text("{}\n", encoding="utf-8")
            (config / "guard.json").write_text("{}\n", encoding="utf-8")
            expected = {
                "config": tree_descriptor(
                    target,
                    "config",
                    MODULE.CONFIG_BINDING_EXCLUSIONS,
                ),
            }
            (config / "added.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.GateProfileError, "changed"):
                MODULE.verify_protected_trees(target, expected)

    def test_explicit_profile_runs_argv_without_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            profiles_path = root / "profiles.json"
            gate_tree = root / "checks"
            gate_tree.mkdir()
            (gate_tree / "gate.py").write_text("trusted\n", encoding="utf-8")
            profiles_path.write_text(
                json.dumps(
                    {
                        "schema": "mindburn.autonomous-release-gates/v3",
                        "profiles": {
                            "Mindburn-Labs/example": {
                                "commands": [["tool", "check"]],
                                "protected_trees": {
                                    "checks": tree_descriptor(root, "checks"),
                                },
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

    def test_tree_verification_runs_before_any_gate_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            checks = root / "checks"
            checks.mkdir()
            (checks / "gate.py").write_text("trusted\n", encoding="utf-8")
            profiles_path = root / "profiles.json"
            profiles_path.write_text(
                json.dumps(
                    {
                        "schema": "mindburn.autonomous-release-gates/v3",
                        "profiles": {
                            "Mindburn-Labs/example": {
                                "commands": [["tool", "check"]],
                                "protected_trees": {
                                    "checks": {"exclude": [], "sha256": "0" * 64},
                                },
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
            with mock.patch.object(MODULE.subprocess, "run") as execute:
                with self.assertRaisesRegex(MODULE.GateProfileError, "tree changed"):
                    MODULE.run(args)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
