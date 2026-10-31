from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/generate-repo-inventory.rb"
BEGIN = "<!-- BEGIN GENERATED REPOSITORY INVENTORY -->"
END = "<!-- END GENERATED REPOSITORY INVENTORY -->"
MANIFEST = """---
organization: example
inventory_summary:
  total_repositories: 99
  deleted_repositories: [retired]
  production_release_status: not_released
release_readiness:
  production_promotion_allowed: false
repositories:
- name: public-repo
  visibility: public
  archived: false
- name: internal-archive
  visibility: internal
  archived: true
- name: private-repo
  visibility: private
  archived: false
"""


class InventoryTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        (root / "repo-manifest.yaml").write_text(MANIFEST)
        (root / "README.md").write_text(f"Before\n{BEGIN}\nstale\n{END}\nAfter\n")
        return root

    def run_inventory(self, root, *arguments):
        return subprocess.run(
            ["ruby", str(SCRIPT), "--repo-root", str(root), *arguments],
            text=True, capture_output=True,
        )

    def test_regeneration_preserves_policy_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            self.assertNotEqual(self.run_inventory(root, "--check").returncode, 0)
            result = self.run_inventory(root, "--write")
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = (root / "repo-manifest.yaml").read_text()
            self.assertIn("production_release_status: not_released", manifest)
            self.assertIn("production_promotion_allowed: false", manifest)
            self.assertIn("retired", manifest)
            readme = (root / "README.md").read_text()
            self.assertIn("3 repositories: 2 active, 1 archived; 1 public, 1 private, 1 internal.", readme)
            self.assertTrue(readme.startswith("Before\n") and readme.endswith("After\n"))
            self.assertEqual(self.run_inventory(root, "--check").returncode, 0)
            self.assertEqual(self.run_inventory(root, "--write").returncode, 0)
            self.assertEqual(manifest, (root / "repo-manifest.yaml").read_text())

    def test_invalid_rows_fail_before_writes(self):
        changes = [
            MANIFEST.replace("name: private-repo", "name: public-repo"),
            MANIFEST.replace("visibility: private", "visibility: secret"),
            MANIFEST.replace("archived: false", 'archived: "false"'),
            MANIFEST.replace("name: private-repo", "name: retired"),
        ]
        for manifest in changes:
            with self.subTest(manifest=manifest), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                (root / "repo-manifest.yaml").write_text(manifest)
                result = self.run_inventory(root, "--write")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((root / "repo-manifest.yaml").read_text(), manifest)

    def test_missing_docs_block_prevents_partial_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            result = self.run_inventory(root, "--write", "--docs-root", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "repo-manifest.yaml").read_text(), MANIFEST)

    def test_invalid_marker_order_or_duplicates_cannot_bypass_check(self):
        for readme in [f"{END}\n{BEGIN}\n", f"{BEGIN}\n{BEGIN}\n{END}\n"]:
            with self.subTest(readme=readme), tempfile.TemporaryDirectory() as directory:
                root = self.fixture(directory)
                (root / "README.md").write_text(readme)
                result = self.run_inventory(root, "--write")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((root / "repo-manifest.yaml").read_text(), MANIFEST)

    def test_github_reconciliation_rejects_visibility_or_repository_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory)
            listing = [
                {"name": "public-repo", "visibility": "PUBLIC", "isArchived": False},
                {"name": "internal-archive", "visibility": "INTERNAL", "isArchived": True},
                {"name": "private-repo", "visibility": "PRIVATE", "isArchived": False},
            ]
            path = root / "github.json"
            path.write_text(json.dumps(listing))
            result = self.run_inventory(root, "--write", "--github-json", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            for changed in [listing[:-1], [*listing, listing[0]], [dict(row, visibility="PRIVATE") for row in listing]]:
                path.write_text(json.dumps(changed))
                result = self.run_inventory(root, "--check", "--github-json", str(path))
                self.assertNotEqual(result.returncode, 0)

    def test_ecosystem_map_needs_no_legacy_snapshots_and_scopes_its_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "owned/map.md"
            command = ["ruby", str(ROOT / "scripts/generate-helm-ecosystem-map.rb"), "--output", str(output)]
            env = dict(os.environ, MINDBURN_WORKSPACE_ROOT=str(root))
            result = subprocess.run([*command, "--write", "--check"], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = output.read_text()
            self.assertIn("Local classification and migration snapshots were not supplied", text)
            self.assertIn("no migration inventory is asserted", text)
            self.assertNotIn(".github-repo", text)
            self.assertFalse((root / "docs_for_team").exists())
            self.assertFalse((root / "docs-engineering-handbook").exists())
            result = subprocess.run([*command, "--check", "--legacy-snapshots"], env=env, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
