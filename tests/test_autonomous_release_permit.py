from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "autonomous_release_permit.py"
SPEC = importlib.util.spec_from_file_location("autonomous_release_permit", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def git(repo: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *arguments],
        text=True,
    ).strip()


def build_repo(root: Path) -> tuple[Path, str, str]:
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Permit Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "permit@example.test"], check=True)
    (repo / "example.txt").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "example.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "base"], check=True)
    base = git(repo, "rev-parse", "HEAD")
    (repo / "example.txt").write_text("base\nhead\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "commit", "-am", "head"], check=True)
    return repo, base, git(repo, "rev-parse", "HEAD")


def prepare_args(repo: Path, base: str, head: str, output: Path) -> argparse.Namespace:
    return argparse.Namespace(
        repository="Mindburn-Labs/example",
        pull_request=42,
        base_ref="refs/heads/main",
        base_sha=base,
        head_sha=head,
        workflow_repository="Mindburn-Labs/.github",
        workflow_path=".github/workflows/autonomous-release-permit.yml",
        workflow_ref="refs/heads/main",
        workflow_sha="3" * 40,
        run_id=101,
        run_attempt=1,
        issued_at="2026-07-14T10:00:00Z",
        anthropic_model="claude-fable-5",
        openai_model="gpt-5.6-sol",
        target_dir=repo,
        output_dir=output,
        max_patch_bytes=524_288,
        max_changed_files=400,
    )


class AutonomousReleasePermitTests(unittest.TestCase):
    def test_prepare_binds_context_and_patch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo, base, head = build_repo(root)
            output = root / "permit-input"
            MODULE.prepare(prepare_args(repo, base, head, output))

            context = json.loads((output / "context.json").read_text(encoding="utf-8"))
            prompt = (output / "review-prompt.txt").read_text(encoding="utf-8")
        self.assertEqual(context["head_sha"], head)
        self.assertEqual(
            context["required_reviewers"],
            [
                {"provider": "anthropic", "model": "claude-fable-5"},
                {"provider": "openai", "model": "gpt-5.6-sol"},
            ],
        )
        self.assertIn("+head", prompt)
        self.assertIn("zero authorization weight", prompt)

    def test_prepare_rejects_stale_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo, base, head = build_repo(root)
            args = prepare_args(repo, base, "4" * 40, root / "permit-input")
            with self.assertRaisesRegex(MODULE.PermitInputError, "does not match event head"):
                MODULE.prepare(args)

    def test_prepare_rejects_oversized_patch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo, base, head = build_repo(root)
            args = prepare_args(repo, base, head, root / "permit-input")
            args.max_patch_bytes = 1
            with self.assertRaisesRegex(MODULE.PermitInputError, "limit is 1"):
                MODULE.prepare(args)

    def test_envelope_binds_response_to_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo, base, head = build_repo(root)
            permit_input = root / "permit-input"
            MODULE.prepare(prepare_args(repo, base, head, permit_input))
            raw = root / "raw.json"
            raw.write_text('{"verdict":"ALLOW","findings":[]}\n', encoding="utf-8")
            output = root / "review.json"
            MODULE.envelope(
                argparse.Namespace(
                    context=permit_input / "context.json",
                    raw=raw,
                    provider="anthropic",
                    model="claude-fable-5",
                    output=output,
                    max_response_bytes=1_048_576,
                ),
            )
            review = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(review["head_sha"], head)
        self.assertEqual(review["verdict"], "ALLOW")
        self.assertEqual(len(review["response_sha256"]), 64)

    def test_envelope_rejects_extra_or_duplicate_fields(self) -> None:
        for content, message in (
            ('{"verdict":"ALLOW","findings":[],"approval":true}', "keys invalid"),
            ('{"verdict":"ALLOW","verdict":"DENY","findings":[]}', "duplicate JSON key"),
        ):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as tmpdir:
                path = Path(tmpdir) / "raw.json"
                path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(MODULE.PermitInputError, message):
                    MODULE.validate_model_response(MODULE.load_json_strict(path))

    def test_workflow_keeps_model_jobs_read_only_and_pinned(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "autonomous-release-permit.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("copilot-requests: write", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("cancel-in-progress", workflow)
        self.assertIn("--allow-tool=read", workflow)
        self.assertIn("--deny-tool='shell,write,url,memory'", workflow)
        self.assertIn("@github/copilot@1.0.70", workflow)
        self.assertIn(
            "sha512-onEwx5tod9t31Lc2rT5ns6s/fY6jtdwVWS3Fzs8hKUjCv7LFIMGf71MLcikl4GBXn6cq44+HVdNzCMWnLjYl3g==",
            workflow,
        )
        self.assertIn("name: HELM Autonomous Release Permit", workflow)
        self.assertIn("repository: Mindburn-Labs/.github", workflow)
        self.assertNotIn("repository: Mindburn-Labs/platform-actions", workflow)
        self.assertIn("ref: ${{ github.workflow_sha }}", workflow)
        self.assertIn(
            "ref: ed9afa8e6931115364efe2bbbd4f6479a1a10d11",
            workflow,
        )

    def test_workflow_requires_deterministic_repository_gates(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "autonomous-release-permit.yml").read_text(
            encoding="utf-8",
        )
        self.assertIn("name: Deterministic repository gates", workflow)
        for command in ("make setup", "make lint", "make test", "make build"):
            self.assertIn(command, workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)


if __name__ == "__main__":
    unittest.main()
