from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_authority_promotion.py"
SPEC = importlib.util.spec_from_file_location("verify_authority_promotion", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

PARENT_SHA = "1" * 40
PARENT_KERNEL_SHA = "2" * 40
CANDIDATE_KERNEL_SHA = "3" * 40
CONTEXT_SHA = "4" * 64
RESPONSE_A = "5" * 64
RESPONSE_B = "6" * 64


def git(repository: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repository), *arguments],
        text=True,
    ).strip()


def build_candidate(root: Path) -> tuple[Path, str, str]:
    repository = root / "candidate"
    (repository / "config").mkdir(parents=True)
    (repository / "tests" / "fixtures").mkdir(parents=True)
    (repository / ".github" / "workflows").mkdir(parents=True)
    gates = b'{"profiles":{}}\n'
    corpus = b'{"schema":"mindburn.release-permit-adversarial/v1","cases":[]}\n'
    (repository / "config" / "autonomous-release-gates.json").write_bytes(gates)
    (
        repository / "tests" / "fixtures" / "autonomous-release-adversarial.json"
    ).write_bytes(corpus)
    authority = {
        "schema": "mindburn.release-authority/v1",
        "generation": 2,
        "kernel_sha": CANDIDATE_KERNEL_SHA,
        "gate_profiles_sha256": hashlib.sha256(gates).hexdigest(),
        "adversarial_corpus_sha256": hashlib.sha256(corpus).hexdigest(),
        "parent": {"generation": 1, "workflow_sha": PARENT_SHA},
    }
    (repository / "config" / "autonomous-release-authority.json").write_text(
        json.dumps(authority, indent=2) + "\n",
        encoding="utf-8",
    )
    (repository / ".github" / "workflows" / "ci.yml").write_text(
        f"""name: permit
steps:
  - ref: {CANDIDATE_KERNEL_SHA}
  - ref: {CANDIDATE_KERNEL_SHA}
  - ref: {CANDIDATE_KERNEL_SHA}
  - run: python script.py --authority-manifest policy/config/autonomous-release-authority.json
""",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repository), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "Permit Test"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "permit@example.test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-m", "candidate"], check=True
    )
    candidate_sha = git(repository, "rev-parse", "HEAD")
    return repository, candidate_sha, git(repository, "rev-parse", "HEAD^{tree}")


def build_permit(candidate_sha: str, candidate_tree: str) -> dict[str, object]:
    permit: dict[str, object] = {
        "schema": "mindburn.release-permit/v2",
        "permit_id": "",
        "decision": "ALLOW",
        "repository": "Mindburn-Labs/.github",
        "pull_request": 33,
        "base_ref": "refs/heads/main",
        "base_sha": "7" * 40,
        "head_sha": candidate_sha,
        "merge_sha": "8" * 40,
        "merge_tree_sha": candidate_tree,
        "workflow_repository": "Mindburn-Labs/.github",
        "workflow_path": ".github/workflows/ci.yml",
        "workflow_ref": "Mindburn-Labs/.github/.github/workflows/ci.yml@refs/heads/main",
        "workflow_sha": PARENT_SHA,
        "run_id": 101,
        "run_attempt": 1,
        "issued_at": "2026-07-14T10:00:00Z",
        "authority": {
            "schema": "mindburn.release-authority/v1",
            "generation": 1,
            "kernel_sha": PARENT_KERNEL_SHA,
            "gate_profiles_sha256": "9" * 64,
            "adversarial_corpus_sha256": "a" * 64,
            "parent": None,
        },
        "context_sha256": CONTEXT_SHA,
        "reviews": [
            {
                "reviewer": {"provider": "anthropic", "model": "claude-fable-5"},
                "verdict": "ALLOW",
                "response_sha256": RESPONSE_A,
                "blocking_findings": 0,
                "advisory_findings": 0,
            },
            {
                "reviewer": {"provider": "openai", "model": "gpt-5.6-sol"},
                "verdict": "ALLOW",
                "response_sha256": RESPONSE_B,
                "blocking_findings": 0,
                "advisory_findings": 1,
            },
        ],
        "reasons": [],
    }
    permit["permit_id"] = "sha256:" + "b" * 64
    return permit


def build_fake_verifier(root: Path, *, succeeds: bool = True) -> Path:
    verifier = root / "release-permit-verify"
    verifier.write_text(
        "#!/bin/sh\n" + ("exit 0\n" if succeeds else "echo rejected >&2\nexit 2\n"),
        encoding="utf-8",
    )
    verifier.chmod(0o700)
    return verifier


def verify_args(
    repository: Path,
    candidate_sha: str,
    permit_path: Path,
    verifier: Path,
) -> argparse.Namespace:
    trusted_context = permit_path.parent / "context.json"
    trusted_context.write_text("{}\n", encoding="utf-8")
    return argparse.Namespace(
        permit=permit_path,
        permit_verifier=verifier,
        trusted_context=trusted_context,
        candidate_repository=repository,
        candidate_sha=candidate_sha,
        candidate_pr=33,
        expected_run_id=101,
        expected_run_attempt=1,
        expected_parent_generation=1,
        expected_parent_workflow_sha=PARENT_SHA,
        output=None,
    )


class AuthorityPromotionTests(unittest.TestCase):
    def test_previous_generation_permit_ratifies_exact_successor(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repository, candidate_sha, candidate_tree = build_candidate(root)
            permit_path = root / "permit.json"
            permit_path.write_text(
                json.dumps(build_permit(candidate_sha, candidate_tree), indent=2)
                + "\n",
                encoding="utf-8",
            )
            result = MODULE.verify(
                verify_args(
                    repository, candidate_sha, permit_path, build_fake_verifier(root)
                ),
            )
        self.assertEqual(result["candidate_generation"], 2)
        self.assertEqual(result["parent_workflow_sha"], PARENT_SHA)

    def test_tree_or_permit_substitution_fails_closed(self) -> None:
        for mutation, message in (
            ("tree", "merge tree"),
            ("permit", "permit_id"),
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as tmpdir,
            ):
                root = Path(tmpdir)
                repository, candidate_sha, candidate_tree = build_candidate(root)
                permit = build_permit(candidate_sha, candidate_tree)
                if mutation == "tree":
                    permit["merge_tree_sha"] = "b" * 40
                else:
                    permit["permit_id"] = "invalid"
                permit_path = root / "permit.json"
                permit_path.write_text(json.dumps(permit) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(MODULE.PermitInputError, message):
                    MODULE.verify(
                        verify_args(
                            repository,
                            candidate_sha,
                            permit_path,
                            build_fake_verifier(root),
                        ),
                    )

    def test_kernel_rejection_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repository, candidate_sha, candidate_tree = build_candidate(root)
            permit_path = root / "permit.json"
            permit_path.write_text(
                json.dumps(build_permit(candidate_sha, candidate_tree)) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.PermitInputError, "pinned Kernel rejected"
            ):
                MODULE.verify(
                    verify_args(
                        repository,
                        candidate_sha,
                        permit_path,
                        build_fake_verifier(root, succeeds=False),
                    ),
                )


if __name__ == "__main__":
    unittest.main()
