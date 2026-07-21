from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wait_for_authority_suite.py"
SPEC = importlib.util.spec_from_file_location("wait_for_authority_suite", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)


def archive(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        for name, content in entries.items():
            bundle.writestr(name, content)
    return output.getvalue()


class FakeJobClient:
    def __init__(
        self,
        *,
        artifacts=None,
        jobs=None,
        artifact_archive=b"",
        artifact_archives=None,
    ) -> None:
        self.artifacts = artifacts or []
        self.jobs = jobs or []
        self.artifact_archive = artifact_archive
        self.artifact_archives = artifact_archives or {}
        self.token = "read-token"

    def get_json(self, path: str):
        if path.endswith("/artifacts"):
            return {"artifacts": self.artifacts}
        if "/jobs" in path:
            return {"jobs": self.jobs}
        raise AssertionError(path)

    def get_bytes(self, path: str, *, accept: str = "") -> bytes:
        del accept
        if "/actions/artifacts/" in path and path.endswith("/zip"):
            artifact_id = int(path.split("/actions/artifacts/", 1)[1].split("/", 1)[0])
            if artifact_id in self.artifact_archives:
                return self.artifact_archives[artifact_id]
            return self.artifact_archive
        raise AssertionError(path)


class AuthoritySuiteTests(unittest.TestCase):
    def test_trigger_must_exactly_match_source_contract(self) -> None:
        contract = MODULE.load_json(
            ROOT / "config" / "autonomous-release-control-plane.json",
            label="contract",
        )
        corpus = MODULE.load_json(
            ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
            label="corpus",
        )
        contract = MODULE.validate_contract(contract, corpus)
        trigger = {
            "schema": MODULE.TRIGGER_SCHEMA,
            "repository": contract["adversarial_suite"]["repository"],
            "workflow_sha": "a" * 40,
            "started_at": "2026-07-14T00:00:00Z",
            "cases": contract["adversarial_suite"]["cases"],
        }
        self.assertEqual(MODULE.validate_trigger(trigger, contract), trigger)
        trigger["cases"] = trigger["cases"][:-1]
        with self.assertRaisesRegex(MODULE.PermitInputError, "exactly match"):
            MODULE.validate_trigger(trigger, contract)

    def test_pre_model_reject_requires_failed_gate_and_no_evidence(self) -> None:
        workflow_sha = "a" * 40
        head_sha = "b" * 40
        merge_sha = "c" * 40
        marker = json.dumps(
            {
                "schema": MODULE.PROVENANCE_SCHEMA,
                "repository": "Mindburn-Labs/lab",
                "workflow_path": MODULE.WORKFLOW_PATH,
                "workflow_sha": workflow_sha,
                "head_sha": head_sha,
                "merge_sha": merge_sha,
                "run_id": 7,
                "run_attempt": 2,
            },
        ).encode()
        client = FakeJobClient(
            artifacts=[
                {
                    "id": 9,
                    "name": MODULE.PROVENANCE_ARTIFACT,
                    "expired": False,
                },
            ],
            jobs=[
                {"name": "Deterministic repository gates", "conclusion": "failure"},
                {"name": "anthropic / claude-fable-5", "conclusion": "skipped"},
                {"name": "openai / gpt-5.6-sol", "conclusion": "skipped"},
            ],
            artifact_archive=archive(
                {
                    "release-workflow-provenance.json": marker,
                    "release-workflow-provenance.attestation.json": b"signed-bundle",
                },
            ),
        )
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            mock.patch.object(
                MODULE,
                "verify_attestation",
            ) as verifier,
        ):
            detail = MODULE.validate_pre_model_reject(
                client,
                "Mindburn-Labs/lab",
                {"id": 7, "run_attempt": 2},
                head_sha=head_sha,
                workflow_sha=workflow_sha,
                attestation_token=client.token,
                directory=Path(tmpdir) / "case",
            )
        self.assertEqual(detail["failed_gates"], ["Deterministic repository gates"])
        self.assertEqual(detail["merge_sha"], merge_sha)
        verifier.assert_called_once()
        self.assertEqual(verifier.call_args.kwargs["workflow_sha"], workflow_sha)
        self.assertEqual(verifier.call_args.kwargs["source_sha"], merge_sha)

    def test_pre_model_reject_fails_if_review_artifact_exists(self) -> None:
        client = FakeJobClient(
            artifacts=[{"name": "release-review-openai", "expired": False}],
            jobs=[{"name": "Bind immutable review input", "conclusion": "failure"}],
        )
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            self.assertRaisesRegex(
                MODULE.PermitInputError,
                "forbidden review evidence",
            ),
        ):
            MODULE.validate_pre_model_reject(
                client,
                "Mindburn-Labs/lab",
                {"id": 7, "run_attempt": 1},
                head_sha="b" * 40,
                workflow_sha="a" * 40,
                attestation_token=client.token,
                directory=Path(tmpdir) / "case",
            )

    def test_pre_model_reject_requires_candidate_workflow_provenance(self) -> None:
        client = FakeJobClient(
            jobs=[
                {"name": "Deterministic repository gates", "conclusion": "failure"},
                {"name": "anthropic / claude-fable-5", "conclusion": "skipped"},
                {"name": "openai / gpt-5.6-sol", "conclusion": "skipped"},
            ],
        )
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            self.assertRaisesRegex(
                MODULE.PermitInputError,
                "lacks candidate workflow provenance",
            ),
        ):
            MODULE.validate_pre_model_reject(
                client,
                "Mindburn-Labs/lab",
                {"id": 7, "run_attempt": 1},
                head_sha="b" * 40,
                workflow_sha="a" * 40,
                attestation_token=client.token,
                directory=Path(tmpdir) / "case",
            )

    def test_pre_model_reject_rejects_parent_workflow_marker(self) -> None:
        marker = json.dumps(
            {
                "schema": MODULE.PROVENANCE_SCHEMA,
                "repository": "Mindburn-Labs/lab",
                "workflow_path": MODULE.WORKFLOW_PATH,
                "workflow_sha": "d" * 40,
                "head_sha": "b" * 40,
                "merge_sha": "c" * 40,
                "run_id": 7,
                "run_attempt": 1,
            },
        ).encode()
        client = FakeJobClient(
            artifacts=[
                {
                    "id": 9,
                    "name": MODULE.PROVENANCE_ARTIFACT,
                    "expired": False,
                },
            ],
            jobs=[
                {"name": "Deterministic repository gates", "conclusion": "failure"},
                {"name": "anthropic / claude-fable-5", "conclusion": "skipped"},
                {"name": "openai / gpt-5.6-sol", "conclusion": "skipped"},
            ],
            artifact_archive=archive(
                {
                    "release-workflow-provenance.json": marker,
                    "release-workflow-provenance.attestation.json": b"signed-bundle",
                },
            ),
        )
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            self.assertRaisesRegex(
                MODULE.PermitInputError,
                "workflow_sha does not match the proof run",
            ),
        ):
            MODULE.validate_pre_model_reject(
                client,
                "Mindburn-Labs/lab",
                {"id": 7, "run_attempt": 1},
                head_sha="b" * 40,
                workflow_sha="a" * 40,
                attestation_token=client.token,
                directory=Path(tmpdir) / "case",
            )

    def test_review_envelopes_require_exact_artifacts(self) -> None:
        client = FakeJobClient(
            artifacts=[
                {"id": 9, "name": "release-review-anthropic", "expired": False},
                {"id": 10, "name": "release-review-openai", "expired": False},
            ],
            artifact_archives={
                9: archive({"review-anthropic.json": b'{"provider":"anthropic"}'}),
                10: archive({"review-openai.json": b'{"provider":"openai"}'}),
            },
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir) / "case"
            directory.mkdir()
            paths = MODULE.write_review_envelopes(
                client,
                "Mindburn-Labs/lab",
                7,
                directory,
            )
        self.assertEqual([path.name for path in paths], [
            "review-anthropic.json",
            "review-openai.json",
        ])

    def test_deny_permit_replays_reviews_with_parent_kernel(self) -> None:
        workflow_sha = "a" * 40
        head_sha = "b" * 40
        merge_sha = "c" * 40
        authority = {
            "schema": "mindburn.release-authority/v1",
            "generation": 1,
            "kernel_sha": "d" * 40,
            "gate_profiles_sha256": "e" * 64,
            "adversarial_corpus_sha256": "f" * 64,
            "parent": None,
        }
        context = {
            "repository": "Mindburn-Labs/lab",
            "pull_request": 7,
            "head_sha": head_sha,
            "workflow_sha": workflow_sha,
            "run_id": 9,
            "run_attempt": 1,
            "authority": authority,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            directory = Path(tmpdir)
            context_path = directory / "context.json"
            context_bytes = json.dumps(context).encode("utf-8")
            context_path.write_bytes(context_bytes)
            permit_path = directory / "release-permit.json"
            permit_path.write_text(
                json.dumps(
                    {
                        "schema": "mindburn.release-permit/v2",
                        "permit_id": "sha256:" + "1" * 64,
                        "decision": "DENY",
                        "repository": "Mindburn-Labs/lab",
                        "pull_request": 7,
                        "base_ref": "refs/heads/main",
                        "base_sha": "2" * 40,
                        "head_sha": head_sha,
                        "merge_sha": merge_sha,
                        "merge_tree_sha": "3" * 40,
                        "workflow_repository": "Mindburn-Labs/.github",
                        "workflow_path": ".github/workflows/ci.yml",
                        "workflow_ref": "workflow-ref",
                        "workflow_sha": workflow_sha,
                        "run_id": 9,
                        "run_attempt": 1,
                        "issued_at": "2026-07-21T00:00:00Z",
                        "authority": authority,
                        "context_sha256": MODULE.hashlib.sha256(context_bytes).hexdigest(),
                        "reviews": [
                            {
                                "reviewer": {
                                    "provider": "anthropic",
                                    "model": "claude-fable-5",
                                },
                                "verdict": "ALLOW",
                                "response_sha256": "4" * 64,
                                "blocking_findings": 0,
                                "advisory_findings": 0,
                            },
                            {
                                "reviewer": {
                                    "provider": "openai",
                                    "model": "gpt-5.6-sol",
                                },
                                "verdict": "DENY",
                                "response_sha256": "5" * 64,
                                "blocking_findings": 1,
                                "advisory_findings": 0,
                            },
                        ],
                        "reasons": [
                            {
                                "code": "BLOCKING_FINDING",
                                "reviewer": "openai/gpt-5.6-sol",
                                "detail": "blocking review",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            bundle_path = directory / "release-permit.attestation.json"
            bundle_path.write_text("{}", encoding="utf-8")
            review_paths = (
                directory / "review-anthropic.json",
                directory / "review-openai.json",
            )
            for path in review_paths:
                path.write_text("{}", encoding="utf-8")
            with (
                mock.patch.object(MODULE, "verify_attestation"),
                mock.patch.object(MODULE, "replay_permit_with_parent_kernel") as replay,
            ):
                MODULE.validate_deny_permit(
                    permit_path,
                    bundle_path,
                    context_path,
                    run={"id": 9, "run_attempt": 1},
                    repository="Mindburn-Labs/lab",
                    case={
                        "id": "deny-review-replay",
                        "pull_request": 7,
                        "head_sha": head_sha,
                    },
                    workflow_sha=workflow_sha,
                    authority=authority,
                    attestation_token="observer-token",
                    kernel_verifier=Path("/parent-kernel"),
                    review_paths=review_paths,
                )
        replay.assert_called_once()
        self.assertEqual(replay.call_args.args[0], Path("/parent-kernel"))
        self.assertEqual(replay.call_args.args[3], review_paths)
        self.assertEqual(replay.call_args.kwargs["expected"], "DENY")


if __name__ == "__main__":
    unittest.main()
