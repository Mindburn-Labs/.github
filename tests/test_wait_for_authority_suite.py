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
    def __init__(self, *, artifacts=None, jobs=None, artifact_archive=b"") -> None:
        self.artifacts = artifacts or []
        self.jobs = jobs or []
        self.artifact_archive = artifact_archive
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
            return self.artifact_archive
        raise AssertionError(path)


class AuthoritySuiteTests(unittest.TestCase):
    def test_unclassified_newer_case_run_blocks_older_exact_allow(self) -> None:
        case = {
            "id": "allow",
            "expected": "ALLOW",
            "pull_request": 8,
            "head_sha": "b" * 40,
        }
        trigger = {
            "repository": "Mindburn-Labs/lab",
            "workflow_sha": "a" * 40,
            "started_at": "2026-07-14T00:00:00Z",
            "cases": [case],
        }
        newer = {"id": 11, "run_number": 11, "run_attempt": 1, "status": "in_progress"}
        older = {"id": 10, "run_number": 10, "run_attempt": 1, "status": "completed"}
        client = mock.Mock(token="observer-token")
        with tempfile.TemporaryDirectory() as tmpdir:
            args = mock.Mock(
                contract=Path(tmpdir) / "contract.json",
                adversarial_corpus=Path(tmpdir) / "corpus.json",
                trigger=Path(tmpdir) / "trigger.json",
                expected_workflow_sha="a" * 40,
                expected_authority=Path(tmpdir) / "authority.json",
                output_dir=Path(tmpdir) / "suite",
                timeout_seconds=60,
                poll_seconds=5,
            )
            with (
                mock.patch.object(MODULE, "load_json", return_value={}),
                mock.patch.object(MODULE, "validate_contract", return_value={}),
                mock.patch.object(MODULE, "validate_trigger", return_value=trigger),
                mock.patch.object(MODULE, "load_json_file", return_value={}),
                mock.patch.object(
                    MODULE,
                    "candidate_runs",
                    return_value=[newer, older],
                ),
                mock.patch.object(
                    MODULE,
                    "verify_run_workflow_provenance",
                    return_value=None,
                ) as provenance,
                mock.patch.object(MODULE.time, "monotonic", side_effect=[0, 0, 61]),
                mock.patch.object(MODULE.time, "sleep"),
                mock.patch.object(MODULE, "verify_case") as verify,
                self.assertRaisesRegex(MODULE.PermitInputError, "timed out"),
            ):
                MODULE.wait_for_suite(args, client)
        provenance.assert_called_once()
        self.assertIs(provenance.call_args.args[2], newer)
        verify.assert_not_called()

    def test_newest_exact_case_failure_never_falls_back_to_older_run(self) -> None:
        case = {
            "id": "allow",
            "expected": "ALLOW",
            "pull_request": 8,
            "head_sha": "b" * 40,
        }
        trigger = {
            "repository": "Mindburn-Labs/lab",
            "workflow_sha": "a" * 40,
            "started_at": "2026-07-14T00:00:00Z",
            "cases": [case],
        }
        newer = {
            "id": 11,
            "run_number": 11,
            "run_attempt": 1,
            "status": "completed",
        }
        older = {
            "id": 10,
            "run_number": 10,
            "run_attempt": 1,
            "status": "completed",
        }
        client = mock.Mock(token="observer-token")
        with tempfile.TemporaryDirectory() as tmpdir:
            args = mock.Mock(
                contract=Path(tmpdir) / "contract.json",
                adversarial_corpus=Path(tmpdir) / "corpus.json",
                trigger=Path(tmpdir) / "trigger.json",
                expected_workflow_sha="a" * 40,
                expected_authority=Path(tmpdir) / "authority.json",
                output_dir=Path(tmpdir) / "suite",
                timeout_seconds=60,
                poll_seconds=5,
            )
            with (
                mock.patch.object(MODULE, "load_json", return_value={}),
                mock.patch.object(MODULE, "validate_contract", return_value={}),
                mock.patch.object(
                    MODULE,
                    "validate_trigger",
                    return_value=trigger,
                ),
                mock.patch.object(MODULE, "load_json_file", return_value={}),
                mock.patch.object(
                    MODULE,
                    "candidate_runs",
                    return_value=[newer, older],
                ),
                mock.patch.object(
                    MODULE,
                    "verify_run_workflow_provenance",
                    return_value={"is_expected_workflow": True},
                ),
                mock.patch.object(
                    MODULE,
                    "verify_case",
                    side_effect=MODULE.PermitInputError("tampered permit"),
                ) as verify,
                self.assertRaisesRegex(
                    MODULE.PermitInputError,
                    "case allow run 11 failed validation",
                ),
            ):
                MODULE.wait_for_suite(args, client)
        self.assertEqual(verify.call_count, 1)
        self.assertIs(verify.call_args.kwargs["run"], newer)

    def test_allow_and_deny_cases_are_both_reduced_by_parent_kernel(self) -> None:
        for expected, conclusion in (("ALLOW", "success"), ("DENY", "failure")):
            with (
                self.subTest(expected=expected),
                tempfile.TemporaryDirectory() as tmpdir,
            ):
                root = Path(tmpdir)
                output_dir = root / "suite"
                output_dir.mkdir()
                evidence = root / "evidence"
                evidence.mkdir()
                permit_path = evidence / "release-permit.json"
                bundle_path = evidence / "release-permit.attestation.json"
                context_path = evidence / "context.json"
                review_paths = {
                    provider: evidence / f"review-{provider}.json"
                    for provider in ("anthropic", "openai")
                }
                for path in (
                    permit_path,
                    bundle_path,
                    context_path,
                    *review_paths.values(),
                ):
                    path.write_text("{}\n", encoding="utf-8")
                permit = {
                    "permit_id": "sha256:" + "a" * 64,
                    "merge_sha": "b" * 40,
                    "merge_tree_sha": "c" * 40,
                }
                args = mock.Mock(
                    output_dir=output_dir,
                    kernel_verifier=root / "release-permit-verify",
                )
                client = mock.Mock(token="observer-token")
                with (
                    mock.patch.object(
                        MODULE,
                        "write_attested_case",
                        return_value=(
                            permit_path,
                            bundle_path,
                            context_path,
                            review_paths,
                        ),
                    ),
                    mock.patch.object(
                        MODULE,
                        "verify_candidate_permit",
                        return_value=permit,
                    ),
                    mock.patch.object(
                        MODULE,
                        "validate_deny_permit",
                        return_value=permit,
                    ),
                    mock.patch.object(MODULE, "verify_permit_reduction") as reduce,
                ):
                    receipt = MODULE.verify_case(
                        args,
                        client,
                        case={
                            "id": f"case-{expected.lower()}",
                            "expected": expected,
                            "pull_request": 8,
                            "head_sha": "d" * 40,
                        },
                        run={"id": 42, "run_attempt": 1, "conclusion": conclusion},
                        repository="Mindburn-Labs/contracts-autonomous-release-lab",
                        authority={"generation": 2},
                        workflow_sha="e" * 40,
                    )
                self.assertEqual(receipt["expected"], expected)
                reduce.assert_called_once_with(
                    args.kernel_verifier,
                    permit_path,
                    context_path,
                    review_paths,
                    output_dir
                    / "cases"
                    / f"case-{expected.lower()}"
                    / "parent-kernel-permit.json",
                )

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
            mock.patch(
                "wait_for_authority_canary.verify_attestation",
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
            mock.patch("wait_for_authority_canary.verify_attestation"),
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


if __name__ == "__main__":
    unittest.main()
