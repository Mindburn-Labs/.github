from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "wait_for_authority_canary.py"
SPEC = importlib.util.spec_from_file_location("wait_for_authority_canary", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)


def archive(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, content in entries.items():
            bundle.writestr(name, content)
    return buffer.getvalue()


class AuthorityCanaryTests(unittest.TestCase):
    def test_attestation_verification_uses_explicit_observer_token(self) -> None:
        completed = mock.Mock(returncode=0, stderr=b"")
        with mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run:
            MODULE.verify_attestation(
                Path("permit.json"),
                Path("bundle.json"),
                repository="Mindburn-Labs/example",
                workflow_sha="a" * 40,
                source_sha="b" * 40,
                github_token="observer-token",
            )
        self.assertEqual(run.call_args.kwargs["env"]["GH_TOKEN"], "observer-token")

    def test_attestation_verification_rejects_ambient_token_fallback(self) -> None:
        with self.assertRaisesRegex(MODULE.PermitInputError, "explicit token"):
            MODULE.verify_attestation(
                Path("permit.json"),
                Path("bundle.json"),
                repository="Mindburn-Labs/example",
                workflow_sha="a" * 40,
                source_sha="b" * 40,
                github_token="",
            )

    def test_extract_attested_permit_accepts_bounded_exact_entries(self) -> None:
        permit = b'{"decision":"ALLOW"}\n'
        attestation = b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n'
        self.assertEqual(
            MODULE.extract_attested_permit(
                archive(
                    {
                        "release-permit.json": permit,
                        "release-permit.attestation.json": attestation,
                    },
                ),
            ),
            (permit, attestation),
        )

    def test_extract_attested_permit_rejects_substitution_or_oversize(self) -> None:
        for payload in (
            archive({"release-permit.json": b"{}", "extra": b"x"}),
            archive({"../release-permit.json": b"{}"}),
            archive(
                {
                    "release-permit.json": b"x" * (MODULE.MAX_PERMIT_BYTES + 1),
                    "release-permit.attestation.json": b"{}",
                },
            ),
            archive(
                {
                    "release-permit.json": b"{}",
                    "release-permit.attestation.json": b"x"
                    * (MODULE.MAX_BUNDLE_BYTES + 1),
                },
            ),
        ):
            with (
                self.subTest(size=len(payload)),
                self.assertRaises(MODULE.PermitInputError),
            ):
                MODULE.extract_attested_permit(payload)

    def test_extract_trusted_context_accepts_exact_bounded_input(self) -> None:
        context = b'{"schema":"mindburn.release-permit-context/v2"}\n'
        self.assertEqual(
            MODULE.extract_trusted_context(
                archive(
                    {
                        "context.json": context,
                        "review-prompt.txt": b"Review this exact context.\n",
                        "patch.diff": b"diff --git a/a b/a\n",
                    },
                ),
            ),
            context,
        )

    def test_extract_trusted_context_rejects_substitution(self) -> None:
        for payload in (
            archive({"context.json": b"{}", "review-prompt.txt": b"x"}),
            archive(
                {
                    "../context.json": b"{}",
                    "review-prompt.txt": b"x",
                    "patch.diff": b"x",
                },
            ),
            archive(
                {
                    "context.json": b"x" * (MODULE.MAX_CONTEXT_BYTES + 1),
                    "review-prompt.txt": b"x",
                    "patch.diff": b"x",
                },
            ),
            archive(
                {
                    "context.json": b"{}",
                    "review-prompt.txt": b"x",
                    "patch.diff": b"x" * (MODULE.MAX_PATCH_BYTES + 1),
                },
            ),
        ):
            with (
                self.subTest(size=len(payload)),
                self.assertRaises(MODULE.PermitInputError),
            ):
                MODULE.extract_trusted_context(payload)

    def test_extract_model_review_accepts_only_exact_bounded_provider_entry(
        self,
    ) -> None:
        review = b'{"schema":"mindburn.release-review/v1"}\n'
        self.assertEqual(
            MODULE.extract_model_review(
                archive({"review-openai.json": review}),
                "openai",
            ),
            review,
        )
        for payload in (
            archive(
                {
                    "review-openai.json": review,
                    "untrusted-extra.json": b"{}",
                },
            ),
            archive({"../review-openai.json": review}),
            archive(
                {
                    "review-openai.json": b"x" * (MODULE.MAX_REVIEW_BYTES + 1),
                },
            ),
        ):
            with (
                self.subTest(size=len(payload)),
                self.assertRaises(MODULE.PermitInputError),
            ):
                MODULE.extract_model_review(payload, "openai")
        with self.assertRaisesRegex(MODULE.PermitInputError, "unsupported"):
            MODULE.extract_model_review(
                archive({"review-unknown.json": review}),
                "unknown",
            )

    def test_parent_kernel_exactly_recomputes_allow_and_deny(self) -> None:
        for decision, returncode in (("ALLOW", 0), ("DENY", 3)):
            with (
                self.subTest(decision=decision),
                tempfile.TemporaryDirectory() as tmpdir,
            ):
                root = Path(tmpdir)
                permit_path = root / "release-permit.json"
                context_path = root / "context.json"
                output_path = root / "parent-kernel-permit.json"
                permit_bytes = ('{"decision":"' + decision + '"}\n').encode()
                permit_path.write_bytes(permit_bytes)
                context_path.write_text("{}\n", encoding="utf-8")
                review_paths = {
                    provider: root / f"review-{provider}.json"
                    for provider in MODULE.MODEL_REVIEW_PROVIDERS
                }
                for path in review_paths.values():
                    path.write_text("{}\n", encoding="utf-8")

                def reproduce(command, **_kwargs):
                    Path(command[command.index("--output") + 1]).write_bytes(
                        permit_bytes
                    )
                    return mock.Mock(returncode=returncode, stdout=b"", stderr=b"")

                with mock.patch.object(
                    MODULE.subprocess,
                    "run",
                    side_effect=reproduce,
                ) as run:
                    MODULE.verify_permit_reduction(
                        root / "release-permit-verify",
                        permit_path,
                        context_path,
                        review_paths,
                        output_path,
                    )
                command = run.call_args.args[0]
                self.assertEqual(command.count("--review"), 2)
                self.assertLess(
                    command.index(str(review_paths["anthropic"].resolve())),
                    command.index(str(review_paths["openai"].resolve())),
                )

    def test_parent_kernel_reduction_rejects_nonidentical_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            permit_path = root / "release-permit.json"
            context_path = root / "context.json"
            output_path = root / "parent-kernel-permit.json"
            permit_path.write_text('{"decision":"DENY"}\n', encoding="utf-8")
            context_path.write_text("{}\n", encoding="utf-8")
            review_paths = {
                provider: root / f"review-{provider}.json"
                for provider in MODULE.MODEL_REVIEW_PROVIDERS
            }
            for path in review_paths.values():
                path.write_text("{}\n", encoding="utf-8")

            def mismatch(command, **_kwargs):
                Path(command[command.index("--output") + 1]).write_text(
                    '{"decision":"ALLOW"}\n',
                    encoding="utf-8",
                )
                return mock.Mock(returncode=3, stdout=b"", stderr=b"")

            with (
                mock.patch.object(MODULE.subprocess, "run", side_effect=mismatch),
                self.assertRaisesRegex(
                    MODULE.PermitInputError,
                    "differs from the parent Kernel",
                ),
            ):
                MODULE.verify_permit_reduction(
                    root / "release-permit-verify",
                    permit_path,
                    context_path,
                    review_paths,
                    output_path,
                )


if __name__ == "__main__":
    unittest.main()
