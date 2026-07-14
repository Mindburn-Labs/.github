from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import sys
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
            with self.subTest(size=len(payload)), self.assertRaises(MODULE.PermitInputError):
                MODULE.extract_attested_permit(payload)

    def test_extract_trusted_context_accepts_exact_bounded_input(self) -> None:
        context = b'{"schema":"mindburn.release-permit-context/v2"}\n'
        self.assertEqual(
            MODULE.extract_trusted_context(
                archive(
                    {
                        "context.json": context,
                        "review-prompt.txt": b"Review this exact context.\n",
                    },
                ),
            ),
            context,
        )

    def test_extract_trusted_context_rejects_substitution(self) -> None:
        for payload in (
            archive({"context.json": b"{}", "extra": b"x"}),
            archive({"../context.json": b"{}", "review-prompt.txt": b"x"}),
            archive(
                {
                    "context.json": b"x" * (MODULE.MAX_CONTEXT_BYTES + 1),
                    "review-prompt.txt": b"x",
                },
            ),
        ):
            with self.subTest(size=len(payload)), self.assertRaises(MODULE.PermitInputError):
                MODULE.extract_trusted_context(payload)


if __name__ == "__main__":
    unittest.main()
