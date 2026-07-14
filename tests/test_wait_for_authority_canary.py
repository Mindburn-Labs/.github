from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import sys
import unittest
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
    def test_extract_permit_accepts_one_bounded_exact_entry(self) -> None:
        content = b'{"decision":"ALLOW"}\n'
        self.assertEqual(
            MODULE.extract_permit(archive({"release-permit.json": content})),
            content,
        )

    def test_extract_permit_rejects_substitution_or_oversize(self) -> None:
        for payload in (
            archive({"release-permit.json": b"{}", "extra": b"x"}),
            archive({"../release-permit.json": b"{}"}),
            archive({"release-permit.json": b"x" * (MODULE.MAX_PERMIT_BYTES + 1)}),
        ):
            with self.subTest(size=len(payload)), self.assertRaises(MODULE.PermitInputError):
                MODULE.extract_permit(payload)


if __name__ == "__main__":
    unittest.main()
