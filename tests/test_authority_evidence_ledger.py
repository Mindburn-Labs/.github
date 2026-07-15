from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "authority_evidence_ledger.py"
SPEC = importlib.util.spec_from_file_location("authority_evidence_ledger", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeClient:
    def __init__(self, *, recursive_tree_truncated: bool = False) -> None:
        self.ref_sha = "1" * 40
        self.commits = {self.ref_sha: {"tree": {"sha": "2" * 40}}}
        self.trees: dict[str, list[dict[str, object]]] = {"2" * 40: []}
        self.blobs: dict[str, bytes] = {}
        self.patches = 0
        self.recursive_tree_truncated = recursive_tree_truncated
        self.recursive_tree_reads = 0
        self.created_trees = 0
        self.created_commits = 0

    def response(self, value):
        return MODULE.APIResponse(json.loads(json.dumps(value)), None)

    def request(self, method: str, path: str, *, payload=None):
        if "/git/ref/heads/authority/evidence-v1" in path and method == "GET":
            return self.response(
                {"ref": MODULE.LEDGER_REF, "object": {"sha": self.ref_sha}}
            )
        if "/git/refs/heads/authority/evidence-v1" in path and method == "PATCH":
            if payload.get("force") is not False:
                raise AssertionError("ledger update must be non-forcing")
            commit = self.commits[payload["sha"]]
            parents = commit["parents"]
            if parents != [self.ref_sha]:
                raise MODULE.PermitInputError("non-fast-forward")
            self.ref_sha = payload["sha"]
            self.patches += 1
            return self.response(
                {"ref": MODULE.LEDGER_REF, "object": {"sha": self.ref_sha}}
            )
        if "/git/commits/" in path and method == "GET":
            return self.response(self.commits[path.rsplit("/", 1)[1]])
        if "/compare/" in path and method == "GET":
            parent, head = path.rsplit("/", 1)[1].split("...", 1)
            if head != self.ref_sha:
                raise AssertionError("comparison did not use the live ledger head")
            return self.response(
                {
                    "status": "ahead",
                    "ahead_by": 1,
                    "behind_by": 0,
                    "merge_base_commit": {"sha": parent},
                }
            )
        if "/git/trees/" in path and method == "GET":
            self.recursive_tree_reads += 1
            sha = path.split("/git/trees/", 1)[1].split("?", 1)[0]
            return self.response(
                {
                    "sha": sha,
                    "truncated": self.recursive_tree_truncated,
                    "tree": self.trees[sha],
                }
            )
        if "/contents/" in path and method == "GET":
            encoded, query = path.split("/contents/", 1)[1].split("?", 1)
            directory = urllib.parse.unquote(encoded)
            ref = urllib.parse.parse_qs(query)["ref"][0]
            tree_sha = self.commits[ref]["tree"]["sha"]
            by_path: dict[str, dict[str, object]] = {}
            for entry in self.trees[tree_sha]:
                entry_path = str(entry["path"])
                if not entry_path.startswith(directory + "/"):
                    continue
                remainder = entry_path.removeprefix(directory + "/")
                segment, separator, _ = remainder.partition("/")
                child_path = f"{directory}/{segment}"
                if separator:
                    by_path[child_path] = {
                        "path": child_path,
                        "type": "dir",
                        "sha": hashlib.sha1(child_path.encode()).hexdigest(),  # nosec B324
                    }
                else:
                    by_path[child_path] = {
                        "path": child_path,
                        "type": "file",
                        "sha": entry["sha"],
                    }
            if not by_path:
                raise MODULE.PermitInputError(
                    "GitHub GET failed with HTTP 404: namespace absent"
                )
            return self.response(list(by_path.values()))
        if path.endswith("/git/blobs") and method == "POST":
            content = base64.b64decode(payload["content"], validate=True)
            sha = hashlib.sha1(b"blob\0" + content).hexdigest()  # nosec B324
            self.blobs[sha] = content
            return self.response({"sha": sha})
        if "/git/blobs/" in path and method == "GET":
            sha = path.rsplit("/", 1)[1]
            return self.response(
                {
                    "sha": sha,
                    "encoding": "base64",
                    "content": base64.b64encode(self.blobs[sha]).decode("ascii"),
                }
            )
        if path.endswith("/git/trees") and method == "POST":
            base = list(self.trees[payload["base_tree"]])
            by_path = {entry["path"]: entry for entry in base}
            for entry in payload["tree"]:
                by_path[entry["path"]] = entry
            sha = "3579bdf"[self.created_trees] * 40
            self.created_trees += 1
            self.trees[sha] = list(by_path.values())
            return self.response({"sha": sha})
        if path.endswith("/git/commits") and method == "POST":
            sha = "468ace"[self.created_commits] * 40
            self.created_commits += 1
            self.commits[sha] = {
                "sha": sha,
                "tree": {"sha": payload["tree"]},
                "parents": payload["parents"],
            }
            return self.response({"sha": sha})
        raise AssertionError((method, path, payload))


class AuthorityEvidenceLedgerTests(unittest.TestCase):
    def inputs(self) -> dict[str, bytes]:
        return {
            "release-permit.json": b'{"decision":"ALLOW"}\n',
            "release-permit.attestation.json": b'{"bundle":true}\n',
        }

    def append(self, client: FakeClient, inputs=None):
        return MODULE.append_record(
            client,
            namespace="bootstrap/pr-36/" + "a" * 40 + "/intent",
            record_type="bootstrap",
            phase="intent",
            workflow_sha="b" * 40,
            run_id=42,
            run_attempt=1,
            inputs=inputs or self.inputs(),
        )

    def test_append_is_non_forcing_and_exact_retry_is_idempotent(self) -> None:
        client = FakeClient()
        first = self.append(client)
        self.assertFalse(first["idempotent"])
        self.assertEqual(first["ledger_parent_sha"], "1" * 40)
        self.assertEqual(first["ledger_head_sha"], "4" * 40)
        self.assertEqual(client.patches, 1)

        second = self.append(client)
        self.assertTrue(second["idempotent"])
        self.assertEqual(client.patches, 1)

    def test_existing_namespace_with_different_bytes_fails_closed(self) -> None:
        client = FakeClient()
        self.append(client)
        changed = self.inputs()
        changed["release-permit.json"] = b'{"decision":"DENY"}\n'
        with self.assertRaisesRegex(MODULE.PermitInputError, "manifest"):
            self.append(client, changed)

    def test_append_ignores_a_truncated_whole_ledger_tree(self) -> None:
        client = FakeClient(recursive_tree_truncated=True)
        receipt = self.append(client)
        self.assertFalse(receipt["idempotent"])
        self.assertEqual(client.recursive_tree_reads, 0)

    def test_stable_descriptor_survives_later_ledger_heads(self) -> None:
        client = FakeClient()
        first = self.append(client)
        initial = MODULE.stable_record_descriptor(first)
        closure = MODULE.append_record(
            client,
            namespace="bootstrap/pr-36/" + "a" * 40 + "/closure",
            record_type="bootstrap",
            phase="closure",
            workflow_sha="b" * 40,
            run_id=42,
            run_attempt=1,
            inputs={"intent-descriptor.json": MODULE.canonical_json(initial)},
        )
        self.assertNotEqual(closure["ledger_head_sha"], first["ledger_head_sha"])
        retry = self.append(client)
        self.assertTrue(retry["idempotent"])
        self.assertEqual(retry["ledger_head_sha"], closure["ledger_head_sha"])
        self.assertEqual(MODULE.stable_record_descriptor(retry), initial)

    def test_namespace_cannot_nest_beneath_a_phase_leaf(self) -> None:
        client = FakeClient()
        with self.assertRaisesRegex(MODULE.PermitInputError, "record grammar|phase"):
            MODULE.append_record(
                client,
                namespace="bootstrap/pr-36/" + "a" * 40 + "/intent/x/closure",
                record_type="bootstrap",
                phase="closure",
                workflow_sha="b" * 40,
                run_id=42,
                run_attempt=1,
                inputs=self.inputs(),
            )

    def test_read_record_rehydrates_exact_manifest_bound_bytes(self) -> None:
        client = FakeClient()
        receipt = self.append(client)
        record = MODULE.read_record(
            client,
            namespace=receipt["namespace"],
            record_type="bootstrap",
            phase="intent",
        )
        self.assertIsNotNone(record)
        self.assertEqual(record["inputs"], self.inputs())
        self.assertEqual(record["descriptor"], MODULE.stable_record_descriptor(receipt))

    def test_input_collection_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "evidence").mkdir()
            (root / "outside").write_text("secret", encoding="utf-8")
            (root / "evidence" / "escape").symlink_to(root / "outside")
            with self.assertRaisesRegex(MODULE.PermitInputError, "symbolic"):
                MODULE.collect_inputs(
                    root,
                    includes=[],
                    include_trees=["evidence"],
                )

    def test_append_rejects_a_path_trie_larger_than_the_read_bound(self) -> None:
        inputs = {
            f"a{index}/b{index}/evidence.json": b"{}\n"
            for index in range(MODULE.MAX_FILES)
        }
        with self.assertRaisesRegex(MODULE.PermitInputError, "path tree"):
            MODULE.validate_inputs(inputs)


if __name__ == "__main__":
    unittest.main()
