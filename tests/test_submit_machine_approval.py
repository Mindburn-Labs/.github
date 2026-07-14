from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "submit_machine_approval.py"
SPEC = importlib.util.spec_from_file_location("submit_machine_approval", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

HEAD_SHA = "2" * 40
WORKFLOW_SHA = "3" * 40
REPOSITORY = "Mindburn-Labs/.github"


class FakeClient:
    def __init__(self) -> None:
        self.reviews: list[dict[str, object]] = []
        self.posts = 0

    def request(self, method: str, path: str, *, payload=None):
        if path.startswith("/installation/repositories"):
            return {"repositories": [{"full_name": REPOSITORY}]}
        if path == "/repos/Mindburn-Labs/.github/pulls/36":
            return {
                "number": 36,
                "state": "open",
                "draft": False,
                "merged": False,
                "base": {"ref": "main"},
                "head": {"sha": HEAD_SHA, "repo": {"full_name": REPOSITORY}},
            }
        if path.endswith("/reviews?per_page=100"):
            return json.loads(json.dumps(self.reviews))
        if method == "POST" and path.endswith("/reviews"):
            self.posts += 1
            review = {
                "id": len(self.reviews) + 1,
                "state": "APPROVED",
                "commit_id": payload["commit_id"],
                "user": {"login": MODULE.APPROVER_LOGIN},
            }
            self.reviews.append(review)
            return json.loads(json.dumps(review))
        if method == "GET" and "/reviews/" in path:
            review_id = int(path.rsplit("/", 1)[1])
            return json.loads(json.dumps(self.reviews[review_id - 1]))
        raise AssertionError(f"unexpected request {method} {path}")


def arguments() -> argparse.Namespace:
    return argparse.Namespace(
        permit=Path("permit.json"),
        permit_bundle=Path("permit.attestation.json"),
        trusted_context=Path("context.json"),
        kernel_verifier=Path("release-permit-verify"),
        repository=REPOSITORY,
        pull_request=36,
        head_sha=HEAD_SHA,
        workflow_sha=WORKFLOW_SHA,
        approver_app_slug=MODULE.APPROVER_SLUG,
        approver_installation_id=MODULE.APPROVER_INSTALLATION_ID,
    )


class SubmitMachineApprovalTests(unittest.TestCase):
    def permit(self) -> dict[str, object]:
        return {
            "decision": "ALLOW",
            "repository": REPOSITORY,
            "pull_request": 36,
            "head_sha": HEAD_SHA,
            "workflow_sha": WORKFLOW_SHA,
            "permit_id": "sha256:" + "4" * 64,
        }

    def test_submits_and_confirms_exact_head_approval(self) -> None:
        client = FakeClient()
        with mock.patch.object(MODULE, "verify_permit", return_value=self.permit()):
            receipt = MODULE.submit_machine_approval(
                arguments(),
                client,
                attestation_token="observer",
            )
        self.assertEqual(receipt["review_state"], "APPROVED")
        self.assertEqual(receipt["head_sha"], HEAD_SHA)
        self.assertEqual(client.posts, 1)

    def test_exact_latest_approval_is_idempotent(self) -> None:
        client = FakeClient()
        client.reviews.append(
            {
                "id": 1,
                "state": "APPROVED",
                "commit_id": HEAD_SHA,
                "user": {"login": MODULE.APPROVER_LOGIN},
            },
        )
        with mock.patch.object(MODULE, "verify_permit", return_value=self.permit()):
            MODULE.submit_machine_approval(arguments(), client, attestation_token="observer")
        self.assertEqual(client.posts, 0)

    def test_stale_approval_is_replaced(self) -> None:
        client = FakeClient()
        client.reviews.append(
            {
                "id": 1,
                "state": "APPROVED",
                "commit_id": "9" * 40,
                "user": {"login": MODULE.APPROVER_LOGIN},
            },
        )
        with mock.patch.object(MODULE, "verify_permit", return_value=self.permit()):
            MODULE.submit_machine_approval(arguments(), client, attestation_token="observer")
        self.assertEqual(client.posts, 1)

    def test_wrong_repository_scope_fails_closed_before_review(self) -> None:
        client = FakeClient()
        original = client.request

        def request(method: str, path: str, *, payload=None):
            value = original(method, path, payload=payload)
            if path.startswith("/installation/repositories"):
                value["repositories"] = []
            return value

        client.request = request  # type: ignore[method-assign]
        with (
            mock.patch.object(MODULE, "verify_permit", return_value=self.permit()),
            self.assertRaisesRegex(MODULE.PermitInputError, "scope is not exact"),
        ):
            MODULE.submit_machine_approval(arguments(), client, attestation_token="observer")
        self.assertEqual(client.posts, 0)

    def test_wrong_action_identity_fails_closed_before_review(self) -> None:
        client = FakeClient()
        args = arguments()
        args.approver_installation_id += 1
        with (
            mock.patch.object(MODULE, "verify_permit", return_value=self.permit()),
            self.assertRaisesRegex(MODULE.PermitInputError, "wrong approver App identity"),
        ):
            MODULE.submit_machine_approval(args, client, attestation_token="observer")
        self.assertEqual(client.posts, 0)


if __name__ == "__main__":
    unittest.main()
