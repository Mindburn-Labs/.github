#!/usr/bin/env python3
"""Submit an exact-head approval using the isolated HELM approver GitHub App."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from autonomous_release_permit import PermitInputError, require_sha
from verify_authority_promotion import verify_permit_with_kernel
from wait_for_authority_canary import load_json_file, verify_attestation


API_VERSION = "2026-03-10"
APPROVER_LOGIN = "helm-authority-approver[bot]"
APPROVER_SLUG = "helm-authority-approver"
APPROVER_APP_ID = 4298283
APPROVER_INSTALLATION_ID = 146576964
ORGANIZATION = "Mindburn-Labs"
SCHEMA = "mindburn.release-authority-machine-approval/v1"


class GitHubApprovalClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise PermitInputError("HELM authority approver token is required")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        content = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": " ".join(("Bearer", self.token)),
            "X-GitHub-Api-Version": API_VERSION,
        }
        if content is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.api_url + path,
            data=content,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
                body = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            raise PermitInputError(
                f"GitHub {method} {path} failed with HTTP {exc.code}: {detail}",
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PermitInputError(f"GitHub {method} {path} failed: {exc}") from exc
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermitInputError(f"GitHub {method} {path} returned invalid JSON") from exc


def nested(value: dict[str, Any], *keys: str, label: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            raise PermitInputError(f"GitHub response is missing {label}")
        current = current.get(key)
    return current


def require_object(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def require_list(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise PermitInputError(f"{label} must be an array")
    return value


def verify_installation(
    client: GitHubApprovalClient,
    *,
    repository: str,
    app_slug: str,
    installation_id: int,
) -> dict[str, Any]:
    if app_slug != APPROVER_SLUG or installation_id != APPROVER_INSTALLATION_ID:
        raise PermitInputError("token action returned the wrong approver App identity")
    encoded = urllib.parse.quote(repository, safe="")
    repositories = require_object(
        client.request("GET", f"/installation/repositories?per_page=100&repository={encoded}"),
        label="installation repositories",
    )
    names = {
        item.get("full_name")
        for item in require_list(repositories.get("repositories"), label="installation repositories")
        if isinstance(item, dict)
    }
    if names != {repository}:
        raise PermitInputError("approver token repository scope is not exact")
    return {
        "app_id": APPROVER_APP_ID,
        "app_slug": app_slug,
        "id": installation_id,
    }


def verify_permit(
    args: argparse.Namespace,
    *,
    attestation_token: str,
) -> dict[str, Any]:
    permit = load_json_file(args.permit, label="machine approval permit")
    expected = {
        "decision": "ALLOW",
        "repository": args.repository,
        "pull_request": args.pull_request,
        "head_sha": args.head_sha,
        "workflow_sha": args.workflow_sha,
    }
    for field, value in expected.items():
        if permit.get(field) != value:
            raise PermitInputError(f"machine approval permit {field} is not exact")
    merge_sha = require_sha(permit.get("merge_sha"), label="permit merge_sha", length=40)
    verify_attestation(
        args.permit,
        args.permit_bundle,
        repository=args.repository,
        workflow_sha=args.workflow_sha,
        source_sha=merge_sha,
        github_token=attestation_token,
    )
    verify_permit_with_kernel(args.kernel_verifier, args.permit, args.trusted_context)
    return permit


def validate_pull_request(
    client: GitHubApprovalClient,
    *,
    repository: str,
    pull_request: int,
    head_sha: str,
) -> dict[str, Any]:
    value = require_object(
        client.request("GET", f"/repos/{repository}/pulls/{pull_request}"),
        label="pull request",
    )
    if (
        value.get("number") != pull_request
        or value.get("state") != "open"
        or value.get("draft") is True
        or value.get("merged") is True
        or nested(value, "base", "ref", label="pull request base ref") != "main"
        or nested(value, "head", "sha", label="pull request head SHA") != head_sha
        or nested(value, "head", "repo", "full_name", label="pull request head repository")
        != repository
    ):
        raise PermitInputError("pull request does not match the machine approval contract")
    return value


def latest_approver_review(reviews: list[Any]) -> dict[str, Any] | None:
    matches = [
        review
        for review in reviews
        if isinstance(review, dict)
        and nested(review, "user", "login", label="review author") == APPROVER_LOGIN
        and isinstance(review.get("id"), int)
    ]
    return max(matches, key=lambda review: review["id"], default=None)


def submit_machine_approval(
    args: argparse.Namespace,
    client: GitHubApprovalClient,
    *,
    attestation_token: str,
) -> dict[str, Any]:
    args.head_sha = require_sha(args.head_sha, label="head_sha", length=40)
    args.workflow_sha = require_sha(args.workflow_sha, label="workflow_sha", length=40)
    if not args.repository.startswith(f"{ORGANIZATION}/") or args.pull_request <= 0:
        raise PermitInputError("machine approval target is invalid")

    permit = verify_permit(args, attestation_token=attestation_token)
    installation = verify_installation(
        client,
        repository=args.repository,
        app_slug=args.approver_app_slug,
        installation_id=args.approver_installation_id,
    )
    validate_pull_request(
        client,
        repository=args.repository,
        pull_request=args.pull_request,
        head_sha=args.head_sha,
    )
    reviews_path = f"/repos/{args.repository}/pulls/{args.pull_request}/reviews"
    reviews = require_list(client.request("GET", f"{reviews_path}?per_page=100"), label="reviews")
    review = latest_approver_review(reviews)
    if review is None or review.get("state") != "APPROVED" or review.get("commit_id") != args.head_sha:
        review = require_object(
            client.request(
                "POST",
                reviews_path,
                payload={
                    "body": f"HELM signed ALLOW permit {permit['permit_id']}",
                    "commit_id": args.head_sha,
                    "event": "APPROVE",
                },
            ),
            label="created review",
        )
    review_id = review.get("id")
    if not isinstance(review_id, int) or review_id <= 0:
        raise PermitInputError("machine approval review ID is invalid")
    confirmed = require_object(
        client.request("GET", f"{reviews_path}/{review_id}"),
        label="confirmed review",
    )
    if (
        confirmed.get("state") != "APPROVED"
        or confirmed.get("commit_id") != args.head_sha
        or nested(confirmed, "user", "login", label="confirmed review author")
        != APPROVER_LOGIN
    ):
        raise PermitInputError("GitHub did not retain the exact-head machine approval")
    validate_pull_request(
        client,
        repository=args.repository,
        pull_request=args.pull_request,
        head_sha=args.head_sha,
    )
    return {
        "schema": SCHEMA,
        "repository": args.repository,
        "pull_request": args.pull_request,
        "head_sha": args.head_sha,
        "workflow_sha": args.workflow_sha,
        "permit_id": permit["permit_id"],
        "review_id": review_id,
        "review_state": "APPROVED",
        "approver_login": APPROVER_LOGIN,
        "approver_app_id": installation.get("app_id"),
        "approver_installation_id": installation.get("id"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--permit", type=Path, required=True)
    parser.add_argument("--permit-bundle", type=Path, required=True)
    parser.add_argument("--trusted-context", type=Path, required=True)
    parser.add_argument("--kernel-verifier", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--approver-app-slug", required=True)
    parser.add_argument("--approver-installation-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        approver_token = os.environ.get("HELM_AUTHORITY_APPROVER_TOKEN", "")
        attestation_token = os.environ.get("GH_TOKEN", "")
        if not attestation_token:
            raise PermitInputError("GH_TOKEN is required for attestation verification")
        if approver_token == attestation_token:
            raise PermitInputError("approver and attestation tokens must be distinct")
        result = submit_machine_approval(
            args,
            GitHubApprovalClient(
                approver_token,
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            ),
            attestation_token=attestation_token,
        )
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"submit-machine-approval: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
