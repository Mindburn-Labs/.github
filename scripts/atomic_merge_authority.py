#!/usr/bin/env python3
"""Atomically advance authority main to GitHub's exact reviewed merge commit."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any
import urllib.error
import urllib.request

from autonomous_release_permit import PermitInputError, require_sha


API_VERSION = "2026-03-10"
REPOSITORY = "Mindburn-Labs/.github"
MAIN_REF = "refs/heads/main"
UPDATE_REFS_MUTATION = """
mutation($repositoryId: ID!, $beforeOid: GitObjectID!, $afterOid: GitObjectID!) {
  updateRefs(input: {
    repositoryId: $repositoryId,
    refUpdates: [{
      name: "refs/heads/main",
      beforeOid: $beforeOid,
      afterOid: $afterOid,
      force: false
    }]
  }) { clientMutationId }
}
"""
REPOSITORY_ID_QUERY = """
query {
  repository(owner: "Mindburn-Labs", name: ".github") { id }
}
"""


class GitHubMergeClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise PermitInputError("GH_TOKEN is required")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        content = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
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
                value = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            raise PermitInputError(
                f"GitHub {method} {path} failed with HTTP {exc.code}: {detail}",
            ) from exc
        except (urllib.error.URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermitInputError(f"GitHub {method} {path} failed: {exc}") from exc
        if not isinstance(value, dict):
            raise PermitInputError(f"GitHub {method} {path} returned a non-object")
        return value

    def get(self, path: str) -> dict[str, Any]:
        return self.request("GET", path)

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        response = self.request(
            "POST",
            "/graphql",
            payload={"query": query, "variables": variables},
        )
        if response.get("errors"):
            raise PermitInputError(f"GitHub GraphQL rejected atomic ref update: {response['errors']}")
        data = response.get("data")
        if not isinstance(data, dict):
            raise PermitInputError("GitHub GraphQL response has no data object")
        return data


def nested_string(value: dict[str, Any], *keys: str, label: str) -> str:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            raise PermitInputError(f"GitHub response is missing {label}")
        current = current.get(key)
    if not isinstance(current, str) or not current:
        raise PermitInputError(f"GitHub response has invalid {label}")
    return current


def validate_pull_request(
    pull_request: dict[str, Any],
    *,
    number: int,
    base_sha: str,
    head_sha: str,
    merged: bool,
    merge_sha: str | None = None,
) -> None:
    expected_state = "closed" if merged else "open"
    if (
        pull_request.get("number") != number
        or pull_request.get("state") != expected_state
        or pull_request.get("draft") is True
        or nested_string(pull_request, "base", "ref", label="pull request base ref") != "main"
        or nested_string(pull_request, "base", "sha", label="pull request base SHA") != base_sha
        or nested_string(pull_request, "head", "sha", label="pull request head SHA") != head_sha
        or nested_string(
            pull_request,
            "head",
            "repo",
            "full_name",
            label="pull request head repository",
        )
        != REPOSITORY
    ):
        raise PermitInputError("pull request does not match the exact ratified candidate")
    if merged:
        if pull_request.get("merged") is not True or pull_request.get("merge_commit_sha") != merge_sha:
            raise PermitInputError("pull request is not marked merged at the exact reviewed commit")
    elif pull_request.get("merged") is True:
        raise PermitInputError("candidate pull request was already merged")


def atomic_merge(args: argparse.Namespace, client: GitHubMergeClient) -> dict[str, Any]:
    base_sha = require_sha(args.base_sha, label="base_sha", length=40)
    head_sha = require_sha(args.head_sha, label="head_sha", length=40)
    merge_sha = require_sha(args.merge_sha, label="merge_sha", length=40)
    tree_sha = require_sha(args.tree_sha, label="tree_sha", length=40)
    if args.pull_request <= 0:
        raise PermitInputError("pull_request must be positive")

    main = client.get(f"/repos/{REPOSITORY}/git/ref/heads/main")
    if nested_string(main, "object", "sha", label="main SHA") != base_sha:
        raise PermitInputError("authority main moved before the atomic merge")
    pull_request = client.get(f"/repos/{REPOSITORY}/pulls/{args.pull_request}")
    validate_pull_request(
        pull_request,
        number=args.pull_request,
        base_sha=base_sha,
        head_sha=head_sha,
        merged=False,
    )
    merge_commit = client.get(f"/repos/{REPOSITORY}/git/commits/{merge_sha}")
    parents = merge_commit.get("parents")
    if (
        not isinstance(parents, list)
        or len(parents) != 2
        or [parent.get("sha") for parent in parents if isinstance(parent, dict)]
        != [base_sha, head_sha]
        or nested_string(merge_commit, "tree", "sha", label="merge tree SHA") != tree_sha
    ):
        raise PermitInputError("reviewed merge commit does not have the exact base, head, and tree")

    repository_data = client.graphql(REPOSITORY_ID_QUERY, {})
    repository = repository_data.get("repository")
    if not isinstance(repository, dict) or not isinstance(repository.get("id"), str):
        raise PermitInputError("GitHub GraphQL returned no authority repository ID")
    update_data = client.graphql(
        UPDATE_REFS_MUTATION,
        {
            "repositoryId": repository["id"],
            "beforeOid": base_sha,
            "afterOid": merge_sha,
        },
    )
    if not isinstance(update_data.get("updateRefs"), dict):
        raise PermitInputError("GitHub GraphQL returned no atomic ref-update result")

    main_after = client.get(f"/repos/{REPOSITORY}/git/ref/heads/main")
    if nested_string(main_after, "object", "sha", label="main SHA") != merge_sha:
        raise PermitInputError("authority main does not equal the exact reviewed merge commit")
    for _ in range(10):
        pull_request = client.get(f"/repos/{REPOSITORY}/pulls/{args.pull_request}")
        try:
            validate_pull_request(
                pull_request,
                number=args.pull_request,
                base_sha=base_sha,
                head_sha=head_sha,
                merged=True,
                merge_sha=merge_sha,
            )
            break
        except PermitInputError:
            time.sleep(1)
    else:
        raise PermitInputError("GitHub did not mark the exact candidate pull request merged")
    return {
        "schema": "mindburn.release-authority-atomic-merge/v1",
        "repository": REPOSITORY,
        "pull_request": args.pull_request,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_sha": merge_sha,
        "merge_tree_sha": tree_sha,
        "ref": MAIN_REF,
        "force": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--merge-sha", required=True)
    parser.add_argument("--tree-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        receipt = atomic_merge(
            args,
            GitHubMergeClient(
                os.environ.get("GH_TOKEN", ""),
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            ),
        )
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError) as exc:
        print(f"atomic-merge-authority: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
