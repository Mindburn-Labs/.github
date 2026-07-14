#!/usr/bin/env python3
"""Remove human approval gates only after the public machine gate is active."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any
import urllib.error
import urllib.request

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from authority_ruleset_broker import (
    API_VERSION,
    ORGANIZATION,
    PUBLIC_AUTONOMOUS_REPOSITORY_IDS,
    STABLE_RULESET_ID,
    validate_ref,
    validate_ruleset,
)


BOOTSTRAP_SCHEMA = "mindburn.release-authority-bootstrap/v1"
HUMAN_RULESET_ID = 17911735
HUMAN_RULESET_NAME = "Mindburn default branch approval gate"
AUTHORITY_REPOSITORY_ID = 1159255601
KERNEL_REPOSITORY_ID = 1158479649


class GitHubAdminClient:
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
    ) -> dict[str, Any] | None:
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
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermitInputError(f"GitHub {method} {path} returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise PermitInputError(f"GitHub {method} {path} returned a non-object")
        return value


def require_object(value: dict[str, Any] | None, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} returned no object")
    return value


def load_contract(path: Path) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=str(path))
    except UnicodeDecodeError as exc:
        raise PermitInputError("bootstrap contract is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError("bootstrap contract must be an object")
    require_exact_keys(
        value,
        required={"schema", "human_approval_ruleset", "classic_branch_protection"},
        label="bootstrap contract",
    )
    if value["schema"] != BOOTSTRAP_SCHEMA:
        raise PermitInputError("unsupported bootstrap contract schema")

    human = value["human_approval_ruleset"]
    if not isinstance(human, dict):
        raise PermitInputError("human approval ruleset contract must be an object")
    require_exact_keys(
        human,
        required={
            "id",
            "name",
            "before_repository_ids",
            "after_repository_ids",
            "remove_repository_ids",
            "rules",
        },
        label="human approval ruleset contract",
    )
    before = human["before_repository_ids"]
    after = human["after_repository_ids"]
    remove = human["remove_repository_ids"]
    for ids, label in ((before, "before"), (after, "after"), (remove, "remove")):
        if (
            not isinstance(ids, list)
            or any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in ids)
            or ids != sorted(set(ids))
        ):
            raise PermitInputError(f"bootstrap {label} repository IDs are invalid")
    if human["id"] != HUMAN_RULESET_ID or human["name"] != HUMAN_RULESET_NAME:
        raise PermitInputError("bootstrap contract names the wrong human ruleset")
    if set(remove) != {AUTHORITY_REPOSITORY_ID, KERNEL_REPOSITORY_ID}:
        raise PermitInputError("bootstrap removes the wrong human-gated repositories")
    if set(remove) - set(PUBLIC_AUTONOMOUS_REPOSITORY_IDS):
        raise PermitInputError("bootstrap removal is outside public machine coverage")
    if after != [repository_id for repository_id in before if repository_id not in remove]:
        raise PermitInputError("bootstrap post-removal repository IDs are not exact")
    if not isinstance(human["rules"], list) or not human["rules"]:
        raise PermitInputError("bootstrap human rules must be a non-empty list")

    classic = value["classic_branch_protection"]
    if not isinstance(classic, dict):
        raise PermitInputError("classic branch protection contract must be an object")
    require_exact_keys(
        classic,
        required={"repository", "branch", "before", "after"},
        label="classic branch protection contract",
    )
    if classic["repository"] != "Mindburn-Labs/.github" or classic["branch"] != "main":
        raise PermitInputError("bootstrap contract names the wrong protected branch")
    if not isinstance(classic["before"], dict) or not isinstance(classic["after"], dict):
        raise PermitInputError("classic protection states must be objects")
    expected_after = json.loads(json.dumps(classic["before"]))
    expected_after["required_pull_request_reviews"] = None
    if classic["after"] != expected_after:
        raise PermitInputError("classic protection contract changes more than human approval")
    return value


def human_ruleset_state(contract: dict[str, Any], state: str) -> dict[str, Any]:
    human = contract["human_approval_ruleset"]
    repository_ids = human[f"{state}_repository_ids"]
    return {
        "name": human["name"],
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
            "repository_id": {"repository_ids": repository_ids},
        },
        "rules": human["rules"],
    }


def controlled_ruleset(ruleset: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ruleset.get(key)
        for key in ("name", "target", "enforcement", "bypass_actors", "conditions", "rules")
    }


def boolean_setting(protection: dict[str, Any], key: str) -> bool | None:
    value = protection.get(key)
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("enabled"), bool):
        raise PermitInputError(f"classic protection {key} is malformed")
    return value["enabled"]


def normalize_classic_protection(protection: dict[str, Any]) -> dict[str, Any]:
    reviews = protection.get("required_pull_request_reviews")
    if reviews is not None:
        if not isinstance(reviews, dict):
            raise PermitInputError("classic required pull request reviews are malformed")
        reviews = {
            key: reviews.get(key)
            for key in (
                "dismiss_stale_reviews",
                "require_code_owner_reviews",
                "require_last_push_approval",
                "required_approving_review_count",
            )
        }
    return {
        "allow_deletions": boolean_setting(protection, "allow_deletions"),
        "allow_force_pushes": boolean_setting(protection, "allow_force_pushes"),
        "allow_fork_syncing": boolean_setting(protection, "allow_fork_syncing"),
        "block_creations": boolean_setting(protection, "block_creations"),
        "enforce_admins": boolean_setting(protection, "enforce_admins"),
        "lock_branch": boolean_setting(protection, "lock_branch"),
        "required_conversation_resolution": boolean_setting(
            protection,
            "required_conversation_resolution",
        ),
        "required_linear_history": boolean_setting(protection, "required_linear_history"),
        "required_pull_request_reviews": reviews,
        "required_signatures": boolean_setting(protection, "required_signatures"),
        "required_status_checks": protection.get("required_status_checks"),
        "restrictions": protection.get("restrictions"),
    }


def remove_human_approval_gates(
    args: argparse.Namespace,
    client: GitHubAdminClient,
) -> dict[str, Any]:
    candidate_sha = require_sha(args.candidate_sha, label="candidate_sha", length=40)
    candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    contract = load_contract(args.contract)

    stable = require_object(
        client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{STABLE_RULESET_ID}"),
        label="stable machine ruleset",
    )
    validate_ruleset(
        stable,
        kind="stable",
        expected_sha=candidate_sha,
        expected_ref=candidate_ref,
    )

    human_path = f"/orgs/{ORGANIZATION}/rulesets/{HUMAN_RULESET_ID}"
    human = require_object(client.request("GET", human_path), label="human ruleset")
    if human.get("id") != HUMAN_RULESET_ID:
        raise PermitInputError("GitHub returned the wrong human ruleset")
    before_human = human_ruleset_state(contract, "before")
    after_human = human_ruleset_state(contract, "after")
    human_state = controlled_ruleset(human)
    if human_state == before_human:
        if require_object(client.request("GET", human_path), label="human ruleset") != human:
            raise PermitInputError("human ruleset changed during removal")
        client.request("PUT", human_path, payload=after_human)
        human = require_object(client.request("GET", human_path), label="human ruleset")
        human_state = controlled_ruleset(human)
    if human_state != after_human:
        raise PermitInputError("human ruleset is neither exact legacy nor exact post-removal state")

    classic = contract["classic_branch_protection"]
    branch_path = (
        f"/repos/{classic['repository']}/branches/{classic['branch']}/protection"
    )
    protection = require_object(
        client.request("GET", branch_path),
        label="classic branch protection",
    )
    normalized = normalize_classic_protection(protection)
    if normalized == classic["before"]:
        refetched = require_object(
            client.request("GET", branch_path),
            label="classic branch protection",
        )
        if refetched != protection:
            raise PermitInputError("classic branch protection changed during removal")
        client.request("DELETE", f"{branch_path}/required_pull_request_reviews")
        protection = require_object(
            client.request("GET", branch_path),
            label="classic branch protection",
        )
        normalized = normalize_classic_protection(protection)
    if normalized != classic["after"]:
        raise PermitInputError(
            "classic branch protection is neither exact legacy nor exact post-removal state",
        )

    return {
        "schema": "mindburn.release-authority-human-gate-removal/v1",
        "machine_ruleset_id": STABLE_RULESET_ID,
        "machine_workflow_sha": candidate_sha,
        "machine_workflow_ref": candidate_ref,
        "human_ruleset_id": HUMAN_RULESET_ID,
        "human_repository_ids": after_human["conditions"]["repository_id"]["repository_ids"],
        "removed_repository_ids": contract["human_approval_ruleset"]["remove_repository_ids"],
        "classic_repository": classic["repository"],
        "classic_branch": classic["branch"],
        "classic_required_pull_request_reviews": None,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        receipt = remove_human_approval_gates(
            args,
            GitHubAdminClient(
                os.environ.get("GH_TOKEN", ""),
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            ),
        )
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError) as exc:
        print(f"remove-human-approval-gates: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
