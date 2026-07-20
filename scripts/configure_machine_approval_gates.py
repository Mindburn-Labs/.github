#!/usr/bin/env python3
"""Install the machine-approval interlock before retiring public CODEOWNER gates."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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
from authority_evidence_ledger import LEDGER_REF, REPOSITORY as LEDGER_REPOSITORY
from authority_ruleset_broker import (
    API_VERSION,
    ORGANIZATION,
    STABLE_RULESET_ID,
    validate_ref,
    validate_ruleset,
)
from submit_machine_approval import (
    APPROVER_APP_ID,
    APPROVER_INSTALLATION_ID,
    APPROVER_LOGIN,
    SCHEMA as APPROVAL_SCHEMA,
)


BOOTSTRAP_SCHEMA = "mindburn.release-authority-bootstrap/v3"
CONFIGURATION_SCHEMA = "mindburn.release-authority-machine-gates/v1"
HUMAN_RULESET_ID = 17911735
HUMAN_RULESET_NAME = "Mindburn default branch approval gate"
MACHINE_RULESET_NAME = "HELM Machine Approval Interlock"
UPDATER_RULESET_NAME = "HELM Exclusive Main Updater"
PROOF_REF_RULESET_NAME = "HELM Immutable Proof Fixtures"
EVIDENCE_HISTORY_RULESET_NAME = "HELM Append-Only Evidence History"
EVIDENCE_UPDATER_RULESET_NAME = "HELM Exclusive Evidence Appender"
AUTHORITY_REPOSITORY_ID = 1159255601
KERNEL_REPOSITORY_ID = 1158479649
LAB_REPOSITORY_ID = 1300498536
CANARY_REPOSITORY_ID = 1301786253
LAB_MAIN_SHA = "e183c28646d3b577b3ce472d98e832e6bc668330"
UPDATE_INTERLOCK_REPOSITORY_IDS = (
    KERNEL_REPOSITORY_ID,
    AUTHORITY_REPOSITORY_ID,
    CANARY_REPOSITORY_ID,
)
KERNEL_QUALITY_RULESET_ID = 16024605
KERNEL_QUALITY_RULESET_NAME = "main protection"
AUTONOMOUS_REPOSITORIES = (
    "Mindburn-Labs/.github",
    "Mindburn-Labs/helm-ai-kernel",
    "Mindburn-Labs/contracts-autonomous-release-canary",
)
ATOMIC_MERGE_SETTINGS = {
    "allow_merge_commit": True,
    "allow_squash_merge": False,
    "allow_rebase_merge": False,
    "delete_branch_on_merge": False,
}
KERNEL_REQUIRED_STATUS_CONTEXTS = (
    "Quality PR profile",
    "hygiene",
    "kernel",
    "python-sdk",
    "ts-sdk",
    "rust-sdk",
    "java-sdk",
    "contract-drift",
    "deployment-smoke",
    "kind-smoke",
    "release-smoke",
    "Coverage and truth",
    "OpenSSF Scorecard",
    "CodeQL (go)",
    "CodeQL (javascript-typescript)",
    "CodeQL (python)",
    "CodeQL (java-kotlin)",
    "Rust audit",
)
PROOF_REFS = {
    "refs/heads/main": LAB_MAIN_SHA,
    "refs/heads/adversarial/git-lfs-content-substitution": (
        "627042be00ec9a2eca210caa671ef7f81ba73d39"
    ),
    "refs/heads/adversarial/oversized-review-context": (
        "28078dde81725b24708699f89bc0e5f72cf3e24b"
    ),
    "refs/heads/adversarial/patch-boundary-and-json-forgery": (
        "b4124d6928f2b6f4c2a10e8e4a16bc5359441214"
    ),
    "refs/heads/adversarial/self-weakened-makefile": (
        "a46e2c66222b5e26b98ea00fb35e5bc43d6f7b7a"
    ),
    "refs/heads/adversarial/source-instruction-overrides-review": (
        "b5096f27833cbc853fe780a70052b5f0686005d5"
    ),
    "refs/heads/adversarial/symlink-read-boundary": (
        "89b3050718bc51ccfbc9f528ddcfe1d099a82bcb"
    ),
    "refs/heads/adversarial/workflow-token-escalation": (
        "0573b2dffb10632f0cb38e1eb465c970b82c4a0a"
    ),
    "refs/heads/canary/authority-generation": (
        "2c080470f81d0aaa3235eddf012e2d6d6b770bd1"
    ),
}


@dataclass(frozen=True)
class AdminResponse:
    body: Any
    etag: str | None


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
        if_match: str | None = None,
    ) -> AdminResponse:
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
        if if_match is not None:
            headers["If-Match"] = if_match
        request = urllib.request.Request(
            self.api_url + path,
            data=content,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
                raw = response.read()
                etag = response.headers.get("ETag")
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            if exc.code == 412:
                raise PermitInputError(
                    f"GitHub rejected stale state for {path}"
                ) from exc
            raise PermitInputError(
                f"GitHub {method} {path} failed with HTTP {exc.code}: {detail}",
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise PermitInputError(f"GitHub {method} {path} failed: {exc}") from exc
        if not raw:
            return AdminResponse(None, etag)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermitInputError(
                f"GitHub {method} {path} returned invalid JSON"
            ) from exc
        return AdminResponse(value, etag)


def require_object(response: AdminResponse, *, label: str) -> dict[str, Any]:
    if not isinstance(response.body, dict):
        raise PermitInputError(f"{label} returned no object")
    return response.body


def load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def load_contract(path: Path) -> dict[str, Any]:
    value = load_json(path, label="bootstrap contract")
    require_exact_keys(
        value,
        required={
            "schema",
            "approver",
            "merger",
            "machine_approval_ruleset",
            "exclusive_updater_ruleset",
            "human_approval_ruleset",
            "classic_branch_protection",
            "repository_settings",
            "kernel_quality_ruleset",
            "proof_ref_ruleset",
            "proof_refs",
            "evidence_ledger",
        },
        label="bootstrap contract",
    )
    if value["schema"] != BOOTSTRAP_SCHEMA:
        raise PermitInputError("unsupported bootstrap contract schema")

    approver = value["approver"]
    if approver != {
        "app_id": APPROVER_APP_ID,
        "installation_id": APPROVER_INSTALLATION_ID,
        "login": APPROVER_LOGIN,
        "slug": "helm-authority-approver",
        "organization": ORGANIZATION,
        "permission": {"pull_requests": "write"},
    }:
        raise PermitInputError("bootstrap contract names the wrong approver")

    merger_app_id = validate_merger(value["merger"])

    machine = value["machine_approval_ruleset"]
    if not isinstance(machine, dict):
        raise PermitInputError("machine approval ruleset contract must be an object")
    if machine != machine_ruleset_payload():
        raise PermitInputError("machine approval ruleset contract is not exact")
    updater = value["exclusive_updater_ruleset"]
    if not isinstance(updater, dict) or updater != updater_ruleset_payload(
        merger_app_id
    ):
        raise PermitInputError("exclusive updater ruleset contract is not exact")

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
            or any(
                not isinstance(item, int) or isinstance(item, bool) or item <= 0
                for item in ids
            )
            or ids != sorted(set(ids))
        ):
            raise PermitInputError(f"bootstrap {label} repository IDs are invalid")
    if human["id"] != HUMAN_RULESET_ID or human["name"] != HUMAN_RULESET_NAME:
        raise PermitInputError("bootstrap contract names the wrong human ruleset")
    if set(remove) != {AUTHORITY_REPOSITORY_ID, KERNEL_REPOSITORY_ID}:
        raise PermitInputError(
            "bootstrap retires the wrong CODEOWNER-gated repositories"
        )
    if set(remove) - set(UPDATE_INTERLOCK_REPOSITORY_IDS):
        raise PermitInputError(
            "bootstrap retirement is outside public machine coverage"
        )
    if after != [
        repository_id for repository_id in before if repository_id not in remove
    ]:
        raise PermitInputError("bootstrap post-retirement repository IDs are not exact")
    if not isinstance(human["rules"], list) or not human["rules"]:
        raise PermitInputError("bootstrap human rules must be a non-empty list")

    classic = value["classic_branch_protection"]
    if not isinstance(classic, dict):
        raise PermitInputError("classic branch protection contract must be an object")
    require_exact_keys(
        classic,
        required={"repository", "branch", "expected"},
        label="classic branch protection contract",
    )
    if classic["repository"] != "Mindburn-Labs/.github" or classic["branch"] != "main":
        raise PermitInputError("bootstrap contract names the wrong protected branch")
    reviews = classic["expected"].get("required_pull_request_reviews")
    if (
        not isinstance(reviews, dict)
        or reviews.get("required_approving_review_count") != 1
    ):
        raise PermitInputError("classic protection must retain one required approval")

    expected_repository_settings = {
        repository: ATOMIC_MERGE_SETTINGS for repository in AUTONOMOUS_REPOSITORIES
    }
    if value["repository_settings"] != expected_repository_settings:
        raise PermitInputError("bootstrap repository settings contract is not exact")
    if value["kernel_quality_ruleset"] != {
        "id": KERNEL_QUALITY_RULESET_ID,
        "name": KERNEL_QUALITY_RULESET_NAME,
        "after": kernel_quality_ruleset_payload(),
    }:
        raise PermitInputError("bootstrap Kernel quality ruleset contract is not exact")
    if value["proof_ref_ruleset"] != proof_ref_ruleset_payload():
        raise PermitInputError("bootstrap proof-ref ruleset contract is not exact")
    if value["proof_refs"] != PROOF_REFS:
        raise PermitInputError("bootstrap proof-ref identities are not exact")
    expected_ledger = {
        "repository": LEDGER_REPOSITORY,
        "ref": LEDGER_REF,
        "history_ruleset": evidence_history_ruleset_payload(),
        "exclusive_updater_ruleset": evidence_updater_ruleset_payload(
            merger_app_id
        ),
    }
    if value["evidence_ledger"] != expected_ledger:
        raise PermitInputError("bootstrap evidence ledger contract is not exact")
    return value


def validate_merger(value: Any) -> int | None:
    if not isinstance(value, dict):
        raise PermitInputError("bootstrap merger App must be an object")
    require_exact_keys(
        value,
        required={
            "enabled",
            "app_id",
            "installation_id",
            "login",
            "slug",
            "organization",
            "permission",
        },
        label="bootstrap merger App",
    )
    expected = {
        "login": "helm-authority-merger[bot]",
        "slug": "helm-authority-merger",
        "organization": ORGANIZATION,
        "permission": {"contents": "write", "pull_requests": "read"},
    }
    if any(
        value.get(key) != expected_value for key, expected_value in expected.items()
    ):
        raise PermitInputError("bootstrap contract names the wrong merger App")
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        raise PermitInputError("bootstrap merger enabled flag must be boolean")
    app_id = value.get("app_id")
    installation_id = value.get("installation_id")
    if not enabled:
        if app_id is not None or installation_id is not None:
            raise PermitInputError("disabled merger App cannot retain authority IDs")
        return None
    for item, label in ((app_id, "app_id"), (installation_id, "installation_id")):
        if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
            raise PermitInputError(f"bootstrap merger {label} must be positive")
    if app_id in {APPROVER_APP_ID, 4296957, 4296928}:
        raise PermitInputError("merger App must be independent from all other roles")
    return app_id


def machine_ruleset_payload() -> dict[str, Any]:
    return {
        "name": MACHINE_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
            "repository_id": {
                "repository_ids": list(UPDATE_INTERLOCK_REPOSITORY_IDS),
            },
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["merge"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_last_push_approval": True,
                    "required_approving_review_count": 1,
                    "required_review_thread_resolution": False,
                    "required_reviewers": [],
                },
            },
        ],
    }


def updater_ruleset_payload(merger_app_id: int | None) -> dict[str, Any]:
    bypass_actors = (
        []
        if merger_app_id is None
        else [
            {
                "actor_id": merger_app_id,
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ]
    )
    return {
        "name": UPDATER_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": bypass_actors,
        "conditions": {
            "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
            "repository_id": {
                "repository_ids": list(UPDATE_INTERLOCK_REPOSITORY_IDS),
            },
        },
        "rules": [
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": False},
            }
        ],
    }


def proof_ref_ruleset_payload() -> dict[str, Any]:
    staged = proof_ref_ruleset_staged_payload()
    return {
        **staged,
        "rules": [{"type": "creation"}, *staged["rules"]],
    }


def proof_ref_ruleset_staged_payload() -> dict[str, Any]:
    return {
        "name": PROOF_REF_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {
                "exclude": [],
                "include": list(PROOF_REFS),
            },
            "repository_id": {"repository_ids": [LAB_REPOSITORY_ID]},
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": False},
            },
        ],
    }


def evidence_history_ruleset_payload() -> dict[str, Any]:
    return {
        "name": EVIDENCE_HISTORY_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": [LEDGER_REF]},
            "repository_id": {"repository_ids": [AUTHORITY_REPOSITORY_ID]},
        },
        "rules": [
            {"type": "creation"},
            {"type": "deletion"},
            {"type": "non_fast_forward"},
        ],
    }


def evidence_updater_ruleset_payload(
    merger_app_id: int | None,
) -> dict[str, Any]:
    bypass_actors = (
        []
        if merger_app_id is None
        else [
            {
                "actor_id": merger_app_id,
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ]
    )
    return {
        "name": EVIDENCE_UPDATER_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": bypass_actors,
        "conditions": {
            "ref_name": {"exclude": [], "include": [LEDGER_REF]},
            "repository_id": {"repository_ids": [AUTHORITY_REPOSITORY_ID]},
        },
        "rules": [
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": False},
            }
        ],
    }


def kernel_status_rule() -> dict[str, Any]:
    return {
        "type": "required_status_checks",
        "parameters": {
            "strict_required_status_checks_policy": True,
            "do_not_enforce_on_create": False,
            "required_status_checks": [
                {"context": context} for context in KERNEL_REQUIRED_STATUS_CONTEXTS
            ],
        },
    }


def kernel_quality_ruleset_payload() -> dict[str, Any]:
    return {
        "name": KERNEL_QUALITY_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": ["refs/heads/main"]},
        },
        "rules": [kernel_status_rule()],
    }


def kernel_quality_ruleset_legacy_payload() -> dict[str, Any]:
    return {
        **kernel_quality_ruleset_payload(),
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews_on_push": True,
                    "required_reviewers": [],
                    "require_code_owner_review": False,
                    "dismissal_restriction": {
                        "enabled": False,
                        "allowed_actors": [],
                    },
                    "require_last_push_approval": False,
                    "required_review_thread_resolution": True,
                    "allowed_merge_methods": ["merge", "squash", "rebase"],
                },
            },
            {"type": "required_linear_history"},
            kernel_status_rule(),
            {"type": "deletion"},
            {"type": "non_fast_forward"},
        ],
    }


def human_ruleset_state(contract: dict[str, Any], state: str) -> dict[str, Any]:
    human = contract["human_approval_ruleset"]
    return {
        "name": human["name"],
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
            "repository_id": {"repository_ids": human[f"{state}_repository_ids"]},
        },
        "rules": human["rules"],
    }


def controlled_ruleset(ruleset: dict[str, Any]) -> dict[str, Any]:
    return {
        key: ruleset.get(key)
        for key in (
            "name",
            "target",
            "enforcement",
            "bypass_actors",
            "conditions",
            "rules",
        )
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
            raise PermitInputError(
                "classic required pull request reviews are malformed"
            )
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
        "required_linear_history": boolean_setting(
            protection, "required_linear_history"
        ),
        "required_pull_request_reviews": reviews,
        "required_signatures": boolean_setting(protection, "required_signatures"),
        "required_status_checks": protection.get("required_status_checks"),
        "restrictions": protection.get("restrictions"),
    }


def ensure_classic_protection_without_comment_gate(
    client: GitHubAdminClient,
    *,
    path: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    response = client.request("GET", path)
    protection = require_object(response, label="classic branch protection")
    state = normalize_classic_protection(protection)
    legacy = {**expected, "required_conversation_resolution": True}
    if state == legacy:
        if not response.etag:
            raise PermitInputError("classic branch protection GET returned no ETag")
        refetched = client.request("GET", path)
        if refetched.body != protection or refetched.etag != response.etag:
            raise PermitInputError("classic branch protection changed before migration")
        client.request(
            "DELETE",
            f"{path}/required_conversation_resolution",
            if_match=response.etag,
        )
        protection = require_object(
            client.request("GET", path),
            label="confirmed classic branch protection",
        )
        state = normalize_classic_protection(protection)
    if state != expected:
        raise PermitInputError(
            "classic branch protection did not retain its machine approval interlock"
        )
    return protection


def validate_approval(
    path: Path,
    *,
    candidate_sha: str,
    pull_request: int,
) -> dict[str, Any]:
    approval = load_json(path, label="machine approval receipt")
    require_exact_keys(
        approval,
        required={
            "schema",
            "repository",
            "pull_request",
            "head_sha",
            "workflow_sha",
            "permit_id",
            "base_sha",
            "merge_sha",
            "merge_tree_sha",
            "review_id",
            "review_state",
            "approver_login",
            "approver_app_id",
            "approver_installation_id",
        },
        label="machine approval receipt",
    )
    if (
        approval.get("schema") != APPROVAL_SCHEMA
        or approval.get("repository") != "Mindburn-Labs/.github"
        or approval.get("pull_request") != pull_request
        or approval.get("head_sha") != candidate_sha
        or approval.get("review_state") != "APPROVED"
        or approval.get("approver_login") != APPROVER_LOGIN
        or approval.get("approver_app_id") != APPROVER_APP_ID
        or approval.get("approver_installation_id") != APPROVER_INSTALLATION_ID
        or not isinstance(approval.get("review_id"), int)
    ):
        raise PermitInputError("machine approval receipt is not exact")
    for field in ("base_sha", "merge_sha", "merge_tree_sha", "workflow_sha"):
        require_sha(
            approval[field],
            label=f"machine approval {field}",
            length=40,
        )
    permit_id = approval["permit_id"]
    if not isinstance(permit_id, str) or not permit_id.startswith("sha256:"):
        raise PermitInputError("machine approval permit_id is not exact")
    require_sha(
        permit_id.removeprefix("sha256:"),
        label="machine approval permit_id",
        length=64,
    )
    return approval


def verify_live_approval(
    client: GitHubAdminClient,
    approval: dict[str, Any],
    *,
    approved_head_sha: str,
    allow_merged_resume: bool,
) -> None:
    pull_request = approval["pull_request"]
    review_id = approval["review_id"]
    review = require_object(
        client.request(
            "GET",
            f"/repos/Mindburn-Labs/.github/pulls/{pull_request}/reviews/{review_id}",
        ),
        label="live machine approval",
    )
    user = review.get("user")
    if (
        review.get("state") != "APPROVED"
        or review.get("commit_id") != approved_head_sha
        or review.get("body") != f"HELM signed ALLOW permit {approval['permit_id']}"
        or not isinstance(user, dict)
        or user.get("login") != APPROVER_LOGIN
    ):
        raise PermitInputError("live machine approval is not exact and active")
    current = require_object(
        client.request("GET", f"/repos/Mindburn-Labs/.github/pulls/{pull_request}"),
        label="live approval pull request",
    )
    base = current.get("base")
    head = current.get("head")
    common_mismatch = (
        current.get("draft") is True
        or not isinstance(base, dict)
        or base.get("ref") != "main"
        or base.get("sha") != approval["base_sha"]
        or not isinstance(head, dict)
        or head.get("sha") != approved_head_sha
        or not isinstance(head.get("repo"), dict)
        or head["repo"].get("full_name") != "Mindburn-Labs/.github"
    )
    if common_mismatch:
        raise PermitInputError("approved pull request changed before gate cutover")
    if current.get("merged") is not True:
        if current.get("state") != "open":
            raise PermitInputError("approved pull request changed before gate cutover")
        return
    if (
        not allow_merged_resume
        or current.get("state") != "closed"
        or current.get("merge_commit_sha") != approval["merge_sha"]
    ):
        raise PermitInputError("approved pull request is not resumably merged")
    merge_commit = require_object(
        client.request(
            "GET",
            f"/repos/Mindburn-Labs/.github/git/commits/{approval['merge_sha']}",
        ),
        label="merged approval commit",
    )
    parents = merge_commit.get("parents")
    tree = merge_commit.get("tree")
    if (
        not isinstance(parents, list)
        or [parent.get("sha") for parent in parents if isinstance(parent, dict)]
        != [approval["base_sha"], approved_head_sha]
        or not isinstance(tree, dict)
        or tree.get("sha") != approval["merge_tree_sha"]
    ):
        raise PermitInputError("merged approval graph drifted from the permit")


def ensure_machine_ruleset(
    client: GitHubAdminClient,
) -> dict[str, Any]:
    expected = machine_ruleset_payload()
    response = client.request("GET", f"/orgs/{ORGANIZATION}/rulesets?per_page=100")
    if not isinstance(response.body, list):
        raise PermitInputError("GitHub ruleset list is malformed")
    matches = [
        item
        for item in response.body
        if isinstance(item, dict) and item.get("name") == MACHINE_RULESET_NAME
    ]
    if len(matches) > 1:
        raise PermitInputError("multiple machine approval rulesets exist")
    if not matches:
        created = require_object(
            client.request(
                "POST",
                f"/orgs/{ORGANIZATION}/rulesets",
                payload=expected,
            ),
            label="created machine approval ruleset",
        )
        ruleset_id = created.get("id")
    else:
        ruleset_id = matches[0].get("id")
    if not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise PermitInputError("machine approval ruleset ID is invalid")
    current = require_object(
        client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}"),
        label="machine approval ruleset",
    )
    if controlled_ruleset(current) != expected:
        raise PermitInputError("machine approval ruleset is not exact and active")
    return current


def ensure_named_organization_ruleset(
    client: GitHubAdminClient,
    *,
    name: str,
    expected: dict[str, Any],
    create: bool = True,
) -> dict[str, Any]:
    response = client.request("GET", f"/orgs/{ORGANIZATION}/rulesets?per_page=100")
    if not isinstance(response.body, list):
        raise PermitInputError("GitHub ruleset list is malformed")
    matches = [
        item
        for item in response.body
        if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) > 1:
        raise PermitInputError(f"multiple organization rulesets named {name} exist")
    if not matches:
        if not create:
            raise PermitInputError(f"required organization ruleset {name} is absent")
        created = require_object(
            client.request(
                "POST",
                f"/orgs/{ORGANIZATION}/rulesets",
                payload=expected,
            ),
            label=f"created {name} ruleset",
        )
        ruleset_id = created.get("id")
    else:
        ruleset_id = matches[0].get("id")
    if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool) or ruleset_id <= 0:
        raise PermitInputError(f"{name} ruleset ID is invalid")
    current = require_object(
        client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}"),
        label=f"{name} ruleset",
    )
    if controlled_ruleset(current) != expected:
        raise PermitInputError(f"{name} ruleset is not exact and active")
    return current


def ensure_evidence_ledger_rulesets(
    client: GitHubAdminClient,
    *,
    merger_app_id: int,
    expected_head_sha: str,
    allow_advanced: bool,
) -> dict[str, Any]:
    expected_head_sha = require_sha(
        expected_head_sha,
        label="evidence ledger bootstrap head SHA",
        length=40,
    )
    ref_path = LEDGER_REF.removeprefix("refs/")

    def observed_head() -> str:
        ref = require_object(
            client.request("GET", f"/repos/{LEDGER_REPOSITORY}/git/ref/{ref_path}"),
            label="evidence ledger ref",
        )
        if ref.get("ref") != LEDGER_REF or not isinstance(ref.get("object"), dict):
            raise PermitInputError("evidence ledger ref identity drifted")
        return require_sha(
            ref["object"].get("sha"), label="evidence ledger head SHA", length=40
        )

    initial_head_sha = observed_head()
    advanced = initial_head_sha != expected_head_sha
    if advanced and not allow_advanced:
        raise PermitInputError("evidence ledger moved before its authority lock")
    updater = ensure_named_organization_ruleset(
        client,
        name=EVIDENCE_UPDATER_RULESET_NAME,
        expected=evidence_updater_ruleset_payload(merger_app_id),
        create=not advanced,
    )
    if observed_head() != initial_head_sha:
        raise PermitInputError("evidence ledger moved while installing updater lock")
    history = ensure_named_organization_ruleset(
        client,
        name=EVIDENCE_HISTORY_RULESET_NAME,
        expected=evidence_history_ruleset_payload(),
        create=not advanced,
    )
    if observed_head() != initial_head_sha:
        raise PermitInputError("evidence ledger moved while installing history lock")
    return {
        "ref": LEDGER_REF,
        "head_sha": initial_head_sha,
        "history_ruleset_id": history["id"],
        "exclusive_updater_ruleset_id": updater["id"],
    }


def ensure_updater_ruleset(
    client: GitHubAdminClient,
    *,
    merger_app_id: int,
) -> dict[str, Any]:
    expected = updater_ruleset_payload(merger_app_id)
    response = client.request("GET", f"/orgs/{ORGANIZATION}/rulesets?per_page=100")
    if not isinstance(response.body, list):
        raise PermitInputError("GitHub ruleset list is malformed")
    matches = [
        item
        for item in response.body
        if isinstance(item, dict) and item.get("name") == UPDATER_RULESET_NAME
    ]
    if len(matches) > 1:
        raise PermitInputError("multiple exclusive updater rulesets exist")
    if not matches:
        created = require_object(
            client.request(
                "POST",
                f"/orgs/{ORGANIZATION}/rulesets",
                payload=expected,
            ),
            label="created exclusive updater ruleset",
        )
        ruleset_id = created.get("id")
    else:
        ruleset_id = matches[0].get("id")
    if not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise PermitInputError("exclusive updater ruleset ID is invalid")
    current = require_object(
        client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}"),
        label="exclusive updater ruleset",
    )
    if controlled_ruleset(current) != expected:
        raise PermitInputError("exclusive updater ruleset is not exact and active")
    return current


def ensure_proof_ref_ruleset(client: GitHubAdminClient) -> dict[str, Any]:
    repository = "Mindburn-Labs/contracts-autonomous-release-lab"
    def verify_refs() -> None:
        for ref, expected_sha in PROOF_REFS.items():
            branch = ref.removeprefix("refs/heads/")
            live = require_object(
                client.request("GET", f"/repos/{repository}/git/ref/heads/{branch}"),
                label=f"proof fixture {ref}",
            )
            object_value = live.get("object")
            if (
                live.get("ref") != ref
                or not isinstance(object_value, dict)
                or object_value.get("sha") != expected_sha
            ):
                raise PermitInputError(f"proof fixture {ref} drifted before lock")

    verify_refs()
    expected = proof_ref_ruleset_payload()
    staged = proof_ref_ruleset_staged_payload()
    response = client.request("GET", f"/orgs/{ORGANIZATION}/rulesets?per_page=100")
    if not isinstance(response.body, list):
        raise PermitInputError("GitHub ruleset list is malformed")
    matches = [
        item
        for item in response.body
        if isinstance(item, dict) and item.get("name") == PROOF_REF_RULESET_NAME
    ]
    if len(matches) > 1:
        raise PermitInputError("multiple immutable proof-ref rulesets exist")
    if not matches:
        created = require_object(
            client.request(
                "POST",
                f"/orgs/{ORGANIZATION}/rulesets",
                payload=staged,
            ),
            label="created staged immutable proof-ref ruleset",
        )
        ruleset_id = created.get("id")
    else:
        ruleset_id = matches[0].get("id")
    if not isinstance(ruleset_id, int) or ruleset_id <= 0:
        raise PermitInputError("immutable proof-ref ruleset ID is invalid")
    path = f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}"
    current_response = client.request("GET", path)
    current = require_object(current_response, label="immutable proof-ref ruleset")
    state = controlled_ruleset(current)
    if state == expected:
        verify_refs()
        return current
    if state != staged:
        raise PermitInputError("immutable proof-ref ruleset is outside staged/final states")
    verify_refs()
    if not current_response.etag:
        raise PermitInputError("staged immutable proof-ref ruleset GET returned no ETag")
    refetched = client.request("GET", path)
    if refetched.body != current or refetched.etag != current_response.etag:
        raise PermitInputError("immutable proof-ref ruleset changed before final lock")
    client.request(
        "PUT",
        path,
        payload=expected,
        if_match=current_response.etag,
    )
    current = require_object(
        client.request("GET", path),
        label="final immutable proof-ref ruleset",
    )
    if controlled_ruleset(current) != expected:
        raise PermitInputError("immutable proof-ref ruleset is not exact and active")
    verify_refs()
    return current


def ensure_atomic_merge_repository_settings(
    client: GitHubAdminClient,
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for repository in AUTONOMOUS_REPOSITORIES:
        path = f"/repos/{repository}"
        before = require_object(
            client.request("GET", path),
            label=f"{repository} repository settings",
        )
        before_settings = {key: before.get(key) for key in ATOMIC_MERGE_SETTINGS}
        if before_settings != ATOMIC_MERGE_SETTINGS:
            updated = require_object(
                client.request("PATCH", path, payload=ATOMIC_MERGE_SETTINGS),
                label=f"updated {repository} repository settings",
            )
            if {
                key: updated.get(key) for key in ATOMIC_MERGE_SETTINGS
            } != ATOMIC_MERGE_SETTINGS:
                raise PermitInputError(
                    f"{repository} did not accept exact atomic merge settings"
                )
        after = require_object(
            client.request("GET", path),
            label=f"confirmed {repository} repository settings",
        )
        after_settings = {key: after.get(key) for key in ATOMIC_MERGE_SETTINGS}
        if after_settings != ATOMIC_MERGE_SETTINGS:
            raise PermitInputError(
                f"{repository} repository settings drifted after update"
            )
        receipts.append(
            {
                "repository": repository,
                "before": before_settings,
                "after": after_settings,
            }
        )
    return receipts


def ensure_kernel_quality_ruleset(client: GitHubAdminClient) -> dict[str, Any]:
    path = f"/repos/Mindburn-Labs/helm-ai-kernel/rulesets/{KERNEL_QUALITY_RULESET_ID}"
    current_response = client.request("GET", path)
    current = require_object(current_response, label="Kernel quality ruleset")
    if (
        current.get("id") != KERNEL_QUALITY_RULESET_ID
        or current.get("name") != KERNEL_QUALITY_RULESET_NAME
    ):
        raise PermitInputError("GitHub returned the wrong Kernel quality ruleset")
    state = controlled_ruleset(current)
    legacy = kernel_quality_ruleset_legacy_payload()
    expected = kernel_quality_ruleset_payload()
    if state == legacy:
        if not current_response.etag:
            raise PermitInputError("Kernel quality ruleset GET returned no ETag")
        refetched = client.request("GET", path)
        if refetched.body != current or refetched.etag != current_response.etag:
            raise PermitInputError("Kernel quality ruleset changed before migration")
        client.request(
            "PUT",
            path,
            payload=expected,
            if_match=current_response.etag,
        )
        current = require_object(
            client.request("GET", path),
            label="confirmed Kernel quality ruleset",
        )
        state = controlled_ruleset(current)
    if state != expected:
        raise PermitInputError("Kernel quality ruleset is outside resumable states")
    return current


def configure_machine_approval_gates(
    args: argparse.Namespace,
    client: GitHubAdminClient,
) -> dict[str, Any]:
    candidate_sha = require_sha(args.candidate_sha, label="candidate_sha", length=40)
    candidate_ref = validate_ref(args.candidate_ref, label="candidate_ref")
    approved_head_sha = require_sha(
        getattr(args, "approved_head_sha", None) or candidate_sha,
        label="approved_head_sha",
        length=40,
    )
    contract = load_contract(args.contract)
    merger_app_id = validate_merger(contract["merger"])
    if merger_app_id is None:
        raise PermitInputError(
            "merger App is disabled; machine-gate cutover remains fail-closed"
        )
    approval = validate_approval(
        args.approval_receipt,
        candidate_sha=approved_head_sha,
        pull_request=args.pull_request,
    )
    verify_live_approval(
        client,
        approval,
        approved_head_sha=approved_head_sha,
        allow_merged_resume=bool(getattr(args, "allow_merged_resume", False)),
    )

    stable = require_object(
        client.request("GET", f"/orgs/{ORGANIZATION}/rulesets/{STABLE_RULESET_ID}"),
        label="stable machine workflow ruleset",
    )
    validate_ruleset(
        stable,
        kind="stable",
        expected_sha=candidate_sha,
        expected_ref=candidate_ref,
    )

    evidence_ledger = ensure_evidence_ledger_rulesets(
        client,
        merger_app_id=merger_app_id,
        expected_head_sha=approved_head_sha,
        allow_advanced=bool(getattr(args, "allow_merged_resume", False)),
    )
    proof_refs = ensure_proof_ref_ruleset(client)
    machine = ensure_machine_ruleset(client)
    machine_id = machine["id"]
    updater = ensure_updater_ruleset(client, merger_app_id=merger_app_id)
    updater_id = updater["id"]
    repository_settings = ensure_atomic_merge_repository_settings(client)
    kernel_quality = ensure_kernel_quality_ruleset(client)

    classic = contract["classic_branch_protection"]
    branch_path = (
        f"/repos/{classic['repository']}/branches/{classic['branch']}/protection"
    )
    ensure_classic_protection_without_comment_gate(
        client,
        path=branch_path,
        expected=classic["expected"],
    )

    human_path = f"/orgs/{ORGANIZATION}/rulesets/{HUMAN_RULESET_ID}"
    human_response = client.request("GET", human_path)
    human = require_object(human_response, label="human CODEOWNER ruleset")
    if human.get("id") != HUMAN_RULESET_ID:
        raise PermitInputError("GitHub returned the wrong human ruleset")
    before_human = human_ruleset_state(contract, "before")
    after_human = human_ruleset_state(contract, "after")
    human_state = controlled_ruleset(human)
    if human_state == before_human:
        if not human_response.etag:
            raise PermitInputError("human ruleset GET did not return an ETag")
        refetched = client.request("GET", human_path)
        if refetched.body != human or refetched.etag != human_response.etag:
            raise PermitInputError("human ruleset changed before machine-gate cutover")
        client.request(
            "PUT",
            human_path,
            payload=after_human,
            if_match=human_response.etag,
        )
        human = require_object(client.request("GET", human_path), label="human ruleset")
        human_state = controlled_ruleset(human)
    if human_state != after_human:
        raise PermitInputError("human ruleset is outside the exact before/after states")

    # Merge-method and ruleset mutations can cause GitHub to recompute an open
    # pull request's merge candidate. Rebind the approval to the exact graph
    # after every cutover mutation before emitting an authority receipt.
    verify_live_approval(
        client,
        approval,
        approved_head_sha=approved_head_sha,
        allow_merged_resume=bool(getattr(args, "allow_merged_resume", False)),
    )

    return {
        "schema": CONFIGURATION_SCHEMA,
        "machine_workflow_ruleset_id": STABLE_RULESET_ID,
        "machine_workflow_sha": candidate_sha,
        "machine_workflow_ref": candidate_ref,
        "machine_approval_ruleset_id": machine_id,
        "proof_ref_ruleset_id": proof_refs["id"],
        "evidence_ledger": evidence_ledger,
        "exclusive_updater_ruleset_id": updater_id,
        "exclusive_updater_app_id": merger_app_id,
        "repository_settings": repository_settings,
        "kernel_quality_ruleset_id": kernel_quality["id"],
        "machine_approval_review_id": approval["review_id"],
        "machine_approval_head_sha": approved_head_sha,
        "approver_login": APPROVER_LOGIN,
        "human_codeowner_ruleset_id": HUMAN_RULESET_ID,
        "human_codeowner_repository_ids": after_human["conditions"]["repository_id"][
            "repository_ids"
        ],
        "retired_codeowner_repository_ids": contract["human_approval_ruleset"][
            "remove_repository_ids"
        ],
        "classic_repository": classic["repository"],
        "classic_branch": classic["branch"],
        "classic_required_approving_review_count": 1,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--candidate-ref", required=True)
    parser.add_argument("--approved-head-sha")
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--approval-receipt", type=Path, required=True)
    parser.add_argument("--allow-merged-resume", action="store_true")
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        receipt = configure_machine_approval_gates(
            args,
            GitHubAdminClient(
                os.environ.get("GH_TOKEN", ""),
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            ),
        )
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"configure-machine-approval-gates: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
