#!/usr/bin/env python3
"""Verify source-owned HELM release environments and permanent proof lanes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any
from urllib.parse import quote

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from wait_for_authority_canary import GitHubReadClient


CONTROL_SCHEMA = "mindburn.release-control-plane/v2"
AUTHORITY_REPOSITORY = "Mindburn-Labs/.github"
AUTHORITY_REPOSITORY_ID = 1159255601
LAB_REPOSITORY = "Mindburn-Labs/contracts-autonomous-release-lab"
LAB_BASE_SHA = "e183c28646d3b577b3ce472d98e832e6bc668330"
ENVIRONMENT_NAMES = {
    "authority-observer",
    "authority-approval",
    "authority-merge",
    "authority-promotion",
    "authority-control",
}
CONTROL_BRANCH = "authority/control-v1"
CONTROL_REF = f"refs/heads/{CONTROL_BRANCH}"
CONTROL_WORKFLOW_PATH = ".github/workflows/promote-authority.yml"
CONTROL_RULESET_NAME = "HELM Immutable Authority Controller"
CONTROL_SUCCESSOR_RULESET_NAME = "HELM Authority Control Successor"
ADVERSARIAL_SCHEMA = "mindburn.release-permit-adversarial/v1"
EXPECTED_RESULTS = {"ALLOW", "DENY", "PRE_MODEL_REJECT"}
CASE_HEAD_REFS = {
    "source-instruction-overrides-review": "adversarial/source-instruction-overrides-review",
    "workflow-token-escalation": "adversarial/workflow-token-escalation",
    "symlink-read-boundary": "adversarial/symlink-read-boundary",
    "patch-boundary-and-json-forgery": "adversarial/patch-boundary-and-json-forgery",
    "self-weakened-makefile": "adversarial/self-weakened-makefile",
    "git-lfs-content-substitution": "adversarial/git-lfs-content-substitution",
    "oversized-review-context": "adversarial/oversized-review-context",
    "inert-authority-allow-canary": "canary/authority-generation",
}


def load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def validate_environment(value: Any, *, index: int) -> dict[str, Any]:
    label = f"control environments[{index}]"
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    require_exact_keys(
        value,
        required={
            "name",
            "protection_rule_types",
            "deployment_branch_policy",
            "branch_policies",
            "can_admins_bypass",
        },
        label=label,
    )
    if value["name"] not in ENVIRONMENT_NAMES:
        raise PermitInputError(f"{label} has an unexpected name")
    if value["protection_rule_types"] != ["branch_policy"]:
        raise PermitInputError(
            f"{label} must have no reviewers, wait timer, or custom gate"
        )
    if value["deployment_branch_policy"] != {
        "protected_branches": False,
        "custom_branch_policies": True,
    }:
        raise PermitInputError(f"{label} must use exact custom branch policies")
    if value["branch_policies"] != [{"name": CONTROL_BRANCH, "type": "branch"}]:
        raise PermitInputError(f"{label} must admit only the immutable control ref")
    if value["can_admins_bypass"] is not False:
        raise PermitInputError(f"{label} cannot allow administrator bypass")
    return value


def expected_control_ruleset() -> dict[str, Any]:
    return {
        "name": CONTROL_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"exclude": [], "include": [CONTROL_REF]},
            "repository_id": {"repository_ids": [AUTHORITY_REPOSITORY_ID]},
        },
        "rules": [
            {"type": "creation"},
            {"type": "deletion"},
            {"type": "non_fast_forward"},
        ],
    }


def expected_control_successor_ruleset(
    successor_app_id: int | None = None,
) -> dict[str, Any]:
    bypass_actors = (
        []
        if successor_app_id is None
        else [
            {
                "actor_id": successor_app_id,
                "actor_type": "Integration",
                "bypass_mode": "always",
            }
        ]
    )
    return {
        "name": CONTROL_SUCCESSOR_RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": bypass_actors,
        "conditions": {
            "ref_name": {"exclude": [], "include": [CONTROL_REF]},
            "repository_id": {"repository_ids": [AUTHORITY_REPOSITORY_ID]},
        },
        "rules": [
            {
                "type": "update",
                "parameters": {"update_allows_fetch_and_merge": False},
            },
        ],
    }


def validate_control_workflow(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermitInputError("control_workflow must be an object")
    require_exact_keys(
        value,
        required={
            "branch",
            "ref",
            "workflow_path",
            "ruleset",
            "successor_ruleset",
            "successor_app",
        },
        label="control_workflow",
    )
    if value["branch"] != CONTROL_BRANCH or value["ref"] != CONTROL_REF:
        raise PermitInputError("control_workflow names the wrong immutable ref")
    if value["workflow_path"] != CONTROL_WORKFLOW_PATH:
        raise PermitInputError("control_workflow names the wrong workflow")
    successor = value["successor_app"]
    if not isinstance(successor, dict):
        raise PermitInputError("control_workflow successor_app must be an object")
    require_exact_keys(
        successor,
        required={"slug", "app_id", "installation_id"},
        label="control_workflow successor_app",
    )
    if successor["slug"] != "helm-authority-control-updater":
        raise PermitInputError("control successor App slug is not source-owned")
    app_id = successor["app_id"]
    installation_id = successor["installation_id"]
    if (app_id is None) != (installation_id is None):
        raise PermitInputError("control successor App identity is incomplete")
    for field, configured in (
        ("app_id", app_id),
        ("installation_id", installation_id),
    ):
        if configured is not None and (
            not isinstance(configured, int)
            or isinstance(configured, bool)
            or configured <= 0
        ):
            raise PermitInputError(
                f"control successor App {field} must be null or positive"
            )
    if value["ruleset"] != expected_control_ruleset():
        raise PermitInputError("control history ruleset is not exact")
    if value["successor_ruleset"] != expected_control_successor_ruleset(app_id):
        raise PermitInputError("control successor ruleset is not exact")
    return value


def validate_case(value: Any, *, index: int) -> dict[str, Any]:
    label = f"control adversarial_suite cases[{index}]"
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    require_exact_keys(
        value,
        required={
            "id",
            "pull_request",
            "base_sha",
            "head_ref",
            "head_sha",
            "expected",
        },
        label=label,
    )
    if not isinstance(value["id"], str) or not value["id"] or len(value["id"]) > 120:
        raise PermitInputError(f"{label} id is invalid")
    if (
        not isinstance(value["pull_request"], int)
        or isinstance(value["pull_request"], bool)
        or value["pull_request"] <= 0
    ):
        raise PermitInputError(f"{label} pull_request must be positive")
    require_sha(value["head_sha"], label=f"{label} head_sha", length=40)
    if value["base_sha"] != LAB_BASE_SHA:
        raise PermitInputError(f"{label} must bind the immutable lab base")
    if value["head_ref"] != CASE_HEAD_REFS.get(value["id"]):
        raise PermitInputError(f"{label} head_ref is not the exact fixture ref")
    if value["expected"] not in EXPECTED_RESULTS:
        raise PermitInputError(f"{label} expected result is invalid")
    return value


def validate_contract(
    contract: dict[str, Any],
    adversarial: dict[str, Any],
) -> dict[str, Any]:
    require_exact_keys(
        contract,
        required={
            "schema",
            "repository",
            "repository_settings",
            "control_workflow",
            "environments",
            "adversarial_suite",
        },
        label="control contract",
    )
    if contract["schema"] != CONTROL_SCHEMA:
        raise PermitInputError("unsupported control-plane contract schema")
    if contract["repository"] != AUTHORITY_REPOSITORY:
        raise PermitInputError("control contract names the wrong authority repository")
    settings = contract["repository_settings"]
    if not isinstance(settings, dict):
        raise PermitInputError("control repository_settings must be an object")
    require_exact_keys(
        settings,
        required={"delete_branch_on_merge"},
        label="control repository_settings",
    )
    if settings["delete_branch_on_merge"] is not False:
        raise PermitInputError(
            "authority head refs must survive incomplete post-merge promotion"
        )

    validate_control_workflow(contract["control_workflow"])

    environments = contract["environments"]
    if not isinstance(environments, list) or len(environments) != len(ENVIRONMENT_NAMES):
        raise PermitInputError("control contract must contain the exact authority environments")
    validated_environments = [
        validate_environment(environment, index=index)
        for index, environment in enumerate(environments)
    ]
    if {
        environment["name"] for environment in validated_environments
    } != ENVIRONMENT_NAMES:
        raise PermitInputError("control contract environment identities are not exact")

    suite = contract["adversarial_suite"]
    if not isinstance(suite, dict):
        raise PermitInputError("control adversarial_suite must be an object")
    require_exact_keys(
        suite,
        required={"repository", "cases"},
        label="control adversarial_suite",
    )
    if suite["repository"] != LAB_REPOSITORY:
        raise PermitInputError("control suite names the wrong lab repository")
    cases = suite["cases"]
    if not isinstance(cases, list) or len(cases) != 8:
        raise PermitInputError(
            "control suite must contain seven attacks and one ALLOW canary"
        )
    validated_cases = [
        validate_case(case, index=index) for index, case in enumerate(cases)
    ]
    if {case["pull_request"] for case in validated_cases} != set(range(1, 9)):
        raise PermitInputError(
            "control suite pull requests must be exactly 1 through 8"
        )
    if {case["head_ref"] for case in validated_cases} != set(CASE_HEAD_REFS.values()):
        raise PermitInputError("control suite fixture refs are not exact and unique")
    if sum(case["expected"] == "ALLOW" for case in validated_cases) != 1:
        raise PermitInputError("control suite must contain exactly one ALLOW canary")

    require_exact_keys(
        adversarial,
        required={"schema", "cases"},
        label="adversarial corpus",
    )
    if adversarial["schema"] != ADVERSARIAL_SCHEMA:
        raise PermitInputError("unsupported adversarial corpus schema")
    corpus_cases = adversarial["cases"]
    if not isinstance(corpus_cases, list) or len(corpus_cases) != 7:
        raise PermitInputError("adversarial corpus must contain exactly seven cases")
    expected_by_id: dict[str, str] = {}
    for index, case in enumerate(corpus_cases):
        if not isinstance(case, dict):
            raise PermitInputError(f"adversarial corpus case {index} must be an object")
        require_exact_keys(
            case,
            required={"id", "objective", "expected"},
            label=f"adversarial corpus case {index}",
        )
        expected_by_id[case["id"]] = case["expected"]
    suite_by_id = {
        case["id"]: case["expected"]
        for case in validated_cases
        if case["expected"] != "ALLOW"
    }
    if suite_by_id != expected_by_id:
        raise PermitInputError(
            "control suite does not exactly cover the adversarial corpus"
        )
    return contract


def verify_live_repository_settings(
    contract: dict[str, Any],
    client: GitHubReadClient,
) -> dict[str, Any]:
    repository = client.get_json(f"/repos/{AUTHORITY_REPOSITORY}")
    actual = {
        "delete_branch_on_merge": repository.get("delete_branch_on_merge"),
    }
    if actual != contract["repository_settings"]:
        raise PermitInputError(
            "authority repository settings drifted from the recovery contract"
        )
    return actual


def verify_live_environments(
    contract: dict[str, Any],
    client: GitHubReadClient,
    *,
    deployment_disabled: bool = False,
    deployment_transition: bool = False,
) -> list[dict[str, Any]]:
    if deployment_disabled and deployment_transition:
        raise PermitInputError("environment verification mode is ambiguous")
    receipts: list[dict[str, Any]] = []
    for expected in contract["environments"]:
        name = expected["name"]
        environment = client.get_json(
            f"/repos/{AUTHORITY_REPOSITORY}/environments/{name}",
        )
        rule_types = sorted(
            rule.get("type")
            for rule in environment.get("protection_rules", [])
            if isinstance(rule, dict) and isinstance(rule.get("type"), str)
        )
        if rule_types != expected["protection_rule_types"]:
            raise PermitInputError(f"environment {name} protection rules drifted")
        if environment.get("can_admins_bypass") is not expected["can_admins_bypass"]:
            raise PermitInputError(f"environment {name} admin bypass drifted")
        if (
            environment.get("deployment_branch_policy")
            != expected["deployment_branch_policy"]
        ):
            raise PermitInputError(f"environment {name} deployment policy drifted")
        policies = client.get_json(
            f"/repos/{AUTHORITY_REPOSITORY}/environments/{name}/deployment-branch-policies",
        )
        actual_policies = sorted(
            (
                {"name": policy.get("name"), "type": policy.get("type")}
                for policy in policies.get("branch_policies", [])
                if isinstance(policy, dict)
            ),
            key=lambda policy: (str(policy["type"]), str(policy["name"])),
        )
        final_policies = expected["branch_policies"]
        expected_policies = [] if deployment_disabled else final_policies
        allowed_policies = (
            ([], final_policies) if deployment_transition else (expected_policies,)
        )
        if policies.get("total_count") != len(actual_policies):
            raise PermitInputError(f"environment {name} branch-policy count drifted")
        if actual_policies not in allowed_policies:
            raise PermitInputError(f"environment {name} branch policies drifted")
        receipts.append(
            {
                "name": name,
                "can_admins_bypass": environment["can_admins_bypass"],
                "protection_rule_types": rule_types,
                "deployment_branch_policy": environment["deployment_branch_policy"],
                "branch_policies": actual_policies,
            },
        )
    return receipts


def verify_live_control_ruleset(
    contract: dict[str, Any],
    client: GitHubReadClient,
) -> dict[str, Any]:
    expected = contract["control_workflow"]
    try:
        listed_rulesets = json.loads(
            client.get_bytes(
                "/orgs/Mindburn-Labs/rulesets?per_page=100",
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PermitInputError("control-ruleset list is invalid JSON") from exc
    if not isinstance(listed_rulesets, list):
        raise PermitInputError("control-ruleset list must be an array")
    receipts: dict[str, Any] = {}
    for key, name, expected_ruleset in (
        ("history", CONTROL_RULESET_NAME, expected["ruleset"]),
        (
            "successor",
            CONTROL_SUCCESSOR_RULESET_NAME,
            expected["successor_ruleset"],
        ),
    ):
        matches = [
            item
            for item in listed_rulesets
            if isinstance(item, dict) and item.get("name") == name
        ]
        if len(matches) != 1:
            raise PermitInputError(f"exactly one named {key} control ruleset is required")
        ruleset_id = matches[0].get("id")
        if not isinstance(ruleset_id, int) or ruleset_id <= 0:
            raise PermitInputError(f"{key} control ruleset ID is invalid")
        ruleset = client.get_json(f"/orgs/Mindburn-Labs/rulesets/{ruleset_id}")
        controlled = {
            field: ruleset.get(field)
            for field in (
                "name",
                "target",
                "enforcement",
                "bypass_actors",
                "conditions",
                "rules",
            )
        }
        if controlled != expected_ruleset:
            raise PermitInputError(
                f"{key} control ruleset identity or policy drifted"
            )
        receipts[key] = {"id": ruleset_id, **controlled}
    return receipts


def verify_live_control_workflow(
    contract: dict[str, Any],
    client: GitHubReadClient,
    *,
    expected_sha: str | None = None,
    effective_only: bool = False,
) -> dict[str, Any]:
    expected = contract["control_workflow"]
    ruleset_receipt = (
        {} if effective_only else verify_live_control_ruleset(contract, client)
    )

    ref = client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/git/ref/heads/{CONTROL_BRANCH}",
    )
    try:
        control_sha = ref["object"]["sha"]
    except (KeyError, TypeError) as exc:
        raise PermitInputError("control workflow ref response is malformed") from exc
    require_sha(control_sha, label="control workflow SHA", length=40)
    if expected_sha is not None and control_sha != require_sha(
        expected_sha,
        label="expected control workflow SHA",
        length=40,
    ):
        raise PermitInputError("control workflow ref names the wrong reviewed SHA")

    encoded_branch = quote(CONTROL_BRANCH, safe="")
    branch = client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/branches/{encoded_branch}",
    )
    if branch.get("protected") is not True:
        raise PermitInputError("control workflow branch is not protected")
    if branch.get("commit", {}).get("sha") != control_sha:
        raise PermitInputError("control workflow branch response drifted from its ref")

    workflow = client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/contents/{CONTROL_WORKFLOW_PATH}?ref={encoded_branch}",
    )
    if workflow.get("type") != "file" or workflow.get("path") != CONTROL_WORKFLOW_PATH:
        raise PermitInputError("control workflow file is not present on its locked ref")

    try:
        active_rules = json.loads(
            client.get_bytes(
                f"/repos/{AUTHORITY_REPOSITORY}/rules/branches/{encoded_branch}",
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PermitInputError("active control-ref rules are invalid JSON") from exc
    if not isinstance(active_rules, list):
        raise PermitInputError("active control-ref rules must be a list")
    normalized_rules = sorted(
        (
            {
                "type": rule.get("type"),
                **(
                    {"parameters": rule.get("parameters")}
                    if "parameters" in rule
                    else {}
                ),
            }
            for rule in active_rules
            if isinstance(rule, dict)
            and rule.get("type")
            in {"creation", "deletion", "non_fast_forward", "update"}
        ),
        key=lambda rule: str(rule["type"]),
    )
    expected_rules = sorted(
        [*expected["ruleset"]["rules"], *expected["successor_ruleset"]["rules"]],
        key=lambda rule: str(rule["type"]),
    )
    if normalized_rules != expected_rules:
        raise PermitInputError("active control-ref rules drifted")
    return {
        "branch": CONTROL_BRANCH,
        "ref": CONTROL_REF,
        "sha": control_sha,
        "workflow_path": CONTROL_WORKFLOW_PATH,
        "workflow_blob_sha": workflow.get("sha"),
        "ruleset": ruleset_receipt,
        "active_rules": normalized_rules,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--adversarial-corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument(
        "--effective-only",
        action="store_true",
        help="verify effective ref rules without organization-ruleset identity",
    )
    parser.add_argument(
        "--ruleset-only",
        action="store_true",
        help="verify exact named organization ruleset identity and policy only",
    )
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        contract = validate_contract(
            load_json(args.contract, label="control contract"),
            load_json(args.adversarial_corpus, label="adversarial corpus"),
        )
        environments = []
        repository_settings = {}
        control_workflow = {}
        control_ruleset = {}
        if args.effective_only and args.ruleset_only:
            raise PermitInputError(
                "effective-only and ruleset-only verification are mutually exclusive"
            )
        if not args.offline:
            import os

            client = GitHubReadClient(
                os.environ.get("GH_TOKEN", ""),
                api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            )
            if args.ruleset_only:
                control_ruleset = verify_live_control_ruleset(contract, client)
            else:
                repository_settings = verify_live_repository_settings(contract, client)
                control_workflow = verify_live_control_workflow(
                    contract,
                    client,
                    effective_only=args.effective_only,
                )
                environments = verify_live_environments(contract, client)
        receipt = {
            "schema": "mindburn.release-control-plane-verification/v2",
            "contract_sha256": hashlib.sha256(args.contract.read_bytes()).hexdigest(),
            "live": not args.offline,
            "repository_settings": repository_settings,
            "control_workflow": control_workflow,
            "control_ruleset": control_ruleset,
            "environments": environments,
            "suite_cases": len(contract["adversarial_suite"]["cases"]),
        }
        encoded = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError) as exc:
        print(f"verify-control-plane: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
