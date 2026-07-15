#!/usr/bin/env python3
"""Plan, approve, and merge ordinary public PRs without human authorization."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import sys
import time
from typing import Any
import urllib.parse

from autonomous_release_permit import (
    PermitInputError,
    parse_json_strict,
    require_exact_keys,
    require_sha,
)
from submit_machine_approval import (
    APPROVER_APP_ID,
    APPROVER_INSTALLATION_ID,
    APPROVER_LOGIN,
    APPROVER_SLUG,
    GitHubApprovalClient,
    submit_machine_approval,
)
from authority_ruleset_broker import (
    AUTHORITY_REPOSITORY_ID,
    MAIN_REF,
    STABLE_RULESET_ID,
)
from authority_evidence_ledger import (
    LEDGER_REF,
    REPOSITORY as EVIDENCE_LEDGER_REPOSITORY,
    GitHubLedgerClient,
    materialize_record,
    read_record,
)
from configure_machine_approval_gates import (
    AUTONOMOUS_REPOSITORIES,
    ATOMIC_MERGE_SETTINGS,
    HUMAN_RULESET_ID,
    EVIDENCE_HISTORY_RULESET_NAME,
    EVIDENCE_UPDATER_RULESET_NAME,
    KERNEL_QUALITY_RULESET_ID,
    MACHINE_RULESET_NAME,
    PROOF_REFS,
    PROOF_REF_RULESET_NAME,
    UPDATER_RULESET_NAME,
    controlled_ruleset,
    evidence_history_ruleset_payload,
    evidence_updater_ruleset_payload,
    human_ruleset_state,
    kernel_quality_ruleset_payload,
    load_contract as load_bootstrap_contract,
    machine_ruleset_payload,
    normalize_classic_protection,
    proof_ref_ruleset_payload,
    updater_ruleset_payload,
    validate_merger,
)
from observe_authority_promotion import (
    PUBLIC_STABLE_REPOSITORIES,
    observe_effective_stable_rules,
    validate_execution,
)
from verify_authority_promotion import validate_authority_shape, validate_permit
from wait_for_authority_canary import (
    WORKFLOW_NAME,
    WORKFLOW_PATH,
    GitHubReadClient,
    load_json_file,
    run_sort_key,
    verify_candidate_permit,
    verify_attestation,
    verify_permit_reduction,
    verify_run_workflow_provenance,
)
from wait_for_authority_suite import write_attested_case


CONTRACT_SCHEMA = "mindburn.autonomous-release-controller/v1"
STATUS_SCHEMA = "mindburn.autonomous-release-controller-status/v1"
DISCOVERY_SCHEMA = "mindburn.autonomous-release-controller-discovery/v1"
PLAN_SCHEMA = "mindburn.autonomous-release-plan/v2"
APPROVAL_SCHEMA = "mindburn.autonomous-release-approvals/v1"
MERGE_SCHEMA = "mindburn.autonomous-release-merge/v1"
ORDINARY_CLOSURE_SCHEMA = "mindburn.autonomous-release-merge-closure/v1"
PROMOTION_WORKFLOW_NAME = "Promote HELM Release Authority"
PROMOTION_WORKFLOW_PATH = ".github/workflows/promote-authority.yml"
PROMOTION_RECEIPT_SCHEMA = "mindburn.release-authority-observer-receipt/v4"
ORGANIZATION = "Mindburn-Labs"
AUTHORITY_REPOSITORY = "Mindburn-Labs/.github"
SELECTED_REPOSITORIES = {
    "Mindburn-Labs/.github",
    "Mindburn-Labs/helm-ai-kernel",
    "Mindburn-Labs/contracts-autonomous-release-lab",
    "Mindburn-Labs/contracts-autonomous-release-canary",
}
ORDINARY_REPOSITORY_SLUGS = {
    "Mindburn-Labs/helm-ai-kernel": "helm-ai-kernel",
}
MERGE_METHODS = {"merge", "squash", "rebase"}
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
query($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) { id }
}
"""
AUTHORITY_EXACT_PATHS = {
    "Makefile",
    "config/autonomous-release-authority.json",
    "config/autonomous-release-bootstrap-v1.json",
    "config/autonomous-release-ci-template.yml",
    "config/autonomous-release-controller.json",
    "config/autonomous-release-control-plane.json",
    "config/autonomous-release-gates.json",
    "tests/fixtures/autonomous-release-adversarial.json",
}
AUTHORITY_SCRIPT_PREFIXES = (
    "scripts/atomic_merge_authority.py",
    "scripts/authority_",
    "scripts/autonomous_release_",
    "scripts/bootstrap_authority.py",
    "scripts/configure_machine_approval_gates.py",
    "scripts/observe_authority_promotion.py",
    "scripts/run_autonomous_release_gates.py",
    "scripts/submit_machine_approval.py",
    "scripts/verify_authority_promotion.py",
    "scripts/verify_control_plane.py",
    "scripts/wait_for_authority_",
)


def canonical_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def load_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(path.read_text(encoding="utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def parse_object_bytes(content: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(content.decode("utf-8"), label=label)
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} must be an object")
    return value


def record_input_object(
    record: dict[str, Any],
    name: str,
    *,
    label: str,
) -> dict[str, Any]:
    inputs = record.get("inputs")
    if not isinstance(inputs, dict) or not isinstance(inputs.get(name), bytes):
        raise PermitInputError(f"{label} is absent from the evidence ledger")
    return parse_object_bytes(inputs[name], label=label)


def positive_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PermitInputError(f"{label} must be a positive integer")
    return value


def validate_contract(value: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        value,
        required={"schema", "enabled", "apps", "evidence_ledger", "repositories"},
        label="controller contract",
    )
    if value["schema"] != CONTRACT_SCHEMA or not isinstance(value["enabled"], bool):
        raise PermitInputError("unsupported controller contract")
    apps = value["apps"]
    if not isinstance(apps, dict):
        raise PermitInputError("controller apps must be an object")
    require_exact_keys(
        apps,
        required={"observer", "approver", "merger"},
        label="controller apps",
    )
    expected_apps = {
        "observer": ("helm-authority-observer", 4296957, 146542079),
        "approver": (APPROVER_SLUG, APPROVER_APP_ID, APPROVER_INSTALLATION_ID),
    }
    for name, (slug, app_id, installation_id) in expected_apps.items():
        app = apps[name]
        if not isinstance(app, dict):
            raise PermitInputError(f"controller {name} App must be an object")
        require_exact_keys(
            app,
            required={"slug", "app_id", "installation_id"},
            label=f"controller {name} App",
        )
        if app != {
            "slug": slug,
            "app_id": app_id,
            "installation_id": installation_id,
        }:
            raise PermitInputError(f"controller {name} App identity drifted")
    merger = apps["merger"]
    if not isinstance(merger, dict):
        raise PermitInputError("controller merger App must be an object")
    require_exact_keys(
        merger,
        required={"slug", "app_id", "installation_id"},
        label="controller merger App",
    )
    if merger.get("slug") != "helm-authority-merger":
        raise PermitInputError("controller merger App slug drifted")
    if value["enabled"]:
        positive_integer(merger.get("app_id"), label="merger app_id")
        positive_integer(merger.get("installation_id"), label="merger installation_id")
    elif merger.get("app_id") is not None or merger.get("installation_id") is not None:
        raise PermitInputError("disabled controller must not declare merger authority")

    evidence_ledger = value["evidence_ledger"]
    if not isinstance(evidence_ledger, dict):
        raise PermitInputError("controller evidence ledger must be an object")
    require_exact_keys(
        evidence_ledger,
        required={"repository", "ref", "bootstrap_pr", "baseline_main"},
        label="controller evidence ledger",
    )
    baselines = evidence_ledger["baseline_main"]
    if (
        evidence_ledger["repository"] != EVIDENCE_LEDGER_REPOSITORY
        or evidence_ledger["ref"] != LEDGER_REF
        or evidence_ledger["bootstrap_pr"] != 36
        or not isinstance(baselines, dict)
        or set(baselines) != set(ORDINARY_REPOSITORY_SLUGS)
    ):
        raise PermitInputError("controller evidence ledger identity drifted")
    require_sha(
        baselines["Mindburn-Labs/helm-ai-kernel"],
        label="Kernel evidence ledger baseline",
        length=40,
    )

    repositories = value["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 4:
        raise PermitInputError(
            "controller must define the exact four-repository public authority matrix"
        )
    observed: set[str] = set()
    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            raise PermitInputError(f"controller repository {index} must be an object")
        require_exact_keys(
            repository,
            required={"repository", "merge_method", "authority_changes"},
            label=f"controller repository {index}",
        )
        name = repository["repository"]
        if name in observed or name not in SELECTED_REPOSITORIES:
            raise PermitInputError("controller repository allowlist is not exact")
        observed.add(name)
        if repository["merge_method"] not in MERGE_METHODS:
            raise PermitInputError("controller merge method is invalid")
        if repository["merge_method"] != "merge":
            raise PermitInputError(
                "controller requires exact reviewed merge commits for atomic base CAS"
            )
        expected_classification = {
            AUTHORITY_REPOSITORY: "promotion-only",
            "Mindburn-Labs/contracts-autonomous-release-lab": "proof-only",
            "Mindburn-Labs/contracts-autonomous-release-canary": "interlock-canary-only",
        }.get(name, "not-applicable")
        if repository["authority_changes"] != expected_classification:
            raise PermitInputError("controller authority classification drifted")
    if observed != SELECTED_REPOSITORIES:
        raise PermitInputError("controller repository allowlist is incomplete")
    return value


def require_enabled(contract: dict[str, Any]) -> None:
    if contract["enabled"] is not True:
        raise PermitInputError(
            "autonomous controller remains fail-closed until the distinct merger App is live"
        )


def contract_status(args: argparse.Namespace) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    merger = contract["apps"]["merger"]
    return {
        "schema": STATUS_SCHEMA,
        "enabled": contract["enabled"],
        "merger_configured": (
            isinstance(merger["app_id"], int)
            and not isinstance(merger["app_id"], bool)
            and merger["app_id"] > 0
            and isinstance(merger["installation_id"], int)
            and not isinstance(merger["installation_id"], bool)
            and merger["installation_id"] > 0
        ),
        "repositories": [item["repository"] for item in contract["repositories"]],
    }


def verify_bootstrap_final(
    args: argparse.Namespace,
    client: GitHubLedgerClient,
) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    pull_request = contract["evidence_ledger"]["bootstrap_pr"]
    root = f"bootstrap/pr-{pull_request}/{control_sha}"
    final = read_record(
        client,
        namespace=f"{root}/final",
        record_type="bootstrap",
        phase="final",
    )
    closure = read_record(
        client,
        namespace=f"{root}/closure",
        record_type="bootstrap",
        phase="closure",
    )
    intent = read_record(
        client,
        namespace=f"{root}/intent",
        record_type="bootstrap",
        phase="intent",
    )
    if final is None or closure is None or intent is None:
        raise PermitInputError("bootstrap evidence ledger state is incomplete")
    if set(final["inputs"]) != {
        "closure-descriptor.json",
        "ruleset-finalization.json",
        "final-control-plane.json",
        "final-control-plane-observer.json",
    }:
        raise PermitInputError("bootstrap final record has an unexpected file set")
    if set(closure["inputs"]) != {
        "intent-descriptor.json",
        "atomic-merge.json",
        "final-control-plane.json",
        "final-control-plane-observer.json",
    }:
        raise PermitInputError("bootstrap closure record has an unexpected file set")
    if (
        record_input_object(
            final,
            "closure-descriptor.json",
            label="bootstrap closure descriptor",
        )
        != closure["descriptor"]
    ):
        raise PermitInputError("bootstrap final record names another closure")
    if (
        record_input_object(
            closure,
            "intent-descriptor.json",
            label="bootstrap intent descriptor",
        )
        != intent["descriptor"]
    ):
        raise PermitInputError("bootstrap closure names another intent")
    merge = record_input_object(
        closure,
        "atomic-merge.json",
        label="bootstrap atomic merge",
    )
    if (
        merge.get("schema") != "mindburn.release-authority-atomic-merge/v1"
        or merge.get("repository") != AUTHORITY_REPOSITORY
        or merge.get("pull_request") != pull_request
        or merge.get("merge_sha") != control_sha
        or merge.get("ref") != "refs/heads/main"
        or merge.get("force") is not False
    ):
        raise PermitInputError("bootstrap atomic merge record is not exact")
    rulesets = record_input_object(
        final,
        "ruleset-finalization.json",
        label="bootstrap ruleset finalization",
    )
    if (
        rulesets.get("schema") != "mindburn.release-authority-ruleset-transition/v1"
        or rulesets.get("operation") != "bootstrap-finalize"
        or rulesets.get("merged_workflow_sha") != control_sha
        or rulesets.get("stable_ruleset_id") != STABLE_RULESET_ID
    ):
        raise PermitInputError("bootstrap ruleset finalization is not exact")
    identities = {
        (
            record["manifest"]["workflow_sha"],
            record["manifest"]["run_id"],
            record["manifest"]["run_attempt"],
        )
        for record in (intent, closure, final)
    }
    if len(identities) != 1:
        raise PermitInputError("bootstrap ledger phases have different run identities")
    return {
        "schema": "mindburn.autonomous-release-bootstrap-final/v1",
        "decision": "ALLOW",
        "control_sha": control_sha,
        "pull_request": pull_request,
        "ledger_head_sha": final["ledger_head_sha"],
        "final_manifest_sha256": final["descriptor"]["manifest_sha256"],
    }


def verify_observer_installation(
    client: GitHubReadClient,
    *,
    contract: dict[str, Any],
    app_slug: str,
    installation_id: int,
) -> None:
    expected = contract["apps"]["observer"]
    if (
        app_slug != expected["slug"]
        or installation_id != expected["installation_id"]
    ):
        raise PermitInputError("observer token action identity drifted")
    repositories = client.get_json("/installation/repositories?per_page=100")
    items = repositories.get("repositories")
    if (
        not isinstance(items, list)
        or {item.get("full_name") for item in items if isinstance(item, dict)}
        != SELECTED_REPOSITORIES
    ):
        raise PermitInputError("observer App repository scope is not exact")
    stable = client.get_json(f"/orgs/{ORGANIZATION}/rulesets/{STABLE_RULESET_ID}")
    if stable.get("id") != STABLE_RULESET_ID:
        raise PermitInputError("observer App read the wrong stable ruleset")


def verify_repository_settings(
    client: GitHubReadClient,
    *,
    repository: str,
    merge_method: str,
) -> None:
    value = client.get_json(f"/repos/{repository}")
    if merge_method != "merge":
        raise PermitInputError("autonomous controller requires merge commits")
    if (
        value.get("full_name") != repository
        or value.get("default_branch") != "main"
        or value.get("archived") is True
        or value.get("visibility") != "public"
        or {key: value.get(key) for key in ATOMIC_MERGE_SETTINGS}
        != ATOMIC_MERGE_SETTINGS
    ):
        raise PermitInputError(
            f"{repository} settings are incompatible with atomic {merge_method}"
        )


def named_organization_ruleset(
    client: GitHubReadClient,
    *,
    name: str,
) -> dict[str, Any]:
    listed = get_json_value(
        client,
        f"/orgs/{ORGANIZATION}/rulesets?per_page=100",
        label="organization rulesets",
    )
    if not isinstance(listed, list):
        raise PermitInputError("organization ruleset list is malformed")
    matches = [
        item for item in listed if isinstance(item, dict) and item.get("name") == name
    ]
    if len(matches) != 1:
        raise PermitInputError(f"expected exactly one organization ruleset {name}")
    ruleset_id = matches[0].get("id")
    if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
        raise PermitInputError(f"organization ruleset {name} has no valid ID")
    ruleset = client.get_json(f"/orgs/{ORGANIZATION}/rulesets/{ruleset_id}")
    if ruleset.get("id") != ruleset_id or ruleset.get("name") != name:
        raise PermitInputError(f"organization ruleset {name} identity drifted")
    return ruleset


def observe_merge_interlock(
    client: GitHubReadClient,
    *,
    controller_contract: dict[str, Any],
    bootstrap_contract_path: Path,
) -> dict[str, Any]:
    bootstrap = load_bootstrap_contract(bootstrap_contract_path)
    bootstrap_merger_id = validate_merger(bootstrap["merger"])
    controller_merger = controller_contract["apps"]["merger"]
    if (
        bootstrap_merger_id is None
        or bootstrap_merger_id != controller_merger["app_id"]
        or bootstrap["merger"]["installation_id"]
        != controller_merger["installation_id"]
    ):
        raise PermitInputError("controller and bootstrap merger identities differ")

    machine = named_organization_ruleset(client, name=MACHINE_RULESET_NAME)
    if controlled_ruleset(machine) != machine_ruleset_payload():
        raise PermitInputError("machine approval ruleset drifted")
    updater = named_organization_ruleset(client, name=UPDATER_RULESET_NAME)
    if controlled_ruleset(updater) != updater_ruleset_payload(bootstrap_merger_id):
        raise PermitInputError("exclusive updater ruleset drifted")
    ledger_updater = named_organization_ruleset(
        client,
        name=EVIDENCE_UPDATER_RULESET_NAME,
    )
    if controlled_ruleset(ledger_updater) != evidence_updater_ruleset_payload(
        bootstrap_merger_id
    ):
        raise PermitInputError("exclusive evidence appender ruleset drifted")
    ledger_history = named_organization_ruleset(
        client,
        name=EVIDENCE_HISTORY_RULESET_NAME,
    )
    if controlled_ruleset(ledger_history) != evidence_history_ruleset_payload():
        raise PermitInputError("append-only evidence history ruleset drifted")
    proof_refs = named_organization_ruleset(client, name=PROOF_REF_RULESET_NAME)
    if controlled_ruleset(proof_refs) != proof_ref_ruleset_payload():
        raise PermitInputError("immutable proof-ref ruleset drifted")
    lab = "Mindburn-Labs/contracts-autonomous-release-lab"
    for ref, expected_sha in PROOF_REFS.items():
        branch = ref.removeprefix("refs/heads/")
        live_ref = client.get_json(f"/repos/{lab}/git/ref/heads/{branch}")
        object_value = live_ref.get("object")
        if (
            live_ref.get("ref") != ref
            or not isinstance(object_value, dict)
            or object_value.get("sha") != expected_sha
        ):
            raise PermitInputError(f"immutable proof fixture {ref} drifted")
    human = client.get_json(f"/orgs/{ORGANIZATION}/rulesets/{HUMAN_RULESET_ID}")
    if controlled_ruleset(human) != human_ruleset_state(bootstrap, "after"):
        raise PermitInputError("human authorization scope was not retired exactly")
    kernel_quality = client.get_json(
        f"/repos/Mindburn-Labs/helm-ai-kernel/rulesets/{KERNEL_QUALITY_RULESET_ID}"
    )
    if controlled_ruleset(kernel_quality) != kernel_quality_ruleset_payload():
        raise PermitInputError("Kernel quality ruleset drifted")
    classic = bootstrap["classic_branch_protection"]
    classic_protection = client.get_json(
        f"/repos/{classic['repository']}/branches/{classic['branch']}/protection"
    )
    normalized_classic = normalize_classic_protection(classic_protection)
    if normalized_classic != classic["expected"]:
        raise PermitInputError("classic machine approval protection drifted")

    ledger_ref_name = bootstrap["evidence_ledger"]["ref"]
    ledger_ref = client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/git/ref/{ledger_ref_name.removeprefix('refs/')}"
    )
    if ledger_ref.get("ref") != ledger_ref_name or not isinstance(
        ledger_ref.get("object"), dict
    ):
        raise PermitInputError("evidence ledger ref identity drifted")
    ledger_head_sha = require_sha(
        ledger_ref["object"].get("sha"), label="evidence ledger head SHA", length=40
    )
    encoded_ledger_branch = urllib.parse.quote(
        ledger_ref_name.removeprefix("refs/heads/"), safe=""
    )
    ledger_rules = get_json_value(
        client,
        f"/repos/{AUTHORITY_REPOSITORY}/rules/branches/{encoded_ledger_branch}",
        label="effective evidence ledger rules",
    )
    if not isinstance(ledger_rules, list):
        raise PermitInputError("effective evidence ledger rules are malformed")
    actual_ledger_rules = sorted(
        (
            rule.get("ruleset_id"),
            rule.get("type"),
            rule.get("ruleset_source_type"),
            rule.get("ruleset_source"),
        )
        for rule in ledger_rules
        if isinstance(rule, dict)
    )
    expected_ledger_rules = sorted(
        [
            (ledger_history["id"], "creation", "Organization", ORGANIZATION),
            (ledger_history["id"], "deletion", "Organization", ORGANIZATION),
            (
                ledger_history["id"],
                "non_fast_forward",
                "Organization",
                ORGANIZATION,
            ),
            (ledger_updater["id"], "update", "Organization", ORGANIZATION),
        ]
    )
    if actual_ledger_rules != expected_ledger_rules:
        raise PermitInputError("evidence ledger is not append-only and App-exclusive")

    expected_effective: dict[str, list[tuple[int, str, str, str]]] = {}
    interlock_repositories = set(AUTONOMOUS_REPOSITORIES) | {lab}
    for repository in sorted(interlock_repositories):
        if repository in AUTONOMOUS_REPOSITORIES:
            verify_repository_settings(
                client, repository=repository, merge_method="merge"
            )
        rules = get_json_value(
            client,
            f"/repos/{repository}/rules/branches/main",
            label=f"effective merge rules for {repository}",
        )
        if not isinstance(rules, list):
            raise PermitInputError(f"effective merge rules for {repository} malformed")
        actual = sorted(
            (
                rule.get("ruleset_id"),
                rule.get("type"),
                rule.get("ruleset_source_type"),
                rule.get("ruleset_source"),
            )
            for rule in rules
            if isinstance(rule, dict)
        )
        expected = [(STABLE_RULESET_ID, "workflows", "Organization", ORGANIZATION)]
        if repository == lab:
            expected.extend(
                (proof_refs["id"], rule_type, "Organization", ORGANIZATION)
                for rule_type in ("creation", "deletion", "non_fast_forward", "update")
            )
        else:
            expected.extend(
                [
                    (machine["id"], "deletion", "Organization", ORGANIZATION),
                    (machine["id"], "non_fast_forward", "Organization", ORGANIZATION),
                    (machine["id"], "pull_request", "Organization", ORGANIZATION),
                    (updater["id"], "update", "Organization", ORGANIZATION),
                ]
            )
        if repository == "Mindburn-Labs/helm-ai-kernel":
            expected.append(
                (
                    KERNEL_QUALITY_RULESET_ID,
                    "required_status_checks",
                    "Repository",
                    "Mindburn-Labs/helm-ai-kernel",
                )
            )
        expected = sorted(expected)
        if actual != expected:
            raise PermitInputError(
                f"{repository} effective merge rules are not the exclusive interlock"
            )
        expected_effective[repository] = expected
    return {
        "schema": "mindburn.autonomous-release-merge-interlock/v1",
        "merger_app_id": bootstrap_merger_id,
        "merger_installation_id": bootstrap["merger"]["installation_id"],
        "machine_ruleset_id": machine["id"],
        "updater_ruleset_id": updater["id"],
        "kernel_quality_ruleset_id": KERNEL_QUALITY_RULESET_ID,
        "proof_ref_ruleset_id": proof_refs["id"],
        "proof_refs": PROOF_REFS,
        "evidence_ledger_ref": ledger_ref_name,
        "evidence_ledger_head_sha": ledger_head_sha,
        "evidence_history_ruleset_id": ledger_history["id"],
        "evidence_updater_ruleset_id": ledger_updater["id"],
        "evidence_ledger_effective_rules": expected_ledger_rules,
        "effective_rules": expected_effective,
        "repository_settings": bootstrap["repository_settings"],
        "classic_branch_protection": normalized_classic,
    }


def is_authority_path(path: str) -> bool:
    if path in AUTHORITY_EXACT_PATHS or path.startswith(".github/workflows/"):
        return True
    if path.startswith("tools/offline-attest/"):
        return True
    if any(path.startswith(prefix) for prefix in AUTHORITY_SCRIPT_PREFIXES):
        return True
    return path.startswith("tests/test_") and any(
        marker in path
        for marker in (
            "authority",
            "autonomous_release",
            "configure_machine",
            "submit_machine",
            "verify_control_plane",
        )
    )


def nested_string(value: dict[str, Any], *keys: str, label: str) -> str:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            raise PermitInputError(f"GitHub response is missing {label}")
        current = current.get(key)
    if not isinstance(current, str) or not current:
        raise PermitInputError(f"GitHub response has invalid {label}")
    return current


def get_json_value(client: GitHubReadClient, path: str, *, label: str) -> Any:
    try:
        text = client.get_bytes(path).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PermitInputError(f"{label} is not UTF-8") from exc
    return parse_json_strict(text, label=label)


def discover_effective_workflow_sha(client: GitHubReadClient) -> str:
    observed: set[str] = set()
    for repository in PUBLIC_STABLE_REPOSITORIES:
        rules = get_json_value(
            client,
            f"/repos/{repository}/rules/branches/main",
            label=f"effective rules for {repository}",
        )
        if not isinstance(rules, list):
            raise PermitInputError(f"effective rules for {repository} are malformed")
        matches = [
            rule
            for rule in rules
            if isinstance(rule, dict)
            and rule.get("ruleset_id") == STABLE_RULESET_ID
            and rule.get("ruleset_source_type") == "Organization"
            and rule.get("ruleset_source") == ORGANIZATION
            and rule.get("type") == "workflows"
        ]
        if len(matches) != 1:
            raise PermitInputError(
                f"{repository} does not expose one source-owned stable workflow rule"
            )
        parameters = matches[0].get("parameters")
        workflows = (
            parameters.get("workflows") if isinstance(parameters, dict) else None
        )
        if (
            not isinstance(parameters, dict)
            or parameters.get("do_not_enforce_on_create") is not False
            or not isinstance(workflows, list)
            or len(workflows) != 1
            or not isinstance(workflows[0], dict)
            or workflows[0].get("path") != WORKFLOW_PATH
            or workflows[0].get("ref") != MAIN_REF
            or workflows[0].get("repository_id") != AUTHORITY_REPOSITORY_ID
        ):
            raise PermitInputError(f"{repository} stable workflow parameters drifted")
        observed.add(
            require_sha(
                workflows[0].get("sha"),
                label=f"{repository} active workflow SHA",
                length=40,
            )
        )
    if len(observed) != 1:
        raise PermitInputError(
            "public repositories disagree on active release authority"
        )
    return observed.pop()


def discover(args: argparse.Namespace, client: GitHubReadClient) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    verify_observer_installation(
        client,
        contract=contract,
        app_slug=args.observer_app_slug,
        installation_id=args.observer_installation_id,
    )
    active_workflow_sha = discover_effective_workflow_sha(client)
    observe_effective_stable_rules(client, workflow_sha=active_workflow_sha)
    authority = head_authority(client, head_sha=active_workflow_sha)
    return {
        "schema": DISCOVERY_SCHEMA,
        "control_sha": control_sha,
        "active_workflow_sha": active_workflow_sha,
        "generation": authority["generation"],
        "kernel_sha": authority["kernel_sha"],
    }


def changed_paths(
    client: GitHubReadClient,
    repository: str,
    pull_request: int,
) -> list[str]:
    result: list[str] = []
    for page in range(1, 6):
        payload = get_json_value(
            client,
            f"/repos/{repository}/pulls/{pull_request}/files?per_page=100&page={page}",
            label="pull request files",
        )
        if not isinstance(payload, list):
            raise PermitInputError("pull request files response is malformed")
        for item in payload:
            if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
                raise PermitInputError("pull request file entry is malformed")
            status = item.get("status")
            if status not in {
                "added",
                "modified",
                "removed",
                "renamed",
                "copied",
                "changed",
            }:
                raise PermitInputError("pull request file status is invalid")
            paths = [item["filename"]]
            if status == "renamed":
                previous = item.get("previous_filename")
                if not isinstance(previous, str):
                    raise PermitInputError("renamed file lacks its previous path")
                paths.append(previous)
            for path in paths:
                pure = PurePosixPath(path)
                if pure.is_absolute() or ".." in pure.parts or "\\" in path:
                    raise PermitInputError("pull request file path is invalid")
                result.append(path)
        if len(payload) < 100:
            return result
    raise PermitInputError("pull request changed-file list exceeds controller bound")


def open_pull_requests(
    client: GitHubReadClient,
    repository: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for page in range(1, 11):
        payload = get_json_value(
            client,
            f"/repos/{repository}/pulls?state=open&base=main&per_page=100&page={page}",
            label="open pull requests",
        )
        if not isinstance(payload, list) or any(
            not isinstance(item, dict) for item in payload
        ):
            raise PermitInputError("open pull request response is malformed")
        result.extend(payload)
        if len(payload) < 100:
            return result
    raise PermitInputError("open pull request list exceeds controller bound")


def pull_requests_for_commit(
    client: GitHubReadClient,
    repository: str,
    commit_sha: str,
) -> list[dict[str, Any]]:
    payload = get_json_value(
        client,
        f"/repos/{repository}/commits/{commit_sha}/pulls?per_page=100",
        label="commit pull requests",
    )
    if not isinstance(payload, list):
        raise PermitInputError("commit pull request response is malformed")
    return [item for item in payload if isinstance(item, dict)]


def newest_run(
    client: GitHubReadClient,
    repository: str,
    head_sha: str,
    workflow_sha: str,
) -> tuple[dict[str, Any] | None, str | None]:
    query = urllib.parse.urlencode(
        {"event": "pull_request", "head_sha": head_sha, "per_page": 100}
    )
    payload = client.get_json(f"/repos/{repository}/actions/runs?{query}")
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise PermitInputError("workflow runs response is malformed")
    matching = [
        run
        for run in runs
        if isinstance(run, dict)
        and isinstance(run.get("id"), int)
        and run.get("name") == WORKFLOW_NAME
        and run.get("path") == WORKFLOW_PATH
        and run.get("head_sha") == head_sha
    ]
    matching.sort(key=run_sort_key, reverse=True)
    if not matching:
        return None, "NO_WORKFLOW_RUN"
    run = matching[0]
    provenance = verify_run_workflow_provenance(
        client,
        repository,
        run,
        head_sha=head_sha,
        expected_workflow_sha=workflow_sha,
    )
    if provenance is None:
        return None, "NEWEST_RUN_HAS_NO_PROVENANCE"
    if not provenance["is_expected_workflow"]:
        return None, "NEWEST_RUN_USES_DIFFERENT_AUTHORITY"
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return None, "NEWEST_EXACT_RUN_NOT_SUCCESSFUL"
    return run, None


def validate_live_pull_request(
    value: dict[str, Any],
    *,
    repository: str,
    pull_request: int,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> tuple[str, str]:
    observed_base = nested_string(value, "base", "sha", label="pull request base SHA")
    observed_head = nested_string(value, "head", "sha", label="pull request head SHA")
    if (
        value.get("number") != pull_request
        or value.get("state") != "open"
        or value.get("merged") is True
        or value.get("draft") is True
        or nested_string(value, "base", "ref", label="pull request base ref") != "main"
        or nested_string(
            value, "head", "repo", "full_name", label="pull request head repository"
        )
        != repository
        or (base_sha is not None and observed_base != base_sha)
        or (head_sha is not None and observed_head != head_sha)
    ):
        raise PermitInputError(
            "pull request is outside the autonomous controller contract"
        )
    return observed_base, observed_head


def validate_merged_pull_request(
    value: dict[str, Any],
    *,
    repository: str,
    pull_request: int,
    base_sha: str,
    head_sha: str,
    merge_sha: str,
) -> None:
    if (
        value.get("number") != pull_request
        or value.get("state") != "closed"
        or value.get("merged") is not True
        or value.get("draft") is True
        or value.get("merge_commit_sha") != merge_sha
        or nested_string(value, "base", "ref", label="pull request base ref") != "main"
        or nested_string(value, "base", "sha", label="pull request base SHA")
        != base_sha
        or nested_string(value, "head", "sha", label="pull request head SHA")
        != head_sha
        or nested_string(
            value, "head", "repo", "full_name", label="pull request head repository"
        )
        != repository
    ):
        raise PermitInputError(
            "merged pull request differs from the signed controller plan"
        )


def head_authority(
    client: GitHubReadClient,
    *,
    head_sha: str,
) -> dict[str, Any]:
    raw = client.get_bytes(
        "/repos/Mindburn-Labs/.github/contents/"
        f"config/autonomous-release-authority.json?ref={head_sha}",
        accept="application/vnd.github.raw+json",
    )
    try:
        value = parse_json_strict(raw.decode("utf-8"), label="candidate authority")
    except UnicodeDecodeError as exc:
        raise PermitInputError("candidate authority is not UTF-8") from exc
    return validate_authority_shape(value, label="candidate authority")


def verified_plan_entry(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    workflow_sha: str,
    repository_config: dict[str, Any],
    pull_request: int,
    base_sha: str,
    head_sha: str,
    run: dict[str, Any],
    recovery: bool,
) -> dict[str, Any]:
    repository = repository_config["repository"]
    repository_slug = {
        AUTHORITY_REPOSITORY: "github-authority",
        "Mindburn-Labs/helm-ai-kernel": "helm-ai-kernel",
        "Mindburn-Labs/contracts-autonomous-release-lab": "release-lab",
        "Mindburn-Labs/contracts-autonomous-release-canary": "release-interlock-canary",
    }[repository]
    evidence = args.output_dir / "evidence" / repository_slug / str(pull_request)
    permit_path, bundle_path, context_path, reviews = write_attested_case(
        client,
        repository,
        run["id"],
        evidence,
    )
    permit = verify_candidate_permit(
        permit_path,
        bundle_path,
        context_path,
        run=run,
        repository=repository,
        pull_request=pull_request,
        head_sha=head_sha,
        expected_workflow_sha=workflow_sha,
        expected_authority=authority,
        kernel_verifier=args.kernel_verifier,
        attestation_token=client.token,
    )
    verify_permit_reduction(
        args.kernel_verifier,
        permit_path,
        context_path,
        reviews,
        evidence / "parent-controller-permit.json",
    )
    if permit["base_sha"] != base_sha:
        raise PermitInputError("permit base moved before controller planning")
    return {
        "repository": repository,
        "pull_request": pull_request,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_sha": permit["merge_sha"],
        "merge_tree_sha": permit["merge_tree_sha"],
        "permit_id": permit["permit_id"],
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "workflow_sha": workflow_sha,
        "evidence": evidence.relative_to(args.output_dir).as_posix(),
        "merge_method": repository_config["merge_method"],
        "recovery": recovery,
    }


def materialize_ledger_evidence(
    record: dict[str, Any],
    *,
    output_dir: Path,
    evidence_path: str,
) -> Path:
    pure = PurePosixPath(evidence_path)
    if pure.is_absolute() or ".." in pure.parts or "\\" in evidence_path:
        raise PermitInputError("ledger plan evidence path escapes its artifact")
    prefix = evidence_path.rstrip("/") + "/"
    inputs = record.get("inputs")
    if not isinstance(inputs, dict):
        raise PermitInputError("ledger intent inputs are malformed")
    evidence_inputs = {
        path: content for path, content in inputs.items() if path.startswith(prefix)
    }
    if not evidence_inputs:
        raise PermitInputError("ledger intent lacks permit evidence")
    for relative, content in evidence_inputs.items():
        target = output_dir.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or target.is_symlink():
            raise PermitInputError(
                "ledger evidence materialization would overwrite a file"
            )
        target.write_bytes(content)
    return evidence_directory(output_dir, {"evidence": evidence_path})


def verify_ledger_approval(
    client: GitHubReadClient,
    *,
    approval_artifact: dict[str, Any],
    entry: dict[str, Any],
    control_sha: str,
) -> None:
    require_exact_keys(
        approval_artifact,
        required={"schema", "controller_sha", "repository", "approvals"},
        label="ledger approval artifact",
    )
    approvals = approval_artifact["approvals"]
    if (
        approval_artifact["schema"] != APPROVAL_SCHEMA
        or approval_artifact["controller_sha"] != control_sha
        or approval_artifact["repository"] != entry["repository"]
        or not isinstance(approvals, list)
        or len(approvals) != 1
        or not isinstance(approvals[0], dict)
    ):
        raise PermitInputError("ledger approval artifact is not exact")
    verify_machine_approval_receipt(client, approval=approvals[0], entry=entry)


def verify_machine_approval_receipt(
    client: GitHubReadClient,
    *,
    approval: dict[str, Any],
    entry: dict[str, Any],
) -> None:
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
    expected = {
        "schema": "mindburn.release-authority-machine-approval/v2",
        "repository": entry["repository"],
        "pull_request": entry["pull_request"],
        "head_sha": entry["head_sha"],
        "workflow_sha": entry["workflow_sha"],
        "permit_id": entry["permit_id"],
        "base_sha": entry["base_sha"],
        "merge_sha": entry["merge_sha"],
        "merge_tree_sha": entry["merge_tree_sha"],
        "review_state": "APPROVED",
        "approver_login": APPROVER_LOGIN,
        "approver_app_id": APPROVER_APP_ID,
        "approver_installation_id": APPROVER_INSTALLATION_ID,
    }
    if any(approval.get(field) != value for field, value in expected.items()):
        raise PermitInputError("machine approval receipt fields are not exact")
    review_id = positive_integer(approval.get("review_id"), label="ledger review_id")
    review = client.get_json(
        f"/repos/{entry['repository']}/pulls/{entry['pull_request']}/reviews/{review_id}"
    )
    author = review.get("user")
    if (
        review.get("state") != "APPROVED"
        or review.get("commit_id") != entry["head_sha"]
        or review.get("body") != f"HELM signed ALLOW permit {entry['permit_id']}"
        or not isinstance(author, dict)
        or author.get("login") != APPROVER_LOGIN
    ):
        raise PermitInputError("ledger-bound live App approval drifted")


def verify_ordinary_closure(
    closure: dict[str, Any],
    *,
    intent: dict[str, Any],
    entry: dict[str, Any],
    control_sha: str,
) -> None:
    if set(closure.get("inputs", {})) != {
        "intent-descriptor.json",
        "ordinary-merge-closure.json",
    }:
        raise PermitInputError("ordinary closure has an unexpected file set")
    if (
        record_input_object(
            closure,
            "intent-descriptor.json",
            label="ordinary intent descriptor",
        )
        != intent["descriptor"]
    ):
        raise PermitInputError("ordinary closure names another intent")
    value = record_input_object(
        closure,
        "ordinary-merge-closure.json",
        label="ordinary merge closure",
    )
    require_exact_keys(
        value,
        required={"schema", "controller_sha", "repository", "merges"},
        label="ordinary merge closure",
    )
    merges = value["merges"]
    if (
        value["schema"] != ORDINARY_CLOSURE_SCHEMA
        or value["controller_sha"] != control_sha
        or value["repository"] != entry["repository"]
        or not isinstance(merges, list)
        or len(merges) != 1
        or not isinstance(merges[0], dict)
    ):
        raise PermitInputError("ordinary merge closure is malformed")
    expected = {
        "repository": entry["repository"],
        "pull_request": entry["pull_request"],
        "head_sha": entry["head_sha"],
        "permit_id": entry["permit_id"],
        "merge_method": "merge",
        "merge_commit_sha": entry["merge_sha"],
        "merge_tree_sha": entry["merge_tree_sha"],
    }
    if merges[0] != expected:
        raise PermitInputError("ordinary merge closure does not match its intent")
    for field in ("workflow_sha", "run_id", "run_attempt"):
        if closure["manifest"][field] != intent["manifest"][field]:
            raise PermitInputError(
                "ordinary ledger phases have different run identities"
            )


def recover_ordinary_from_ledger(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    contract: dict[str, Any],
    control_sha: str,
    repository_config: dict[str, Any],
) -> dict[str, Any] | None:
    repository = repository_config["repository"]
    if repository not in ORDINARY_REPOSITORY_SLUGS:
        return None
    baseline_value = contract["evidence_ledger"]["baseline_main"][repository]
    baseline = baseline_value
    main = client.get_json(f"/repos/{repository}/git/ref/heads/main")
    main_sha = nested_string(main, "object", "sha", label=f"{repository} main SHA")
    if main_sha == baseline:
        return None
    ledger_client = GitHubLedgerClient(client.token, api_url=client.api_url)
    matches: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for pull_request_value in pull_requests_for_commit(client, repository, main_sha):
        number = pull_request_value.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            continue
        base = pull_request_value.get("base")
        head = pull_request_value.get("head")
        if not isinstance(base, dict) or not isinstance(head, dict):
            continue
        try:
            validate_merged_pull_request(
                pull_request_value,
                repository=repository,
                pull_request=number,
                base_sha=require_sha(
                    base.get("sha"), label="ledger recovery base SHA", length=40
                ),
                head_sha=require_sha(
                    head.get("sha"), label="ledger recovery head SHA", length=40
                ),
                merge_sha=main_sha,
            )
        except PermitInputError:
            continue
        root = (
            f"ordinary/{ORDINARY_REPOSITORY_SLUGS[repository]}/pr-{number}/{main_sha}"
        )
        intent = read_record(
            ledger_client,
            namespace=f"{root}/intent",
            record_type="ordinary-merge",
            phase="intent",
        )
        if intent is None:
            continue
        closure = read_record(
            ledger_client,
            namespace=f"{root}/closure",
            record_type="ordinary-merge",
            phase="closure",
        )
        matches.append((intent, closure))
    if len(matches) != 1:
        raise PermitInputError(
            "non-baseline main lacks exactly one durable ordinary merge intent"
        )
    intent, closure = matches[0]
    if not {"entry.json", "approval.json"}.issubset(intent["inputs"]) or any(
        path not in {"entry.json", "approval.json"} and not path.startswith("evidence/")
        for path in intent["inputs"]
    ):
        raise PermitInputError("ordinary intent contains an unexpected path")
    entry = validate_plan_entry(
        record_input_object(intent, "entry.json", label="ordinary intent entry"),
        label="ordinary intent entry",
    )
    if (
        entry["repository"] != repository
        or entry["merge_sha"] != main_sha
        or entry["recovery"] is not False
        or intent["manifest"]["workflow_sha"] != entry["workflow_sha"]
        or intent["manifest"]["run_id"] != entry["run_id"]
        or intent["manifest"]["run_attempt"] != entry["run_attempt"]
    ):
        raise PermitInputError("ordinary intent entry identity drifted")
    expected_namespace = (
        f"ordinary/{ORDINARY_REPOSITORY_SLUGS[repository]}/"
        f"pr-{entry['pull_request']}/{main_sha}/intent"
    )
    if intent["manifest"]["namespace"] != expected_namespace:
        raise PermitInputError("ordinary intent namespace differs from its entry")
    live_pull_request = client.get_json(
        f"/repos/{repository}/pulls/{entry['pull_request']}"
    )
    validate_merged_pull_request(
        live_pull_request,
        repository=repository,
        pull_request=entry["pull_request"],
        base_sha=entry["base_sha"],
        head_sha=entry["head_sha"],
        merge_sha=entry["merge_sha"],
    )
    evidence = materialize_ledger_evidence(
        intent,
        output_dir=args.output_dir,
        evidence_path=entry["evidence"],
    )
    authority = head_authority(client, head_sha=entry["workflow_sha"])
    permit = verify_candidate_permit(
        evidence / "release-permit.json",
        evidence / "release-permit.attestation.json",
        evidence / "context.json",
        run={"id": entry["run_id"], "run_attempt": entry["run_attempt"]},
        repository=repository,
        pull_request=entry["pull_request"],
        head_sha=entry["head_sha"],
        expected_workflow_sha=entry["workflow_sha"],
        expected_authority=authority,
        kernel_verifier=args.kernel_verifier,
        attestation_token=client.token,
    )
    if (
        permit["base_sha"] != entry["base_sha"]
        or permit["merge_sha"] != entry["merge_sha"]
        or permit["merge_tree_sha"] != entry["merge_tree_sha"]
        or permit["permit_id"] != entry["permit_id"]
    ):
        raise PermitInputError("ordinary ledger permit differs from its entry")
    replay_output = (
        args.output_dir
        / "ledger-replay"
        / ORDINARY_REPOSITORY_SLUGS[repository]
        / str(entry["pull_request"])
        / "recomputed-permit.json"
    )
    replay_output.parent.mkdir(parents=True, exist_ok=False)
    verify_permit_reduction(
        args.kernel_verifier,
        evidence / "release-permit.json",
        evidence / "context.json",
        {
            provider: evidence
            / f"parent-rebuilt-{provider}"
            / f"review-{provider}.json"
            for provider in ("anthropic", "openai")
        },
        replay_output,
    )
    verify_ledger_approval(
        client,
        approval_artifact=record_input_object(
            intent,
            "approval.json",
            label="ordinary intent approval",
        ),
        entry=entry,
        control_sha=control_sha,
    )
    if closure is not None:
        verify_ordinary_closure(
            closure,
            intent=intent,
            entry=entry,
            control_sha=control_sha,
        )
        return None
    return {**entry, "recovery": True}


def promotion_namespace_root(*, generation: int, merge_sha: str) -> str:
    generation = positive_integer(generation, label="promotion generation")
    merge_sha = require_sha(merge_sha, label="promotion merge SHA", length=40)
    return f"promotions/generation-{generation}/{merge_sha}"


def verify_promotion_intent(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    intent: dict[str, Any],
    generation: int,
    merge_sha: str,
    expected_parent: dict[str, Any],
    expected_successor: dict[str, Any],
    materialization_label: str,
    replay_with_kernel: bool,
) -> dict[str, Any]:
    inputs = intent.get("inputs")
    if (
        not isinstance(inputs, dict)
        or "entry.json" not in inputs
        or any(
            path != "entry.json" and not path.startswith("promotion/")
            for path in inputs
        )
    ):
        raise PermitInputError("promotion intent contains an unexpected path")
    required = {
        "promotion/release-permit.json",
        "promotion/release-permit.attestation.json",
        "promotion/ratification-input/context.json",
        "promotion/authority-promotion.json",
        "promotion/candidate-authority.json",
        "promotion/parent-authority.json",
        "promotion/trigger-run.json",
    }
    if not required.issubset(inputs):
        raise PermitInputError("promotion intent lacks required ratification evidence")
    entry = validate_plan_entry(
        record_input_object(intent, "entry.json", label="promotion intent entry"),
        label="promotion intent entry",
    )
    root = promotion_namespace_root(generation=generation, merge_sha=merge_sha)
    if (
        entry["repository"] != AUTHORITY_REPOSITORY
        or entry["merge_sha"] != merge_sha
        or entry["recovery"] is not False
        or entry["evidence"] != "promotion"
        or intent["manifest"]["namespace"] != f"{root}/intent"
        or intent["manifest"]["workflow_sha"] != entry["workflow_sha"]
        or intent["manifest"]["run_id"] != entry["run_id"]
        or intent["manifest"]["run_attempt"] != entry["run_attempt"]
    ):
        raise PermitInputError("promotion intent identity drifted")
    if expected_successor["generation"] != generation or expected_successor[
        "parent"
    ] != {
        "generation": expected_parent["generation"],
        "workflow_sha": entry["workflow_sha"],
    }:
        raise PermitInputError("promotion successor lineage is not exact")
    if head_authority(client, head_sha=entry["workflow_sha"]) != expected_parent:
        raise PermitInputError("promotion intent parent authority drifted")
    if head_authority(client, head_sha=entry["head_sha"]) != expected_successor:
        raise PermitInputError("promotion intent candidate authority drifted")

    materialized = (
        args.output_dir
        / "evidence"
        / "promotion-ledger"
        / f"generation-{generation}-{materialization_label}"
    )
    materialize_record(intent, materialized)
    if (
        load_json_file(
            materialized / "promotion" / "candidate-authority.json",
            label="ledger candidate authority",
        )
        != expected_successor
        or load_json_file(
            materialized / "promotion" / "parent-authority.json",
            label="ledger parent authority",
        )
        != expected_parent
    ):
        raise PermitInputError("promotion intent authority files drifted")
    run = {"id": entry["run_id"], "run_attempt": entry["run_attempt"]}
    permit_path = materialized / "promotion" / "release-permit.json"
    context_path = materialized / "promotion" / "ratification-input" / "context.json"
    bundle_path = materialized / "promotion" / "release-permit.attestation.json"
    if replay_with_kernel:
        permit = verify_candidate_permit(
            permit_path,
            bundle_path,
            context_path,
            run=run,
            repository=AUTHORITY_REPOSITORY,
            pull_request=entry["pull_request"],
            head_sha=entry["head_sha"],
            expected_workflow_sha=entry["workflow_sha"],
            expected_authority=expected_parent,
            kernel_verifier=args.kernel_verifier,
            attestation_token=client.token,
        )
    else:
        permit = load_json_file(permit_path, label="historical promotion permit")
        if validate_permit(permit) != expected_parent:
            raise PermitInputError("historical promotion permit authority drifted")
        historical_identity = {
            "repository": AUTHORITY_REPOSITORY,
            "pull_request": entry["pull_request"],
            "head_sha": entry["head_sha"],
            "workflow_sha": entry["workflow_sha"],
            "run_id": entry["run_id"],
            "run_attempt": entry["run_attempt"],
        }
        if any(
            permit.get(field) != value for field, value in historical_identity.items()
        ):
            raise PermitInputError("historical promotion permit identity drifted")
        verify_attestation(
            permit_path,
            bundle_path,
            repository=AUTHORITY_REPOSITORY,
            workflow_sha=entry["workflow_sha"],
            source_sha=entry["merge_sha"],
            github_token=client.token,
        )
    expected_permit = {
        "base_sha": entry["base_sha"],
        "merge_sha": entry["merge_sha"],
        "merge_tree_sha": entry["merge_tree_sha"],
        "permit_id": entry["permit_id"],
    }
    if any(permit.get(field) != value for field, value in expected_permit.items()):
        raise PermitInputError("promotion ledger permit differs from its entry")
    if replay_with_kernel:
        replay_output = (
            args.output_dir
            / "ledger-replay"
            / f"promotion-generation-{generation}-{materialization_label}.json"
        )
        replay_output.parent.mkdir(parents=True, exist_ok=True)
        if replay_output.exists() or replay_output.is_symlink():
            raise PermitInputError("promotion replay output already exists")
        verify_permit_reduction(
            args.kernel_verifier,
            permit_path,
            context_path,
            {
                provider: materialized
                / "promotion"
                / "parent-rebuilt-reviews"
                / provider
                / f"review-{provider}.json"
                for provider in ("anthropic", "openai")
            },
            replay_output,
        )
    trigger = load_json_file(
        materialized / "promotion" / "trigger-run.json",
        label="ledger trigger run",
    )
    if (
        trigger.get("id") != entry["run_id"]
        or trigger.get("run_attempt") != entry["run_attempt"]
        or trigger.get("head_sha") != entry["head_sha"]
        or trigger.get("event") != "pull_request"
        or trigger.get("status") != "completed"
        or trigger.get("conclusion") != "success"
        or trigger.get("name") != WORKFLOW_NAME
        or trigger.get("path") != WORKFLOW_PATH
    ):
        raise PermitInputError("promotion ledger trigger metadata drifted")
    return entry


def verify_promotion_merged(
    client: GitHubReadClient,
    *,
    intent: dict[str, Any],
    merged: dict[str, Any],
    entry: dict[str, Any],
    generation: int,
) -> None:
    if set(merged.get("inputs", {})) != {
        "intent-descriptor.json",
        "approval.json",
        "merge-response.json",
    }:
        raise PermitInputError("promotion merged phase has an unexpected file set")
    if (
        record_input_object(
            merged,
            "intent-descriptor.json",
            label="promotion intent descriptor",
        )
        != intent["descriptor"]
    ):
        raise PermitInputError("promotion merged phase names another intent")
    verify_machine_approval_receipt(
        client,
        approval=record_input_object(
            merged, "approval.json", label="promotion machine approval"
        ),
        entry=entry,
    )
    merge_response = record_input_object(
        merged, "merge-response.json", label="promotion merge response"
    )
    expected = {
        "schema": "mindburn.release-authority-atomic-merge/v1",
        "repository": AUTHORITY_REPOSITORY,
        "pull_request": entry["pull_request"],
        "base_sha": entry["base_sha"],
        "head_sha": entry["head_sha"],
        "merge_sha": entry["merge_sha"],
        "merge_tree_sha": entry["merge_tree_sha"],
        "ref": MAIN_REF,
        "force": False,
    }
    if merge_response != expected:
        raise PermitInputError("promotion merge response differs from its intent")
    root = promotion_namespace_root(generation=generation, merge_sha=entry["merge_sha"])
    if merged["manifest"]["namespace"] != f"{root}/merged":
        raise PermitInputError("promotion merged namespace drifted")
    for field in ("workflow_sha", "run_id", "run_attempt"):
        if merged["manifest"][field] != intent["manifest"][field]:
            raise PermitInputError("promotion ledger phases have different identities")


def verify_promotion_final(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    intent: dict[str, Any],
    merged: dict[str, Any],
    final: dict[str, Any],
    entry: dict[str, Any],
    authority: dict[str, Any],
    control_sha: str,
    materialization_label: str,
) -> None:
    inputs = final.get("inputs")
    required = {
        "merged-descriptor.json",
        "final-observer-receipt.json",
        "final-observer-receipt.attestation.json",
        "authority-promotion-execution.json",
        "ruleset-activate.json",
    }
    if (
        not isinstance(inputs, dict)
        or not required.issubset(inputs)
        or not any(path.startswith("observer-replay-final/") for path in inputs)
        or any(
            path not in required and not path.startswith("observer-replay-final/")
            for path in inputs
        )
    ):
        raise PermitInputError("promotion final phase has an unexpected file set")
    if (
        record_input_object(
            final,
            "merged-descriptor.json",
            label="promotion merged descriptor",
        )
        != merged["descriptor"]
    ):
        raise PermitInputError("promotion final phase names another merged record")
    root = promotion_namespace_root(
        generation=authority["generation"], merge_sha=entry["merge_sha"]
    )
    if final["manifest"]["namespace"] != f"{root}/final":
        raise PermitInputError("promotion final namespace drifted")
    for field in ("workflow_sha", "run_id", "run_attempt"):
        if final["manifest"][field] != intent["manifest"][field]:
            raise PermitInputError("promotion ledger phases have different identities")
    materialized = (
        args.output_dir
        / "evidence"
        / "promotion-final"
        / f"generation-{authority['generation']}-{materialization_label}"
    )
    materialize_record(final, materialized)
    receipt_path = materialized / "final-observer-receipt.json"
    receipt = load_json_file(receipt_path, label="ledger final observer receipt")
    if (
        receipt.get("schema") != PROMOTION_RECEIPT_SCHEMA
        or receipt.get("phase") != "final"
        or receipt.get("decision") != "ALLOW"
        or receipt.get("control_workflow_sha") != control_sha
        or receipt.get("parent_workflow_sha") != entry["workflow_sha"]
        or receipt.get("candidate_workflow_sha") != entry["head_sha"]
        or receipt.get("merged_workflow_sha") != entry["merge_sha"]
        or receipt.get("merged_tree_sha") != entry["merge_tree_sha"]
        or receipt.get("ratification_permit_id") != entry["permit_id"]
    ):
        raise PermitInputError("ledger final observer receipt identity drifted")
    positive_integer(
        receipt.get("promotion_run_id"), label="final promotion workflow run ID"
    )
    positive_integer(
        receipt.get("promotion_run_attempt"),
        label="final promotion workflow run attempt",
    )
    verify_attestation(
        receipt_path,
        materialized / "final-observer-receipt.attestation.json",
        repository=AUTHORITY_REPOSITORY,
        workflow_sha=control_sha,
        source_sha=control_sha,
        github_token=client.token,
        signer_workflow=f"Mindburn-Labs/.github/{PROMOTION_WORKFLOW_PATH}",
    )
    execution = validate_execution(
        load_json_file(
            materialized / "authority-promotion-execution.json",
            label="ledger promotion execution",
        )
    )
    if (
        execution.get("parent_generation") != authority["generation"] - 1
        or execution.get("candidate_generation") != authority["generation"]
        or execution.get("parent_base_sha") != entry["base_sha"]
        or execution.get("parent_workflow_sha") != entry["workflow_sha"]
        or execution.get("control_workflow_sha") != control_sha
        or execution.get("candidate_workflow_sha") != entry["head_sha"]
        or execution.get("candidate_tree_sha") != entry["merge_tree_sha"]
        or execution.get("candidate_pull_request") != entry["pull_request"]
        or execution.get("merged_workflow_sha") != entry["merge_sha"]
        or execution.get("merged_tree_sha") != entry["merge_tree_sha"]
        or execution.get("ratification_permit_id") != entry["permit_id"]
        or execution.get("ratification_run_id") != entry["run_id"]
        or execution.get("ratification_run_attempt") != entry["run_attempt"]
        or execution.get("authority_suite_sha256")
        != receipt.get("authority_suite_sha256")
    ):
        raise PermitInputError("ledger promotion execution identity drifted")
    activation = load_json_file(
        materialized / "ruleset-activate.json",
        label="ledger ruleset activation",
    )
    if (
        activation.get("schema") != "mindburn.release-authority-ruleset-transition/v1"
        or activation.get("operation") != "activate"
        or activation.get("parent_workflow_sha") != entry["workflow_sha"]
        or activation.get("candidate_workflow_sha") != entry["head_sha"]
        or activation.get("merged_workflow_sha") != entry["merge_sha"]
    ):
        raise PermitInputError("ledger ruleset activation identity drifted")


def read_verified_promotion_chain(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    generation: int,
    merge_sha: str,
    expected_parent: dict[str, Any],
    expected_successor: dict[str, Any],
    control_sha: str,
    materialization_label: str,
    replay_with_kernel: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    ledger_client = GitHubLedgerClient(client.token, api_url=client.api_url)
    root = promotion_namespace_root(generation=generation, merge_sha=merge_sha)
    intent = read_record(
        ledger_client,
        namespace=f"{root}/intent",
        record_type="authority-promotion",
        phase="intent",
    )
    if intent is None:
        raise PermitInputError("successor authority lacks a durable promotion intent")
    entry = verify_promotion_intent(
        args,
        client,
        intent=intent,
        generation=generation,
        merge_sha=merge_sha,
        expected_parent=expected_parent,
        expected_successor=expected_successor,
        materialization_label=materialization_label,
        replay_with_kernel=replay_with_kernel,
    )
    live_pull_request = client.get_json(
        f"/repos/{AUTHORITY_REPOSITORY}/pulls/{entry['pull_request']}"
    )
    validate_merged_pull_request(
        live_pull_request,
        repository=AUTHORITY_REPOSITORY,
        pull_request=entry["pull_request"],
        base_sha=entry["base_sha"],
        head_sha=entry["head_sha"],
        merge_sha=entry["merge_sha"],
    )
    merged = read_record(
        ledger_client,
        namespace=f"{root}/merged",
        record_type="authority-promotion",
        phase="merged",
    )
    if merged is not None:
        verify_promotion_merged(
            client,
            intent=intent,
            merged=merged,
            entry=entry,
            generation=generation,
        )
    final = read_record(
        ledger_client,
        namespace=f"{root}/final",
        record_type="authority-promotion",
        phase="final",
    )
    if final is not None:
        if merged is None:
            raise PermitInputError("promotion final closure has no merged phase")
        verify_promotion_final(
            args,
            client,
            intent=intent,
            merged=merged,
            final=final,
            entry=entry,
            authority=expected_successor,
            control_sha=control_sha,
            materialization_label=materialization_label,
        )
    return entry, merged, final


def has_final_promotion_closure(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    control_sha: str,
    active_workflow_sha: str,
) -> bool:
    if authority["generation"] == 2:
        # Generation 2 is admitted only by the separately verified bootstrap
        # intent/closure/final chain checked by tick-guard.
        return active_workflow_sha == control_sha
    active_workflow_sha = require_sha(
        active_workflow_sha, label="active authority SHA", length=40
    )
    parent_sha = authority["parent"]["workflow_sha"]
    parent = head_authority(client, head_sha=parent_sha)
    entry, _, final = read_verified_promotion_chain(
        args,
        client,
        generation=authority["generation"],
        merge_sha=active_workflow_sha,
        expected_parent=parent,
        expected_successor=authority,
        control_sha=control_sha,
        materialization_label="final-check",
        replay_with_kernel=False,
    )
    if entry["merge_sha"] != active_workflow_sha:
        raise PermitInputError("promotion closure names another active authority")
    return final is not None


def verified_activated_recovery_entry(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    control_sha: str,
    active_workflow_sha: str,
    repository_config: dict[str, Any],
) -> dict[str, Any] | None:
    parent_sha = authority["parent"]["workflow_sha"]
    parent_authority = head_authority(client, head_sha=parent_sha)
    entry, merged, final = read_verified_promotion_chain(
        args,
        client,
        generation=authority["generation"],
        merge_sha=active_workflow_sha,
        expected_parent=parent_authority,
        expected_successor=authority,
        control_sha=control_sha,
        materialization_label="activated-recovery",
        replay_with_kernel=False,
    )
    if merged is None:
        raise PermitInputError("activated authority lacks its durable merged phase")
    if final is not None:
        return None
    if repository_config["merge_method"] != entry["merge_method"]:
        raise PermitInputError("activated recovery merge method drifted")
    return {**entry, "recovery": True}


def recover_merged_authority_promotion(
    args: argparse.Namespace,
    client: GitHubReadClient,
    *,
    authority: dict[str, Any],
    workflow_sha: str,
    repository_config: dict[str, Any],
) -> dict[str, Any] | None:
    main = client.get_json(f"/repos/{AUTHORITY_REPOSITORY}/git/ref/heads/main")
    main_sha = nested_string(main, "object", "sha", label="authority main SHA")
    main_authority = head_authority(client, head_sha=main_sha)
    if main_authority == authority:
        return None
    if main_authority["generation"] != authority["generation"] + 1 or main_authority[
        "parent"
    ] != {"generation": authority["generation"], "workflow_sha": workflow_sha}:
        raise PermitInputError(
            "main authority differs from the controller without an exact successor lineage"
        )
    entry, _, final = read_verified_promotion_chain(
        args,
        client,
        generation=main_authority["generation"],
        merge_sha=main_sha,
        expected_parent=authority,
        expected_successor=main_authority,
        control_sha=require_sha(args.control_sha, label="control_sha", length=40),
        materialization_label="merged-recovery",
        replay_with_kernel=True,
    )
    if final is not None:
        raise PermitInputError(
            "finalized successor is not the independently observed active authority"
        )
    if repository_config["merge_method"] != entry["merge_method"]:
        raise PermitInputError("merged recovery merge method drifted")
    return {**entry, "recovery": True}


def plan(args: argparse.Namespace, client: GitHubReadClient) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    active_workflow_sha = require_sha(
        args.active_workflow_sha,
        label="active_workflow_sha",
        length=40,
    )
    verify_observer_installation(
        client,
        contract=contract,
        app_slug=args.observer_app_slug,
        installation_id=args.observer_installation_id,
    )
    if discover_effective_workflow_sha(client) != active_workflow_sha:
        raise PermitInputError("active release authority changed after discovery")
    observe_effective_stable_rules(client, workflow_sha=active_workflow_sha)
    interlock = observe_merge_interlock(
        client,
        controller_contract=contract,
        bootstrap_contract_path=Path(args.contract).with_name(
            "autonomous-release-bootstrap-v1.json"
        ),
    )
    authority = validate_authority_shape(
        load_json_file(args.authority, label="controller authority"),
        label="controller authority",
    )
    if head_authority(client, head_sha=active_workflow_sha) != authority:
        raise PermitInputError(
            "local authority does not equal the active workflow tree"
        )
    if authority["generation"] == 2 and active_workflow_sha != control_sha:
        raise PermitInputError(
            "bootstrap generation must equal the verified immutable control SHA"
        )
    args.output_dir.mkdir(parents=True, exist_ok=False)
    ordinary: list[dict[str, Any]] = []
    promotions: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for repository_config in contract["repositories"]:
        repository = repository_config["repository"]
        if repository_config["authority_changes"] != "proof-only":
            verify_repository_settings(
                client,
                repository=repository,
                merge_method=repository_config["merge_method"],
            )
        pull_requests = sorted(
            open_pull_requests(client, repository),
            key=lambda value: value.get("number", 0),
        )
        if repository_config["authority_changes"] in {
            "proof-only",
            "interlock-canary-only",
        }:
            reason = (
                "PERMANENT_PROOF_FIXTURE"
                if repository_config["authority_changes"] == "proof-only"
                else "EXPLICIT_INTERLOCK_CANARY_ONLY"
            )
            for pull_request_value in pull_requests:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": pull_request_value.get("number"),
                        "reason": reason,
                    }
                )
            continue
        repository_ordinary: list[dict[str, Any]] = []
        repository_promotions: list[dict[str, Any]] = []
        for pull_request_value in pull_requests:
            number = pull_request_value.get("number")
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                raise PermitInputError("GitHub returned an invalid pull request number")
            try:
                base_sha, head_sha = validate_live_pull_request(
                    pull_request_value,
                    repository=repository,
                    pull_request=number,
                )
                run, reason = newest_run(
                    client,
                    repository,
                    head_sha,
                    active_workflow_sha,
                )
                if run is None:
                    blocked.append(
                        {
                            "repository": repository,
                            "pull_request": number,
                            "reason": reason,
                        }
                    )
                    continue
                entry = verified_plan_entry(
                    args,
                    client,
                    authority=authority,
                    workflow_sha=active_workflow_sha,
                    repository_config=repository_config,
                    pull_request=number,
                    base_sha=base_sha,
                    head_sha=head_sha,
                    run=run,
                    recovery=False,
                )
                if repository_config["authority_changes"] == "promotion-only":
                    paths = changed_paths(client, repository, number)
                    if not paths:
                        raise PermitInputError(
                            "authority promotion has no changed paths"
                        )
                    candidate = head_authority(client, head_sha=head_sha)
                    if candidate["generation"] != authority[
                        "generation"
                    ] + 1 or candidate["parent"] != {
                        "generation": authority["generation"],
                        "workflow_sha": active_workflow_sha,
                    }:
                        raise PermitInputError(
                            "authority-surface PR is not the exact next generation"
                        )
                    repository_promotions.append(entry)
                else:
                    repository_ordinary.append(entry)
            except (OSError, PermitInputError) as exc:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": number,
                        "reason": "VALIDATION_FAILED",
                        "detail": str(exc)[:1000],
                    }
                )
        recovery: dict[str, Any] | None = None
        if repository == AUTHORITY_REPOSITORY:
            try:
                recovery = recover_merged_authority_promotion(
                    args,
                    client,
                    authority=authority,
                    workflow_sha=active_workflow_sha,
                    repository_config=repository_config,
                )
                if recovery is None and authority["generation"] > 2:
                    recovery = verified_activated_recovery_entry(
                        args,
                        client,
                        authority=authority,
                        control_sha=control_sha,
                        active_workflow_sha=active_workflow_sha,
                        repository_config=repository_config,
                    )
            except (OSError, PermitInputError) as exc:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": None,
                        "reason": "AUTHORITY_RECOVERY_FAILED",
                        "detail": str(exc)[:1000],
                    }
                )
                for entry in repository_promotions + repository_ordinary:
                    blocked.append(
                        {
                            "repository": repository,
                            "pull_request": entry["pull_request"],
                            "reason": "SERIALIZED_BEHIND_AUTHORITY_RECOVERY",
                        }
                    )
                continue
        ordinary_recovery: dict[str, Any] | None = None
        if recovery is None:
            try:
                ordinary_recovery = recover_ordinary_from_ledger(
                    args,
                    client,
                    contract=contract,
                    control_sha=control_sha,
                    repository_config=repository_config,
                )
            except (OSError, PermitInputError) as exc:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": None,
                        "reason": "ORDINARY_LEDGER_RECOVERY_FAILED",
                        "detail": str(exc)[:1000],
                    }
                )
                for entry in repository_promotions + repository_ordinary:
                    blocked.append(
                        {
                            "repository": repository,
                            "pull_request": entry["pull_request"],
                            "reason": "SERIALIZED_BEHIND_LEDGER_RECOVERY",
                        }
                    )
                continue
        if recovery is not None:
            promotions.append(recovery)
            for entry in repository_promotions + repository_ordinary:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": entry["pull_request"],
                        "reason": "SERIALIZED_BEHIND_AUTHORITY_RECOVERY",
                    }
                )
        elif ordinary_recovery is not None:
            ordinary.append(ordinary_recovery)
            for entry in repository_promotions + repository_ordinary:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": entry["pull_request"],
                        "reason": "SERIALIZED_BEHIND_LEDGER_RECOVERY",
                    }
                )
        elif repository_promotions:
            repository_promotions.sort(key=lambda entry: entry["pull_request"])
            promotions.append(repository_promotions[0])
            for entry in repository_promotions[1:] + repository_ordinary:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": entry["pull_request"],
                        "reason": "SERIALIZED_BEHIND_AUTHORITY_PROMOTION",
                    }
                )
        elif repository_ordinary:
            repository_ordinary.sort(key=lambda entry: entry["pull_request"])
            ordinary.append(repository_ordinary[0])
            for entry in repository_ordinary[1:]:
                blocked.append(
                    {
                        "repository": repository,
                        "pull_request": entry["pull_request"],
                        "reason": "SERIALIZED_BEHIND_EARLIER_PR",
                    }
                )
    if any(entry["recovery"] is True for entry in ordinary):
        for entry in promotions:
            blocked.append(
                {
                    "repository": entry["repository"],
                    "pull_request": entry["pull_request"],
                    "reason": "SERIALIZED_BEHIND_LEDGER_RECOVERY",
                }
            )
        promotions = []
    elif promotions:
        for entry in ordinary:
            blocked.append(
                {
                    "repository": entry["repository"],
                    "pull_request": entry["pull_request"],
                    "reason": "SERIALIZED_BEHIND_AUTHORITY_PROMOTION",
                }
            )
        ordinary = []
    if len(ordinary) > 1:
        ordinary.sort(
            key=lambda entry: (
                entry["recovery"] is not True,
                entry["repository"],
                entry["pull_request"],
            )
        )
        for entry in ordinary[1:]:
            blocked.append(
                {
                    "repository": entry["repository"],
                    "pull_request": entry["pull_request"],
                    "reason": "SERIALIZED_BEHIND_EARLIER_REPOSITORY",
                }
            )
        ordinary = ordinary[:1]
    return {
        "schema": PLAN_SCHEMA,
        "controller_sha": control_sha,
        "active_workflow_sha": active_workflow_sha,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "merge_interlock": interlock,
        "ordinary": ordinary,
        "promotions": promotions,
        "blocked": blocked,
    }


def validate_plan_entry(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PermitInputError(f"{label} is malformed")
    require_exact_keys(
        value,
        required={
            "repository",
            "pull_request",
            "base_sha",
            "head_sha",
            "merge_sha",
            "merge_tree_sha",
            "permit_id",
            "run_id",
            "run_attempt",
            "workflow_sha",
            "evidence",
            "merge_method",
            "recovery",
        },
        label=label,
    )
    if value["repository"] not in SELECTED_REPOSITORIES:
        raise PermitInputError(f"{label} repository is outside the allowlist")
    positive_integer(value["pull_request"], label=f"{label} pull_request")
    positive_integer(value["run_id"], label=f"{label} run_id")
    positive_integer(value["run_attempt"], label=f"{label} run_attempt")
    for field in (
        "base_sha",
        "head_sha",
        "merge_sha",
        "merge_tree_sha",
        "workflow_sha",
    ):
        require_sha(value[field], label=f"{label} {field}", length=40)
    if not isinstance(value["permit_id"], str) or not value["permit_id"].startswith(
        "sha256:"
    ):
        raise PermitInputError(f"{label} permit_id is invalid")
    require_sha(
        value["permit_id"].removeprefix("sha256:"),
        label=f"{label} permit_id",
        length=64,
    )
    if value["merge_method"] != "merge" or not isinstance(value["recovery"], bool):
        raise PermitInputError(f"{label} merge contract is invalid")
    evidence = value["evidence"]
    if not isinstance(evidence, str):
        raise PermitInputError(f"{label} evidence path is invalid")
    pure = PurePosixPath(evidence)
    if pure.is_absolute() or ".." in pure.parts or "\\" in evidence:
        raise PermitInputError(f"{label} evidence path escapes its artifact")
    return value


def validate_plan(value: dict[str, Any], *, control_sha: str) -> dict[str, Any]:
    require_exact_keys(
        value,
        required={
            "schema",
            "controller_sha",
            "active_workflow_sha",
            "observed_at",
            "merge_interlock",
            "ordinary",
            "promotions",
            "blocked",
        },
        label="controller plan",
    )
    if value["schema"] != PLAN_SCHEMA or value["controller_sha"] != control_sha:
        raise PermitInputError("controller plan was not issued by this authority")
    interlock = value["merge_interlock"]
    if not isinstance(interlock, dict):
        raise PermitInputError("controller plan merge interlock is malformed")
    require_exact_keys(
        interlock,
        required={
            "schema",
            "merger_app_id",
            "merger_installation_id",
            "machine_ruleset_id",
            "updater_ruleset_id",
            "kernel_quality_ruleset_id",
            "proof_ref_ruleset_id",
            "proof_refs",
            "evidence_ledger_ref",
            "evidence_ledger_head_sha",
            "evidence_history_ruleset_id",
            "evidence_updater_ruleset_id",
            "evidence_ledger_effective_rules",
            "effective_rules",
            "repository_settings",
            "classic_branch_protection",
        },
        label="controller plan merge interlock",
    )
    if interlock["schema"] != "mindburn.autonomous-release-merge-interlock/v1":
        raise PermitInputError("controller plan merge interlock schema is unsupported")
    for field in (
        "merger_app_id",
        "merger_installation_id",
        "machine_ruleset_id",
        "updater_ruleset_id",
        "kernel_quality_ruleset_id",
        "proof_ref_ruleset_id",
        "evidence_history_ruleset_id",
        "evidence_updater_ruleset_id",
    ):
        positive_integer(interlock[field], label=f"merge interlock {field}")
    if interlock["evidence_ledger_ref"] != "refs/heads/authority/evidence-v1":
        raise PermitInputError("controller plan names the wrong evidence ledger ref")
    require_sha(
        interlock["evidence_ledger_head_sha"],
        label="merge interlock evidence ledger head SHA",
        length=40,
    )
    active_workflow_sha = require_sha(
        value["active_workflow_sha"],
        label="plan active_workflow_sha",
        length=40,
    )
    if not all(
        isinstance(value[name], list) for name in ("ordinary", "promotions", "blocked")
    ):
        raise PermitInputError("controller plan lists are malformed")
    ordinary = [
        validate_plan_entry(entry, label=f"ordinary plan entry {index}")
        for index, entry in enumerate(value["ordinary"])
    ]
    promotions = [
        validate_plan_entry(entry, label=f"promotion plan entry {index}")
        for index, entry in enumerate(value["promotions"])
    ]
    if (
        len(ordinary) > 1
        or len(promotions) > 1
        or (ordinary and promotions)
        or any(entry["repository"] == AUTHORITY_REPOSITORY for entry in ordinary)
        or any(entry["repository"] != AUTHORITY_REPOSITORY for entry in promotions)
        or any(
            entry["repository"] == "Mindburn-Labs/contracts-autonomous-release-lab"
            for entry in ordinary
        )
        or len({entry["repository"] for entry in ordinary}) != len(ordinary)
    ):
        raise PermitInputError("controller plan violates fixed serialization")
    if any(
        entry["workflow_sha"] != active_workflow_sha and entry["recovery"] is not True
        for entry in ordinary
    ):
        raise PermitInputError("ordinary plan entries do not use the active authority")
    if any(
        entry["workflow_sha"] != active_workflow_sha and entry["recovery"] is not True
        for entry in promotions
    ):
        raise PermitInputError("forward promotion does not use the active authority")
    return value


def select_entry(plan_value: dict[str, Any], repository: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in plan_value["ordinary"]:
        if value.get("repository") == repository:
            result.append(value)
    return result


def evidence_directory(root: Path, entry: dict[str, Any]) -> Path:
    value = entry.get("evidence")
    if not isinstance(value, str):
        raise PermitInputError("controller evidence path is invalid")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "\\" in value:
        raise PermitInputError("controller evidence path escapes its artifact")
    path = root.joinpath(*pure.parts)
    if not path.is_dir() or path.is_symlink():
        raise PermitInputError("controller evidence directory is absent")
    return path


def approve(args: argparse.Namespace) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    if args.repository not in SELECTED_REPOSITORIES:
        raise PermitInputError("approval repository is outside the allowlist")
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    plan_value = validate_plan(
        load_object(args.plan, label="controller plan"),
        control_sha=control_sha,
    )
    observer_token = os.environ.get("GH_TOKEN", "")
    approver_token = os.environ.get("HELM_AUTHORITY_APPROVER_TOKEN", "")
    metadata = GitHubApprovalClient(observer_token)
    approver = GitHubApprovalClient(approver_token)
    receipts: list[dict[str, Any]] = []
    for entry in select_entry(plan_value, args.repository):
        evidence = evidence_directory(args.evidence_root, entry)
        receipt = submit_machine_approval(
            argparse.Namespace(
                permit=evidence / "release-permit.json",
                permit_bundle=evidence / "release-permit.attestation.json",
                trusted_context=evidence / "context.json",
                kernel_verifier=args.kernel_verifier,
                repository=args.repository,
                pull_request=entry["pull_request"],
                head_sha=entry["head_sha"],
                workflow_sha=entry["workflow_sha"],
                approver_app_slug=args.approver_app_slug,
                approver_installation_id=args.approver_installation_id,
                allow_merged_resume=entry["recovery"],
            ),
            approver,
            attestation_token=observer_token,
            metadata_client=metadata,
        )
        if receipt["permit_id"] != entry["permit_id"]:
            raise PermitInputError("approval receipt does not match its plan permit")
        receipts.append(receipt)
    return {
        "schema": APPROVAL_SCHEMA,
        "controller_sha": control_sha,
        "repository": args.repository,
        "approvals": receipts,
    }


def repository_config(contract: dict[str, Any], repository: str) -> dict[str, Any]:
    matches = [
        item for item in contract["repositories"] if item["repository"] == repository
    ]
    if len(matches) != 1:
        raise PermitInputError("repository is outside the source-owned controller set")
    return matches[0]


def verify_merger_installation(
    client: GitHubApprovalClient,
    *,
    contract: dict[str, Any],
    repository: str,
    app_slug: str,
    installation_id: int,
) -> None:
    merger = contract["apps"]["merger"]
    if (
        app_slug != merger["slug"]
        or installation_id != merger["installation_id"]
    ):
        raise PermitInputError("merger token action identity drifted")
    repositories = client.request("GET", "/installation/repositories?per_page=100")
    items = repositories.get("repositories") if isinstance(repositories, dict) else None
    if not isinstance(items, list) or {
        item.get("full_name") for item in items if isinstance(item, dict)
    } != {repository}:
        raise PermitInputError("merger token repository scope is not exact")


def verify_effective_interlock_before_merge(
    client: GitHubApprovalClient,
    *,
    receipt: dict[str, Any],
    repository: str,
) -> None:
    effective = receipt.get("effective_rules")
    expected = effective.get(repository) if isinstance(effective, dict) else None
    if not isinstance(expected, list):
        raise PermitInputError("merge interlock lacks repository effective rules")
    live = client.request("GET", f"/repos/{repository}/rules/branches/main")
    if not isinstance(live, list):
        raise PermitInputError("live effective merge rules are malformed")
    normalized_live = sorted(
        [
            rule.get("ruleset_id"),
            rule.get("type"),
            rule.get("ruleset_source_type"),
            rule.get("ruleset_source"),
        ]
        for rule in live
        if isinstance(rule, dict)
    )
    normalized_expected = sorted(
        list(item)
        for item in expected
        if isinstance(item, (list, tuple)) and len(item) == 4
    )
    if normalized_live != normalized_expected or len(normalized_expected) != len(
        expected
    ):
        raise PermitInputError("exclusive merge interlock drifted after signed plan")


def graphql(
    client: GitHubApprovalClient,
    query: str,
    variables: dict[str, Any],
) -> dict[str, Any]:
    response = client.request(
        "POST",
        "/graphql",
        payload={"query": query, "variables": variables},
    )
    if not isinstance(response, dict) or response.get("errors"):
        raise PermitInputError("GitHub rejected the atomic controller mutation")
    data = response.get("data")
    if not isinstance(data, dict):
        raise PermitInputError("GitHub GraphQL response has no data")
    return data


def merge(args: argparse.Namespace) -> dict[str, Any]:
    contract = validate_contract(
        load_object(args.contract, label="controller contract")
    )
    require_enabled(contract)
    configuration = repository_config(contract, args.repository)
    control_sha = require_sha(args.control_sha, label="control_sha", length=40)
    plan_value = validate_plan(
        load_object(args.plan, label="controller plan"), control_sha=control_sha
    )
    approvals = load_object(args.approvals, label="controller approvals")
    require_exact_keys(
        approvals,
        required={"schema", "controller_sha", "repository", "approvals"},
        label="controller approvals",
    )
    if (
        approvals["schema"] != APPROVAL_SCHEMA
        or approvals["controller_sha"] != control_sha
        or approvals["repository"] != args.repository
        or not isinstance(approvals["approvals"], list)
    ):
        raise PermitInputError("controller approval artifact is invalid")
    by_pr = {
        item.get("pull_request"): item
        for item in approvals["approvals"]
        if isinstance(item, dict)
    }
    client = GitHubApprovalClient(os.environ.get("GH_TOKEN", ""))
    verify_merger_installation(
        client,
        contract=contract,
        repository=args.repository,
        app_slug=args.merger_app_slug,
        installation_id=args.merger_installation_id,
    )
    if (
        plan_value["merge_interlock"]["merger_app_id"]
        != contract["apps"]["merger"]["app_id"]
        or plan_value["merge_interlock"]["merger_installation_id"]
        != contract["apps"]["merger"]["installation_id"]
    ):
        raise PermitInputError("signed plan names a different merger App")
    verify_effective_interlock_before_merge(
        client,
        receipt=plan_value["merge_interlock"],
        repository=args.repository,
    )
    receipts: list[dict[str, Any]] = []
    for entry in select_entry(plan_value, args.repository):
        approval = by_pr.get(entry["pull_request"])
        if not isinstance(approval, dict):
            raise PermitInputError("ordinary merge lacks an isolated App approval")
        expected = {
            "schema": "mindburn.release-authority-machine-approval/v2",
            "repository": args.repository,
            "pull_request": entry["pull_request"],
            "head_sha": entry["head_sha"],
            "workflow_sha": entry["workflow_sha"],
            "permit_id": entry["permit_id"],
            "base_sha": entry["base_sha"],
            "merge_sha": entry["merge_sha"],
            "merge_tree_sha": entry["merge_tree_sha"],
            "review_state": "APPROVED",
            "approver_login": APPROVER_LOGIN,
            "approver_app_id": APPROVER_APP_ID,
            "approver_installation_id": APPROVER_INSTALLATION_ID,
        }
        for field, value in expected.items():
            if approval.get(field) != value:
                raise PermitInputError(f"ordinary approval {field} is not exact")
        review_id = positive_integer(approval.get("review_id"), label="review_id")
        review = client.request(
            "GET",
            f"/repos/{args.repository}/pulls/{entry['pull_request']}/reviews/{review_id}",
        )
        author = review.get("user") if isinstance(review, dict) else None
        if (
            not isinstance(review, dict)
            or review.get("state") != "APPROVED"
            or review.get("commit_id") != entry["head_sha"]
            or review.get("body") != f"HELM signed ALLOW permit {entry['permit_id']}"
            or not isinstance(author, dict)
            or author.get("login") != APPROVER_LOGIN
        ):
            raise PermitInputError("live App approval drifted before merge")
        pull_request_value = client.request(
            "GET", f"/repos/{args.repository}/pulls/{entry['pull_request']}"
        )
        if not isinstance(pull_request_value, dict):
            raise PermitInputError("merge pull request response is malformed")
        if pull_request_value.get("merge_commit_sha") != entry["merge_sha"]:
            raise PermitInputError(
                "live pull request no longer names the reviewed merge commit"
            )
        main_path = f"/repos/{args.repository}/git/ref/heads/main"
        main = client.request("GET", main_path)
        if not isinstance(main, dict):
            raise PermitInputError("main ref response is malformed")
        main_sha = nested_string(main, "object", "sha", label="main SHA")
        merge_commit_sha = require_sha(
            entry["merge_sha"], label="reviewed merge SHA", length=40
        )
        resumed = main_sha == merge_commit_sha
        if resumed:
            if (
                pull_request_value.get("state") != "closed"
                or pull_request_value.get("merged") is not True
            ):
                validate_live_pull_request(
                    pull_request_value,
                    repository=args.repository,
                    pull_request=entry["pull_request"],
                    base_sha=entry["base_sha"],
                    head_sha=entry["head_sha"],
                )
                if pull_request_value.get("merge_commit_sha") != merge_commit_sha:
                    raise PermitInputError(
                        "GitHub reconciliation names a different merge commit"
                    )
                for _ in range(10):
                    pull_request_value = client.request(
                        "GET",
                        f"/repos/{args.repository}/pulls/{entry['pull_request']}",
                    )
                    if (
                        isinstance(pull_request_value, dict)
                        and pull_request_value.get("state") == "closed"
                        and pull_request_value.get("merged") is True
                    ):
                        break
                    time.sleep(2)
                else:
                    raise PermitInputError(
                        "main is exact but GitHub has not reconciled the pull request"
                    )
            validate_merged_pull_request(
                pull_request_value,
                repository=args.repository,
                pull_request=entry["pull_request"],
                base_sha=entry["base_sha"],
                head_sha=entry["head_sha"],
                merge_sha=merge_commit_sha,
            )
        elif main_sha == entry["base_sha"]:
            validate_live_pull_request(
                pull_request_value,
                repository=args.repository,
                pull_request=entry["pull_request"],
                base_sha=entry["base_sha"],
                head_sha=entry["head_sha"],
            )
        else:
            raise PermitInputError("main moved before the atomic merge precondition")
        commit = client.request(
            "GET", f"/repos/{args.repository}/git/commits/{merge_commit_sha}"
        )
        parents = commit.get("parents") if isinstance(commit, dict) else None
        if (
            not isinstance(commit, dict)
            or not isinstance(parents, list)
            or [parent.get("sha") for parent in parents if isinstance(parent, dict)]
            != [entry["base_sha"], entry["head_sha"]]
            or nested_string(commit, "tree", "sha", label="reviewed merge tree")
            != entry["merge_tree_sha"]
        ):
            raise PermitInputError("reviewed merge graph differs from the permit")
        if not resumed:
            repository_name = args.repository.split("/", 1)[1]
            repository_data = graphql(
                client,
                REPOSITORY_ID_QUERY,
                {"owner": ORGANIZATION, "name": repository_name},
            ).get("repository")
            if not isinstance(repository_data, dict) or not isinstance(
                repository_data.get("id"), str
            ):
                raise PermitInputError("GitHub returned no repository node ID")
            update = graphql(
                client,
                UPDATE_REFS_MUTATION,
                {
                    "repositoryId": repository_data["id"],
                    "beforeOid": entry["base_sha"],
                    "afterOid": merge_commit_sha,
                },
            )
            if not isinstance(update.get("updateRefs"), dict):
                raise PermitInputError("GitHub returned no atomic ref-update result")
            main_after = client.request("GET", main_path)
            if (
                not isinstance(main_after, dict)
                or nested_string(main_after, "object", "sha", label="main SHA")
                != merge_commit_sha
            ):
                raise PermitInputError("main does not equal the reviewed merge commit")
        for _ in range(10):
            confirmed = client.request(
                "GET", f"/repos/{args.repository}/pulls/{entry['pull_request']}"
            )
            if (
                isinstance(confirmed, dict)
                and confirmed.get("state") == "closed"
                and confirmed.get("merged") is True
                and confirmed.get("merge_commit_sha") == merge_commit_sha
            ):
                break
            time.sleep(2)
        else:
            raise PermitInputError(
                "main advanced safely but GitHub did not reconcile the pull request"
            )
        receipts.append(
            {
                "repository": args.repository,
                "pull_request": entry["pull_request"],
                "head_sha": entry["head_sha"],
                "permit_id": entry["permit_id"],
                "merge_method": configuration["merge_method"],
                "merge_commit_sha": merge_commit_sha,
                "merge_tree_sha": entry["merge_tree_sha"],
                "resumed": resumed,
            }
        )
    closure = {
        "schema": ORDINARY_CLOSURE_SCHEMA,
        "controller_sha": control_sha,
        "repository": args.repository,
        "merges": [
            {key: value for key, value in receipt.items() if key != "resumed"}
            for receipt in receipts
        ],
    }
    return {
        "schema": MERGE_SCHEMA,
        "controller_sha": control_sha,
        "repository": args.repository,
        "merges": receipts,
        "closure": closure,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    status_parser = subparsers.add_parser("validate-contract")
    status_parser.add_argument("--contract", type=Path, required=True)
    status_parser.add_argument("--output", type=Path, required=True)
    bootstrap_parser = subparsers.add_parser("verify-bootstrap")
    bootstrap_parser.add_argument("--contract", type=Path, required=True)
    bootstrap_parser.add_argument("--control-sha", required=True)
    bootstrap_parser.add_argument("--output", type=Path, required=True)
    discover_parser = subparsers.add_parser("discover")
    discover_parser.add_argument("--contract", type=Path, required=True)
    discover_parser.add_argument("--control-sha", required=True)
    discover_parser.add_argument("--observer-app-slug", required=True)
    discover_parser.add_argument("--observer-installation-id", type=int, required=True)
    discover_parser.add_argument("--output", type=Path, required=True)
    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--contract", type=Path, required=True)
    plan_parser.add_argument("--authority", type=Path, required=True)
    plan_parser.add_argument("--kernel-verifier", type=Path, required=True)
    plan_parser.add_argument("--control-sha", required=True)
    plan_parser.add_argument("--active-workflow-sha", required=True)
    plan_parser.add_argument("--observer-app-slug", required=True)
    plan_parser.add_argument("--observer-installation-id", type=int, required=True)
    plan_parser.add_argument("--output-dir", type=Path, required=True)
    plan_parser.add_argument("--output", type=Path, required=True)
    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("--contract", type=Path, required=True)
    approve_parser.add_argument("--plan", type=Path, required=True)
    approve_parser.add_argument("--evidence-root", type=Path, required=True)
    approve_parser.add_argument("--kernel-verifier", type=Path, required=True)
    approve_parser.add_argument("--control-sha", required=True)
    approve_parser.add_argument("--repository", required=True)
    approve_parser.add_argument("--approver-app-slug", required=True)
    approve_parser.add_argument("--approver-installation-id", type=int, required=True)
    approve_parser.add_argument("--output", type=Path, required=True)
    merge_parser = subparsers.add_parser("merge")
    merge_parser.add_argument("--contract", type=Path, required=True)
    merge_parser.add_argument("--plan", type=Path, required=True)
    merge_parser.add_argument("--approvals", type=Path, required=True)
    merge_parser.add_argument("--control-sha", required=True)
    merge_parser.add_argument("--repository", required=True)
    merge_parser.add_argument("--merger-app-slug", required=True)
    merge_parser.add_argument("--merger-installation-id", type=int, required=True)
    merge_parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command == "validate-contract":
            result = contract_status(args)
        elif args.command == "verify-bootstrap":
            result = verify_bootstrap_final(
                args,
                GitHubLedgerClient(
                    os.environ.get("GH_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
            )
        elif args.command == "discover":
            result = discover(
                args,
                GitHubReadClient(
                    os.environ.get("GH_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
            )
        elif args.command == "plan":
            result = plan(
                args,
                GitHubReadClient(
                    os.environ.get("GH_TOKEN", ""),
                    api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                ),
            )
        elif args.command == "approve":
            result = approve(args)
        else:
            result = merge(args)
        write_json(args.output, result)
        sys.stdout.buffer.write(canonical_json(result))
    except (KeyError, OSError, PermitInputError, TypeError, ValueError) as exc:
        print(f"autonomous-release-controller: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
