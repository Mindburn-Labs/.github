#!/usr/bin/env python3
"""Advance the protected controller from a durable observed-final record."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any
from urllib.parse import quote

from atomic_merge_authority import (
    REPOSITORY,
    REPOSITORY_ID_QUERY,
    GitHubMergeClient,
    nested_string,
    validate_pull_request,
)
from authority_evidence_ledger import (
    GitHubLedgerClient,
    materialize_record,
    read_record,
    stable_record_descriptor,
)
from autonomous_release_permit import PermitInputError, require_sha
from observe_authority_promotion import OBSERVER_SCHEMA, validate_execution
from verify_control_plane import (
    CONTROL_BRANCH,
    CONTROL_REF,
    CONTROL_SUCCESSOR_RULESET_NAME,
    CONTROL_WORKFLOW_PATH,
    load_json,
    validate_control_workflow,
)
from wait_for_authority_canary import (
    load_json_file,
    verify_attestation,
)


RECEIPT_SCHEMA = "mindburn.release-authority-control-successor/v1"
PROMOTION_WORKFLOW_PATH = ".github/workflows/promote-authority.yml"
CONTROL_UPDATE_MUTATION = """
mutation($repositoryId: ID!, $beforeOid: GitObjectID!, $afterOid: GitObjectID!) {
  updateRefs(input: {
    repositoryId: $repositoryId,
    refUpdates: [{
      name: "refs/heads/authority/control-v1",
      beforeOid: $beforeOid,
      afterOid: $afterOid,
      force: false
    }]
  }) { clientMutationId }
}
"""


def positive_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PermitInputError(f"{label} must be a positive integer")
    return value


def verify_updater_scope(
    client: GitHubMergeClient,
    *,
    configured: dict[str, Any],
    app_slug: str,
    app_id: int,
    installation_id: int,
) -> None:
    if (
        configured
        != {
            "slug": app_slug,
            "app_id": app_id,
            "installation_id": installation_id,
        }
        or app_slug != "helm-authority-control-updater"
    ):
        raise PermitInputError("control-updater action identity drifted")
    repositories = client.get("/installation/repositories?per_page=100")
    items = repositories.get("repositories")
    if (
        not isinstance(items, list)
        or {item.get("full_name") for item in items if isinstance(item, dict)}
        != {REPOSITORY}
    ):
        raise PermitInputError("control-updater token repository scope is not exact")


def verify_observer_receipt(
    receipt: dict[str, Any],
    *,
    execution: dict[str, Any],
    parent_control_sha: str,
    successor_sha: str,
) -> None:
    expected = {
        "schema": OBSERVER_SCHEMA,
        "phase": "final",
        "decision": "ALLOW",
        "control_workflow_sha": parent_control_sha,
        "parent_workflow_sha": parent_control_sha,
        "candidate_workflow_sha": execution["candidate_workflow_sha"],
        "merged_workflow_sha": successor_sha,
        "merged_tree_sha": execution["merged_tree_sha"],
        "canary_permit_id": execution["canary_permit_id"],
        "ratification_permit_id": execution["ratification_permit_id"],
        "authority_suite_sha256": execution["authority_suite_sha256"],
        "stable_workflow_sha": successor_sha,
        "candidate_workflow_binding_sha": successor_sha,
    }
    if any(receipt.get(field) != value for field, value in expected.items()):
        raise PermitInputError("durable final observer does not bind the successor")
    positive_integer(
        receipt.get("promotion_run_id"), label="observer promotion_run_id"
    )
    positive_integer(
        receipt.get("promotion_run_attempt"),
        label="observer promotion_run_attempt",
    )


def load_durable_final(
    args: argparse.Namespace,
    ledger_client: GitHubLedgerClient,
    *,
    parent_control_sha: str,
    successor_sha: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    generation = positive_integer(args.generation, label="generation")
    receipt = load_json_file(args.final_receipt, label="promotion final append receipt")
    expected_namespace = f"promotions/generation-{generation}/{successor_sha}/final"
    if (
        receipt.get("namespace") != expected_namespace
        or receipt.get("record_type") != "authority-promotion"
        or receipt.get("phase") != "final"
    ):
        raise PermitInputError("final append receipt names another promotion")
    record = read_record(
        ledger_client,
        namespace=expected_namespace,
        record_type="authority-promotion",
        phase="final",
    )
    if record is None or record.get("descriptor") != stable_record_descriptor(receipt):
        raise PermitInputError("durable final record differs from its append receipt")
    manifest = record.get("manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("workflow_sha") != parent_control_sha
    ):
        raise PermitInputError("durable final record names another parent controller")

    with tempfile.TemporaryDirectory(
        prefix="helm-control-successor-final-"
    ) as temporary:
        materialized = Path(temporary) / "record"
        materialize_record(record, materialized)
        observer_path = materialized / "final-observer-receipt.json"
        bundle_path = materialized / "final-observer-receipt.attestation.json"
        execution = validate_execution(
            load_json_file(
                materialized / "authority-promotion-execution.json",
                label="durable promotion execution",
            )
        )
        observer = load_json_file(observer_path, label="durable final observer")
        verify_observer_receipt(
            observer,
            execution=execution,
            parent_control_sha=parent_control_sha,
            successor_sha=successor_sha,
        )
        verify_attestation(
            observer_path,
            bundle_path,
            repository=REPOSITORY,
            workflow_sha=parent_control_sha,
            source_sha=parent_control_sha,
            github_token=ledger_client.token,
            signer_workflow=f"Mindburn-Labs/.github/{PROMOTION_WORKFLOW_PATH}",
        )
    return record, execution, observer


def verify_successor_merge(
    client: GitHubMergeClient,
    *,
    execution: dict[str, Any],
    parent_control_sha: str,
    successor_sha: str,
) -> None:
    if (
        execution["parent_base_sha"] != parent_control_sha
        or execution["parent_workflow_sha"] != parent_control_sha
        or execution["control_workflow_sha"] != parent_control_sha
        or execution["merged_workflow_sha"] != successor_sha
    ):
        raise PermitInputError("promotion execution does not bind the control lineage")
    pull_request = client.get(
        f"/repos/{REPOSITORY}/pulls/{execution['candidate_pull_request']}"
    )
    validate_pull_request(
        pull_request,
        number=execution["candidate_pull_request"],
        base_sha=parent_control_sha,
        head_sha=execution["candidate_workflow_sha"],
        merged=True,
        merge_sha=successor_sha,
    )
    merge_commit = client.get(f"/repos/{REPOSITORY}/git/commits/{successor_sha}")
    parents = merge_commit.get("parents")
    if (
        not isinstance(parents, list)
        or len(parents) != 2
        or [parent.get("sha") for parent in parents if isinstance(parent, dict)]
        != [parent_control_sha, execution["candidate_workflow_sha"]]
        or nested_string(merge_commit, "tree", "sha", label="successor tree SHA")
        != execution["merged_tree_sha"]
    ):
        raise PermitInputError("successor is not the exact ratified merge commit")
    encoded_sha = quote(successor_sha, safe="")
    workflow = client.get(
        f"/repos/{REPOSITORY}/contents/{CONTROL_WORKFLOW_PATH}?ref={encoded_sha}"
    )
    if workflow.get("type") != "file" or workflow.get("path") != CONTROL_WORKFLOW_PATH:
        raise PermitInputError("successor does not contain the control workflow")


def advance_control(
    args: argparse.Namespace,
    client: GitHubMergeClient,
    ledger_client: GitHubLedgerClient,
) -> dict[str, Any]:
    control_contract = load_json(args.control_contract, label="control contract")
    control = validate_control_workflow(control_contract.get("control_workflow"))
    verify_updater_scope(
        client,
        configured=control["successor_app"],
        app_slug=args.updater_app_slug,
        app_id=args.updater_app_id,
        installation_id=args.updater_installation_id,
    )

    parent_control_sha = require_sha(
        args.parent_control_sha,
        label="parent_control_sha",
        length=40,
    )
    successor_sha = require_sha(args.successor_sha, label="successor_sha", length=40)
    if successor_sha == parent_control_sha:
        raise PermitInputError("control successor must differ from its parent")
    final_record, execution, _observer = load_durable_final(
        args,
        ledger_client,
        parent_control_sha=parent_control_sha,
        successor_sha=successor_sha,
    )
    verify_successor_merge(
        client,
        execution=execution,
        parent_control_sha=parent_control_sha,
        successor_sha=successor_sha,
    )

    control_ref = client.get(f"/repos/{REPOSITORY}/git/ref/heads/{CONTROL_BRANCH}")
    if control_ref.get("ref") not in (None, CONTROL_REF):
        raise PermitInputError("GitHub returned the wrong control ref")
    current_sha = nested_string(control_ref, "object", "sha", label="control SHA")
    if current_sha not in {parent_control_sha, successor_sha}:
        raise PermitInputError("control ref moved outside the resumable successor states")
    state = "already-advanced"
    if current_sha == parent_control_sha:
        repository_data = client.graphql(REPOSITORY_ID_QUERY, {})
        repository = repository_data.get("repository")
        if not isinstance(repository, dict) or not isinstance(
            repository.get("id"), str
        ):
            raise PermitInputError("GitHub GraphQL returned no authority repository ID")
        update = client.graphql(
            CONTROL_UPDATE_MUTATION,
            {
                "repositoryId": repository["id"],
                "beforeOid": parent_control_sha,
                "afterOid": successor_sha,
            },
        )
        if not isinstance(update.get("updateRefs"), dict):
            raise PermitInputError("GitHub returned no atomic control-ref update")
        state = "advanced"

    confirmed = client.get(f"/repos/{REPOSITORY}/git/ref/heads/{CONTROL_BRANCH}")
    if nested_string(confirmed, "object", "sha", label="control SHA") != successor_sha:
        raise PermitInputError("control ref did not advance to the ratified successor")
    return {
        "schema": RECEIPT_SCHEMA,
        "repository": REPOSITORY,
        "ruleset": CONTROL_SUCCESSOR_RULESET_NAME,
        "ref": CONTROL_REF,
        "before_sha": parent_control_sha,
        "after_sha": successor_sha,
        "force": False,
        "state": state,
        "candidate_generation": execution["candidate_generation"],
        "candidate_pull_request": execution["candidate_pull_request"],
        "ratification_permit_id": execution["ratification_permit_id"],
        "final_descriptor": final_record["descriptor"],
        "updater_app_id": args.updater_app_id,
        "updater_installation_id": args.updater_installation_id,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-contract", type=Path, required=True)
    parser.add_argument("--final-receipt", type=Path, required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--parent-control-sha", required=True)
    parser.add_argument("--successor-sha", required=True)
    parser.add_argument("--updater-app-slug", required=True)
    parser.add_argument("--updater-app-id", type=int, required=True)
    parser.add_argument("--updater-installation-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        args = build_parser().parse_args(argv)
        token = os.environ.get("GH_TOKEN", "")
        api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        result = advance_control(
            args,
            GitHubMergeClient(token, api_url=api_url),
            GitHubLedgerClient(token, api_url=api_url),
        )
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        args.output.write_text(encoded, encoding="utf-8")
        sys.stdout.write(encoded)
    except (KeyError, OSError, PermitInputError, TypeError) as exc:
        print(f"advance-authority-control: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
