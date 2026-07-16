from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "bootstrap_authority.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_authority", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
SPEC.loader.exec_module(MODULE)

CANDIDATE_SHA = "2" * 40
BASE_SHA = "1" * 40
MERGE_SHA = "3" * 40
TREE_SHA = "4" * 40
CANDIDATE_REF = "refs/heads/codex/autonomous-release-gen2-bootstrap"


def pull_request(
    repository: str,
    number: int,
    head_sha: str,
    *,
    base_sha: str = BASE_SHA,
    head_ref: str | None = None,
) -> dict[str, object]:
    return {
        "number": number,
        "state": "open",
        "merged": False,
        "draft": False,
        "base": {"ref": "main", "sha": base_sha},
        "head": {
            "ref": head_ref or f"proof-{number}",
            "sha": head_sha,
            "repo": {"full_name": repository},
        },
    }


class TriggerClient:
    def __init__(self, contract: dict[str, object]) -> None:
        repository = contract["adversarial_suite"]["repository"]
        self.pulls = {
            case["pull_request"]: pull_request(
                repository,
                case["pull_request"],
                case["head_sha"],
                base_sha=case["base_sha"],
                head_ref=case["head_ref"],
            )
            for case in contract["adversarial_suite"]["cases"]
        }
        self.patches = 0

    def get(self, path: str):
        if path.endswith("/git/ref/heads/main"):
            base_sha = next(iter(self.pulls.values()))["base"]["sha"]
            return {"ref": "refs/heads/main", "object": {"sha": base_sha}}
        return json.loads(json.dumps(self.pulls[int(path.rsplit("/", 1)[1])]))

    def request(self, method: str, path: str, *, payload=None):
        if method != "PATCH" or payload is None:
            raise AssertionError(f"unexpected request {method} {path}")
        value = self.pulls[int(path.rsplit("/", 1)[1])]
        value["state"] = payload["state"]
        self.patches += 1
        return json.loads(json.dumps(value))


class ResumeMergeClient:
    def get(self, path: str):
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": MERGE_SHA}}
        if "/pulls/" in path:
            value = pull_request(MODULE.REPOSITORY, 36, CANDIDATE_SHA)
            value.update(
                {
                    "state": "closed",
                    "merged": True,
                    "merge_commit_sha": MERGE_SHA,
                },
            )
            return value
        if path.endswith(f"/git/commits/{MERGE_SHA}"):
            return {
                "parents": [{"sha": BASE_SHA}, {"sha": CANDIDATE_SHA}],
                "tree": {"sha": TREE_SHA},
            }
        raise AssertionError(f"unexpected GET {path}")


class RepositorySettingsClient:
    def __init__(self, delete_branch_on_merge: bool) -> None:
        self.delete_branch_on_merge = delete_branch_on_merge
        self.patches = 0

    def get(self, path: str):
        if path != f"/repos/{MODULE.REPOSITORY}":
            raise AssertionError(path)
        return {"delete_branch_on_merge": self.delete_branch_on_merge}

    def request(self, method: str, path: str, *, payload=None):
        if (
            method != "PATCH"
            or path != f"/repos/{MODULE.REPOSITORY}"
            or payload != {"delete_branch_on_merge": False}
        ):
            raise AssertionError((method, path, payload))
        self.delete_branch_on_merge = False
        self.patches += 1
        return {"delete_branch_on_merge": False}


class LedgerSeedClient:
    def __init__(self, *, reserved_evidence: bool = False) -> None:
        self.sha: str | None = None
        self.posts = 0
        self.reserved_evidence = reserved_evidence

    def get(self, path: str):
        if path.endswith(f"/git/commits/{CANDIDATE_SHA}"):
            return {"tree": {"sha": "a" * 40}}
        if path.endswith(f"/git/trees/{'a' * 40}"):
            return {
                "truncated": False,
                "tree": (
                    [{"path": ".helm", "type": "tree", "sha": "b" * 40}]
                    if self.reserved_evidence
                    else []
                ),
            }
        if path.endswith(f"/git/trees/{'b' * 40}"):
            return {
                "truncated": False,
                "tree": [{"path": "evidence", "type": "tree", "sha": "c" * 40}],
            }
        if not path.endswith("/git/ref/heads/authority/evidence-v1"):
            raise AssertionError(path)
        if self.sha is None:
            raise MODULE.PermitInputError("GitHub GET failed with HTTP 404: absent")
        return {"ref": MODULE.LEDGER_REF, "object": {"sha": self.sha}}

    def request(self, method: str, path: str, *, payload=None):
        if (
            method != "POST"
            or not path.endswith("/git/refs")
            or payload != {"ref": MODULE.LEDGER_REF, "sha": CANDIDATE_SHA}
        ):
            raise AssertionError((method, path, payload))
        self.sha = CANDIDATE_SHA
        self.posts += 1
        return {"ref": MODULE.LEDGER_REF, "object": {"sha": self.sha}}


class LedgerStateClient:
    def __init__(self, head_sha: str, *, status: str = "ahead") -> None:
        self.head_sha = head_sha
        self.status = status

    def get(self, path: str):
        if path.endswith("/git/ref/heads/authority/evidence-v1"):
            return {"ref": MODULE.LEDGER_REF, "object": {"sha": self.head_sha}}
        if "/compare/" in path:
            return {
                "status": self.status,
                "ahead_by": 1,
                "behind_by": 0,
                "merge_base_commit": {"sha": CANDIDATE_SHA},
            }
        raise AssertionError(path)


class ControlPlaneAdminClient:
    RULESET_ID = 4242
    SUCCESSOR_RULESET_ID = 4243

    def __init__(
        self,
        *,
        wrong_ref: bool = False,
        existing_environments: set[str] | None = None,
    ) -> None:
        self.ruleset: dict[str, object] | None = None
        self.successor_ruleset: dict[str, object] | None = None
        self.etag = 'W/"control-1"'
        self.ref_sha = "9" * 40 if wrong_ref else None
        self.environment_policies = {
            "authority-observer": [],
            "authority-approval": [],
            "authority-merge": [],
            "authority-promotion": [],
            "authority-control": [],
        }
        self.environments = (
            set(self.environment_policies)
            if existing_environments is None
            else set(existing_environments)
        )
        self.operations: list[str] = []

    def response(self, body, etag=None):
        return SimpleNamespace(body=json.loads(json.dumps(body)), etag=etag)

    def request(self, method: str, path: str, *, payload=None, if_match=None):
        self.operations.append(f"{method} {path}")
        if path == "/orgs/Mindburn-Labs/rulesets?per_page=100" and method == "GET":
            summaries = []
            if self.ruleset is not None:
                summaries.append({"id": self.RULESET_ID, "name": self.ruleset["name"]})
            if self.successor_ruleset is not None:
                summaries.append(
                    {
                        "id": self.SUCCESSOR_RULESET_ID,
                        "name": self.successor_ruleset["name"],
                    }
                )
            return self.response(summaries)
        if path == "/orgs/Mindburn-Labs/rulesets" and method == "POST":
            if payload is None:
                raise AssertionError("missing control ruleset payload")
            if payload["name"] == MODULE.CONTROL_RULESET_NAME:
                if self.ruleset is not None:
                    raise AssertionError("unexpected control history creation")
                if any(rule.get("type") == "creation" for rule in payload["rules"]):
                    raise AssertionError(
                        "control ref creation was blocked before it existed"
                    )
                self.ruleset = {"id": self.RULESET_ID, **payload}
                return self.response(self.ruleset, self.etag)
            if payload["name"] == MODULE.CONTROL_SUCCESSOR_RULESET_NAME:
                if self.successor_ruleset is not None:
                    raise AssertionError("unexpected control successor creation")
                self.successor_ruleset = {
                    "id": self.SUCCESSOR_RULESET_ID,
                    **payload,
                }
                return self.response(self.successor_ruleset, 'W/"successor-1"')
            raise AssertionError("unexpected named control ruleset")
        if path == f"/orgs/Mindburn-Labs/rulesets/{self.RULESET_ID}":
            if self.ruleset is None:
                raise AssertionError("control ruleset is absent")
            if method == "GET":
                return self.response(self.ruleset, self.etag)
            if method == "PUT":
                if (
                    if_match != self.etag
                    or payload is None
                    or self.ref_sha != MERGE_SHA
                ):
                    raise AssertionError("control ruleset was finalized out of order")
                self.ruleset = {"id": self.RULESET_ID, **payload}
                self.etag = 'W/"control-2"'
                return self.response(self.ruleset, self.etag)
        if path == f"/orgs/Mindburn-Labs/rulesets/{self.SUCCESSOR_RULESET_ID}":
            if self.successor_ruleset is None or method != "GET":
                raise AssertionError("control successor ruleset is absent")
            return self.response(self.successor_ruleset, 'W/"successor-1"')
        if path.endswith("/git/matching-refs/heads/authority/control-v1"):
            refs = (
                []
                if self.ref_sha is None
                else [
                    {
                        "ref": "refs/heads/authority/control-v1",
                        "object": {"sha": self.ref_sha},
                    }
                ]
            )
            return self.response(refs)
        if path.endswith("/git/refs") and method == "POST":
            if payload != {
                "ref": "refs/heads/authority/control-v1",
                "sha": MERGE_SHA,
            }:
                raise AssertionError("wrong immutable control ref payload")
            self.ref_sha = MERGE_SHA
            return self.response({"ref": payload["ref"], "object": {"sha": MERGE_SHA}})
        if "/deployment-branch-policies/" in path and method == "DELETE":
            environment = path.split("/environments/", 1)[1].split("/", 1)[0]
            policy_id = int(path.rsplit("/", 1)[1])
            policies = self.environment_policies[environment]
            if [policy.get("id") for policy in policies] != [policy_id]:
                raise AssertionError("unexpected environment policy deletion")
            policies.clear()
            return self.response(None)
        if "/environments/" in path and "/deployment-branch-policies" not in path:
            environment = path.split("/environments/", 1)[1]
            if method != "PUT" or payload != MODULE.DISABLED_ENVIRONMENT_PAYLOAD:
                raise AssertionError((method, path, payload))
            self.environments.add(environment)
            return self.response(
                {
                    "name": environment,
                    "can_admins_bypass": False,
                    "protection_rules": [{"type": "branch_policy", "id": 1}],
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    },
                }
            )
        if path.endswith("/deployment-branch-policies"):
            environment = path.split("/environments/", 1)[1].split("/", 1)[0]
            if environment not in self.environments:
                raise AssertionError(f"environment {environment} is absent")
            policies = self.environment_policies[environment]
            if method == "GET":
                return self.response(
                    {"total_count": len(policies), "branch_policies": policies}
                )
            if method == "POST":
                if (
                    payload != {"name": "authority/control-v1", "type": "branch"}
                    or self.ruleset is None
                    or not any(
                        rule.get("type") == "creation" for rule in self.ruleset["rules"]
                    )
                    or self.ref_sha != MERGE_SHA
                ):
                    raise AssertionError("environment enabled before immutable control")
                created = {"id": len(policies) + 1, **payload}
                policies.append(created)
                return self.response(created)
        raise AssertionError(f"unexpected request {method} {path}")


class ControlPlaneObserverClient:
    def __init__(self, admin: ControlPlaneAdminClient) -> None:
        self.admin = admin

    def get_json(self, path: str):
        if path == f"/orgs/Mindburn-Labs/rulesets/{self.admin.RULESET_ID}":
            if self.admin.ruleset is None:
                raise MODULE.PermitInputError("control ruleset is absent")
            return self.admin.ruleset
        if path == (
            f"/orgs/Mindburn-Labs/rulesets/"
            f"{self.admin.SUCCESSOR_RULESET_ID}"
        ):
            if self.admin.successor_ruleset is None:
                raise MODULE.PermitInputError("control successor ruleset is absent")
            return self.admin.successor_ruleset
        if path == f"/repos/{MODULE.AUTHORITY_REPOSITORY}":
            return {"delete_branch_on_merge": False}
        if path.endswith("/git/ref/heads/authority/control-v1"):
            return {"object": {"sha": self.admin.ref_sha}}
        if "/branches/authority%2Fcontrol-v1" in path:
            return {"protected": True, "commit": {"sha": self.admin.ref_sha}}
        if "/contents/.github/workflows/promote-authority.yml" in path:
            return {
                "type": "file",
                "path": ".github/workflows/promote-authority.yml",
                "sha": "8" * 40,
            }
        if path.endswith("/deployment-branch-policies"):
            environment = path.split("/environments/", 1)[1].split("/", 1)[0]
            policies = self.admin.environment_policies[environment]
            return {"total_count": len(policies), "branch_policies": policies}
        if "/environments/" in path:
            environment = path.split("/environments/", 1)[1].split("/", 1)[0]
            if environment not in self.admin.environments:
                raise AssertionError(f"environment {environment} is absent")
            return {
                "can_admins_bypass": False,
                "protection_rules": [{"type": "branch_policy", "id": 1}],
                "deployment_branch_policy": {
                    "protected_branches": False,
                    "custom_branch_policies": True,
                },
            }
        raise AssertionError(f"unexpected observer GET {path}")

    def get_bytes(self, path: str) -> bytes:
        if path == "/orgs/Mindburn-Labs/rulesets?per_page=100":
            if self.admin.ruleset is None or self.admin.successor_ruleset is None:
                return b"[]"
            return json.dumps(
                [
                    {
                        "id": self.admin.RULESET_ID,
                        "name": self.admin.ruleset["name"],
                    },
                    {
                        "id": self.admin.SUCCESSOR_RULESET_ID,
                        "name": self.admin.successor_ruleset["name"],
                    },
                ]
            ).encode()
        if path.endswith("/rules/branches/authority%2Fcontrol-v1"):
            if self.admin.ruleset is None:
                raise MODULE.PermitInputError("control ruleset is absent")
            return json.dumps(
                [
                    *self.admin.ruleset["rules"],
                    *self.admin.successor_ruleset["rules"],
                ]
            ).encode()
        raise AssertionError(f"unexpected observer bytes GET {path}")


class BootstrapAuthorityTests(unittest.TestCase):
    def load_control_contract(self):
        return MODULE.validate_contract(
            MODULE.load_json(
                ROOT / "config" / "autonomous-release-control-plane.json",
                label="contract",
            ),
            MODULE.load_json(
                ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
                label="corpus",
            ),
        )

    def control_args(self):
        return argparse.Namespace(
            control_contract=ROOT / "config" / "autonomous-release-control-plane.json",
            adversarial_corpus=(
                ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json"
            ),
        )

    def test_bootstrap_preserves_candidate_head_for_fail_closed_recovery(self) -> None:
        for initial, expected_patches in ((True, 1), (False, 0)):
            with self.subTest(initial=initial):
                client = RepositorySettingsClient(initial)
                receipt = MODULE.ensure_recovery_head_ref_policy(client)
                self.assertFalse(receipt["delete_branch_on_merge_after"])
                self.assertEqual(client.patches, expected_patches)

    def test_evidence_ledger_seed_creation_is_exact_and_idempotent(self) -> None:
        client = LedgerSeedClient()
        first = MODULE.ensure_evidence_ledger_seed(
            client,
            expected_sha=CANDIDATE_SHA,
        )
        second = MODULE.ensure_evidence_ledger_seed(
            client,
            expected_sha=CANDIDATE_SHA,
        )
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(client.posts, 1)

    def test_evidence_ledger_seed_rejects_candidate_reserved_tree(self) -> None:
        with self.assertRaisesRegex(MODULE.PermitInputError, "must not pre-seed"):
            MODULE.ensure_evidence_ledger_seed(
                LedgerSeedClient(reserved_evidence=True),
                expected_sha=CANDIDATE_SHA,
            )

    def test_evidence_ledger_resume_requires_seed_descendant(self) -> None:
        exact = MODULE.verify_evidence_ledger_descendant(
            LedgerStateClient(CANDIDATE_SHA),
            seed_sha=CANDIDATE_SHA,
        )
        self.assertFalse(exact["advanced"])
        advanced = MODULE.verify_evidence_ledger_descendant(
            LedgerStateClient("d" * 40),
            seed_sha=CANDIDATE_SHA,
        )
        self.assertTrue(advanced["advanced"])
        with self.assertRaisesRegex(MODULE.PermitInputError, "not a seed descendant"):
            MODULE.verify_evidence_ledger_descendant(
                LedgerStateClient("e" * 40, status="diverged"),
                seed_sha=CANDIDATE_SHA,
            )

    def test_suite_trigger_reopens_every_exact_permanent_case(self) -> None:
        contract = MODULE.validate_contract(
            MODULE.load_json(
                ROOT / "config" / "autonomous-release-control-plane.json",
                label="contract",
            ),
            MODULE.load_json(
                ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
                label="corpus",
            ),
        )
        client = TriggerClient(contract)
        trigger = MODULE.trigger_suite(contract, client, workflow_sha=CANDIDATE_SHA)
        self.assertEqual(trigger["cases"], contract["adversarial_suite"]["cases"])
        self.assertEqual(client.patches, 16)
        self.assertTrue(
            all(value["state"] == "open" for value in client.pulls.values())
        )

    def test_suite_trigger_rejects_head_drift(self) -> None:
        contract = MODULE.validate_contract(
            MODULE.load_json(
                ROOT / "config" / "autonomous-release-control-plane.json",
                label="contract",
            ),
            MODULE.load_json(
                ROOT / "tests" / "fixtures" / "autonomous-release-adversarial.json",
                label="corpus",
            ),
        )
        client = TriggerClient(contract)
        client.pulls[1]["head"]["sha"] = "f" * 40
        with self.assertRaises(MODULE.PermitInputError):
            MODULE.trigger_suite(contract, client, workflow_sha=CANDIDATE_SHA)

    def test_finalization_can_resume_after_exact_atomic_merge(self) -> None:
        ready = {
            "pull_request": 36,
            "base_sha": BASE_SHA,
            "candidate_sha": CANDIDATE_SHA,
            "merge_sha": MERGE_SHA,
            "merge_tree_sha": TREE_SHA,
        }
        receipt = MODULE.confirmed_or_atomic_merge(
            ready,
            ResumeMergeClient(),
            merger={
                "slug": "helm-authority-merger",
                "app_id": 5000001,
                "installation_id": 6000001,
            },
        )
        self.assertEqual(receipt["merge_sha"], MERGE_SHA)
        self.assertFalse(receipt["force"])

    def test_ready_receipt_rejects_candidate_substitution(self) -> None:
        ready = {
            "schema": MODULE.READY_SCHEMA,
            "repository": MODULE.REPOSITORY,
            "pull_request": 36,
            "base_sha": BASE_SHA,
            "candidate_sha": CANDIDATE_SHA,
            "candidate_ref": CANDIDATE_REF,
            "candidate_tree_sha": TREE_SHA,
            "ratification_permit_id": "sha256:" + "5" * 64,
            "ratification_run_id": 1,
            "liveness_permit_id": "sha256:" + "6" * 64,
            "liveness_run_id": 2,
            "liveness_run_attempt": 1,
            "merge_sha": MERGE_SHA,
            "merge_tree_sha": TREE_SHA,
            "evidence_sha256": {},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ready.json"
            path.write_text(json.dumps(ready), encoding="utf-8")
            args = argparse.Namespace(
                ready=path,
                candidate_sha="9" * 40,
                candidate_pr=36,
            )
            with self.assertRaises(MODULE.PermitInputError):
                MODULE.validate_ready(args)

    def test_control_ref_locks_before_environments_are_enabled(self) -> None:
        contract = self.load_control_contract()
        admin = ControlPlaneAdminClient()
        observer = ControlPlaneObserverClient(admin)
        receipt = MODULE.install_control_workflow(
            contract,
            admin,
            observer,
            expected_sha=MERGE_SHA,
        )
        environments = MODULE.enable_control_environments(
            contract,
            admin,
            observer,
            expected_sha=MERGE_SHA,
        )
        self.assertEqual(receipt["sha"], MERGE_SHA)
        self.assertEqual(len(environments), 5)
        create_ruleset = admin.operations.index("POST /orgs/Mindburn-Labs/rulesets")
        create_ref = admin.operations.index(
            "POST /repos/Mindburn-Labs/.github/git/refs"
        )
        lock_ruleset = admin.operations.index(
            f"PUT /orgs/Mindburn-Labs/rulesets/{admin.RULESET_ID}"
        )
        enable_environment = next(
            index
            for index, operation in enumerate(admin.operations)
            if operation.startswith("POST /repos/Mindburn-Labs/.github/environments/")
        )
        self.assertLess(create_ruleset, create_ref)
        self.assertLess(create_ref, lock_ruleset)
        self.assertLess(lock_ruleset, enable_environment)

        before_retry = list(admin.operations)
        MODULE.install_control_workflow(
            contract,
            admin,
            observer,
            expected_sha=MERGE_SHA,
        )
        MODULE.enable_control_environments(
            contract,
            admin,
            observer,
            expected_sha=MERGE_SHA,
        )
        retry_mutations = [
            operation
            for operation in admin.operations[len(before_retry) :]
            if operation.startswith(("POST ", "PUT "))
        ]
        self.assertEqual(retry_mutations, [])

    def test_finalization_prestate_requires_empty_environments_without_lock(
        self,
    ) -> None:
        admin = ControlPlaneAdminClient()
        observer = ControlPlaneObserverClient(admin)
        receipt = MODULE.verify_finalization_control_prestate(
            self.control_args(),
            observer,
            observer,
            expected_control_sha=MERGE_SHA,
        )
        self.assertEqual(receipt["state"], "lock-pending-environments-disabled")
        admin.environment_policies["authority-observer"] = [
            {"id": 1, "name": "authority/control-v1", "type": "branch"}
        ]
        with self.assertRaisesRegex(MODULE.PermitInputError, "branch policies"):
            MODULE.verify_finalization_control_prestate(
                self.control_args(),
                observer,
                observer,
                expected_control_sha=MERGE_SHA,
            )

    def test_finalization_prestate_allows_partial_environments_only_after_lock(
        self,
    ) -> None:
        contract = self.load_control_contract()
        admin = ControlPlaneAdminClient()
        observer = ControlPlaneObserverClient(admin)
        MODULE.install_control_workflow(
            contract,
            admin,
            observer,
            expected_sha=MERGE_SHA,
        )
        admin.environment_policies["authority-observer"] = [
            {"id": 1, "name": "authority/control-v1", "type": "branch"}
        ]
        receipt = MODULE.verify_finalization_control_prestate(
            self.control_args(),
            observer,
            observer,
            expected_control_sha=MERGE_SHA,
        )
        self.assertEqual(receipt["state"], "lock-proven-environments-transitioning")

    def test_missing_control_environments_are_created_disabled(self) -> None:
        contract = self.load_control_contract()
        admin = ControlPlaneAdminClient(
            existing_environments={"authority-observer", "authority-promotion"}
        )
        observer = ControlPlaneObserverClient(admin)
        receipts = MODULE.ensure_control_environments_disabled(
            contract,
            admin,
            observer,
        )
        self.assertEqual(len(receipts), 5)
        self.assertEqual(admin.environments, set(admin.environment_policies))
        self.assertTrue(all(receipt["branch_policies"] == [] for receipt in receipts))
        self.assertEqual(
            [
                operation
                for operation in admin.operations
                if operation.startswith(
                    "PUT /repos/Mindburn-Labs/.github/environments/"
                )
            ],
            [
                "PUT /repos/Mindburn-Labs/.github/environments/authority-observer",
                "PUT /repos/Mindburn-Labs/.github/environments/authority-approval",
                "PUT /repos/Mindburn-Labs/.github/environments/authority-merge",
                "PUT /repos/Mindburn-Labs/.github/environments/authority-promotion",
                "PUT /repos/Mindburn-Labs/.github/environments/authority-control",
            ],
        )

    def test_enabled_control_policies_are_disabled_before_verification(self) -> None:
        contract = self.load_control_contract()
        admin = ControlPlaneAdminClient(
            existing_environments={"authority-observer", "authority-promotion"}
        )
        for environment in ("authority-observer", "authority-promotion"):
            admin.environment_policies[environment] = [
                {
                    "id": 51 if environment == "authority-observer" else 52,
                    "name": "authority/control-v1",
                    "type": "branch",
                }
            ]
        observer = ControlPlaneObserverClient(admin)
        receipts = MODULE.ensure_control_environments_disabled(
            contract,
            admin,
            observer,
        )
        self.assertTrue(all(receipt["branch_policies"] == [] for receipt in receipts))
        self.assertEqual(
            [
                operation
                for operation in admin.operations
                if operation.startswith("DELETE ")
            ],
            [
                "DELETE /repos/Mindburn-Labs/.github/environments/authority-observer/deployment-branch-policies/51",
                "DELETE /repos/Mindburn-Labs/.github/environments/authority-promotion/deployment-branch-policies/52",
            ],
        )

    def test_wrong_control_ref_keeps_environments_disabled(self) -> None:
        contract = self.load_control_contract()
        admin = ControlPlaneAdminClient(wrong_ref=True)
        observer = ControlPlaneObserverClient(admin)
        with self.assertRaisesRegex(MODULE.PermitInputError, "wrong reviewed SHA"):
            MODULE.install_control_workflow(
                contract,
                admin,
                observer,
                expected_sha=MERGE_SHA,
            )
        self.assertTrue(
            all(not policies for policies in admin.environment_policies.values())
        )

    def test_environment_enable_resumes_from_one_exact_policy(self) -> None:
        contract = self.load_control_contract()
        admin = ControlPlaneAdminClient()
        observer = ControlPlaneObserverClient(admin)
        MODULE.install_control_workflow(
            contract,
            admin,
            observer,
            expected_sha=MERGE_SHA,
        )
        admin.environment_policies["authority-observer"] = [
            {"id": 1, "name": "authority/control-v1", "type": "branch"}
        ]
        before = len(admin.operations)
        receipts = MODULE.enable_control_environments(
            contract,
            admin,
            observer,
            expected_sha=MERGE_SHA,
        )
        mutations = [
            operation
            for operation in admin.operations[before:]
            if operation.startswith("POST ")
        ]
        self.assertEqual(len(receipts), 5)
        self.assertEqual(
            mutations,
            [
                "POST /repos/Mindburn-Labs/.github/environments/authority-approval/deployment-branch-policies",
                "POST /repos/Mindburn-Labs/.github/environments/authority-merge/deployment-branch-policies",
                "POST /repos/Mindburn-Labs/.github/environments/authority-promotion/deployment-branch-policies",
                "POST /repos/Mindburn-Labs/.github/environments/authority-control/deployment-branch-policies",
            ],
        )


if __name__ == "__main__":
    unittest.main()
