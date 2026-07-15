from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "authority_ruleset_broker.py"
SPEC = importlib.util.spec_from_file_location("authority_ruleset_broker", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ROOT / "scripts"))
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PARENT_SHA = "1" * 40
CANDIDATE_SHA = "2" * 40
MERGE_SHA = "3" * 40
CANDIDATE_REF = "refs/heads/authority-next"


def ruleset(
    kind: str,
    sha: str,
    ref: str,
    *,
    enforcement: str | None = None,
    conditions: dict[str, object] | None = None,
) -> dict[str, object]:
    stable = kind == "stable"
    return {
        "id": MODULE.STABLE_RULESET_ID if stable else MODULE.CANDIDATE_RULESET_ID,
        "name": MODULE.STABLE_RULESET_NAME if stable else MODULE.CANDIDATE_RULESET_NAME,
        "target": "branch",
        "enforcement": enforcement or ("active" if stable else "evaluate"),
        "bypass_actors": [],
        "conditions": conditions or MODULE.expected_conditions(kind),
        "rules": [
            {
                "type": "workflows",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "workflows": [
                        {
                            "repository_id": MODULE.AUTHORITY_REPOSITORY_ID,
                            "path": MODULE.WORKFLOW_PATH,
                            "sha": sha,
                            "ref": ref,
                        },
                    ],
                },
            },
        ],
    }


class FakeClient:
    def __init__(
        self,
        stable: dict[str, object],
        candidate: dict[str, object],
        *,
        fail_put: int | None = None,
    ) -> None:
        self.current = {
            MODULE.STABLE_RULESET_ID: json.loads(json.dumps(stable)),
            MODULE.CANDIDATE_RULESET_ID: json.loads(json.dumps(candidate)),
        }
        self.puts: list[int] = []
        self.fail_put = fail_put
        self.fail_cas = False
        self.etags = {
            MODULE.STABLE_RULESET_ID: 'W/"stable-1"',
            MODULE.CANDIDATE_RULESET_ID: 'W/"candidate-1"',
        }

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        if_match: str | None = None,
    ) -> object:
        ruleset_id = int(path.rsplit("/", 1)[1])
        if method == "GET":
            return MODULE.APIResponse(
                json.loads(json.dumps(self.current[ruleset_id])),
                self.etags[ruleset_id],
            )
        if method != "PUT" or payload is None:
            raise AssertionError(f"unexpected request {method} {path}")
        if self.fail_put == ruleset_id:
            self.fail_put = None
            raise MODULE.PermitInputError("simulated ruleset update failure")
        if self.fail_cas:
            self.fail_cas = False
            raise MODULE.PermitInputError("ruleset changed before PUT")
        if if_match != self.etags[ruleset_id]:
            raise MODULE.PermitInputError("simulated stale ETag")
        updated = json.loads(json.dumps(payload))
        updated["id"] = ruleset_id
        self.current[ruleset_id] = updated
        self.puts.append(ruleset_id)
        self.etags[ruleset_id] = f'W/"{ruleset_id}-{len(self.puts) + 1}"'
        return MODULE.APIResponse(updated, self.etags[ruleset_id])


def args(operation: str, *, merge_sha: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        operation=operation,
        parent_sha=PARENT_SHA,
        candidate_sha=CANDIDATE_SHA,
        candidate_ref=CANDIDATE_REF,
        merge_sha=merge_sha,
    )


class AuthorityRulesetBrokerTests(unittest.TestCase):
    def test_candidate_ref_requires_full_git_ref_validation(self) -> None:
        with self.assertRaisesRegex(MODULE.PermitInputError, "valid Git branch ref"):
            MODULE.validate_ref(
                "refs/heads/codex/authority..next",
                label="candidate_ref",
            )

    def test_stable_machine_coverage_is_public_only(self) -> None:
        conditions = MODULE.expected_conditions("stable")
        self.assertEqual(
            conditions["repository_id"]["repository_ids"],
            list(MODULE.PUBLIC_AUTONOMOUS_REPOSITORY_IDS),
        )
        self.assertNotIn("repository_name", conditions)

    def test_advance_observe_rebind_then_activate_preserves_safe_order(self) -> None:
        client = FakeClient(
            ruleset("stable", PARENT_SHA, MODULE.MAIN_REF),
            ruleset("candidate", PARENT_SHA, MODULE.MAIN_REF),
        )
        MODULE.transition(args("advance"), client)
        self.assertEqual(client.puts, [MODULE.CANDIDATE_RULESET_ID])
        MODULE.transition(args("rebind", merge_sha=MERGE_SHA), client)
        self.assertEqual(
            client.puts,
            [MODULE.CANDIDATE_RULESET_ID, MODULE.CANDIDATE_RULESET_ID],
        )
        stable = MODULE.workflow_binding(client.current[MODULE.STABLE_RULESET_ID])
        candidate = MODULE.workflow_binding(client.current[MODULE.CANDIDATE_RULESET_ID])
        self.assertEqual(stable["sha"], PARENT_SHA)
        self.assertEqual(candidate["sha"], MERGE_SHA)

        MODULE.transition(args("activate", merge_sha=MERGE_SHA), client)
        self.assertEqual(
            client.puts,
            [
                MODULE.CANDIDATE_RULESET_ID,
                MODULE.CANDIDATE_RULESET_ID,
                MODULE.STABLE_RULESET_ID,
            ],
        )
        for ruleset_id in (MODULE.CANDIDATE_RULESET_ID, MODULE.STABLE_RULESET_ID):
            binding = MODULE.workflow_binding(client.current[ruleset_id])
            self.assertEqual(binding["sha"], MERGE_SHA)
            self.assertEqual(binding["ref"], MODULE.MAIN_REF)

    def test_concurrent_ruleset_drift_fails_closed(self) -> None:
        client = FakeClient(
            ruleset("stable", PARENT_SHA, MODULE.MAIN_REF),
            ruleset("candidate", PARENT_SHA, MODULE.MAIN_REF),
        )
        current = MODULE.APIResponse(
            json.loads(json.dumps(client.current[MODULE.CANDIDATE_RULESET_ID])),
            client.etags[MODULE.CANDIDATE_RULESET_ID],
        )
        client.current[MODULE.CANDIDATE_RULESET_ID]["name"] = "concurrent drift"
        with self.assertRaisesRegex(MODULE.PermitInputError, "changed"):
            MODULE.put_ruleset(
                client,
                current,
                workflow_sha=CANDIDATE_SHA,
                workflow_ref=CANDIDATE_REF,
            )

    def test_restore_returns_candidate_to_parent_without_touching_stable(self) -> None:
        client = FakeClient(
            ruleset("stable", PARENT_SHA, MODULE.MAIN_REF),
            ruleset("candidate", CANDIDATE_SHA, CANDIDATE_REF),
        )
        MODULE.transition(args("restore"), client)
        self.assertEqual(client.puts, [MODULE.CANDIDATE_RULESET_ID])
        binding = MODULE.workflow_binding(client.current[MODULE.CANDIDATE_RULESET_ID])
        self.assertEqual(binding["sha"], PARENT_SHA)

    def test_restore_after_merge_returns_both_rulesets_to_parent(self) -> None:
        client = FakeClient(
            ruleset("stable", MERGE_SHA, MODULE.MAIN_REF),
            ruleset("candidate", MERGE_SHA, MODULE.MAIN_REF),
        )
        MODULE.transition(args("restore", merge_sha=MERGE_SHA), client)
        self.assertEqual(
            client.puts,
            [MODULE.STABLE_RULESET_ID, MODULE.CANDIDATE_RULESET_ID],
        )
        for ruleset_id in (MODULE.STABLE_RULESET_ID, MODULE.CANDIDATE_RULESET_ID):
            self.assertEqual(
                MODULE.workflow_binding(client.current[ruleset_id])["sha"],
                PARENT_SHA,
            )

    def test_missing_etag_fails_closed(self) -> None:
        client = FakeClient(
            ruleset("stable", PARENT_SHA, MODULE.MAIN_REF),
            ruleset("candidate", PARENT_SHA, MODULE.MAIN_REF),
        )
        current = MODULE.APIResponse(
            json.loads(json.dumps(client.current[MODULE.CANDIDATE_RULESET_ID])),
            None,
        )
        with self.assertRaisesRegex(MODULE.PermitInputError, "ETag"):
            MODULE.put_ruleset(
                client,
                current,
                workflow_sha=CANDIDATE_SHA,
                workflow_ref=CANDIDATE_REF,
            )

    def test_server_side_compare_and_swap_race_fails_closed(self) -> None:
        client = FakeClient(
            ruleset("stable", PARENT_SHA, MODULE.MAIN_REF),
            ruleset("candidate", PARENT_SHA, MODULE.MAIN_REF),
        )
        current = MODULE.get_ruleset(client, MODULE.CANDIDATE_RULESET_ID)
        client.fail_cas = True
        with self.assertRaisesRegex(MODULE.PermitInputError, "changed before PUT"):
            MODULE.put_ruleset(
                client,
                current,
                workflow_sha=CANDIDATE_SHA,
                workflow_ref=CANDIDATE_REF,
            )

    def test_unexpected_bypass_or_coverage_fails_closed(self) -> None:
        for mutation in ("bypass", "coverage"):
            with self.subTest(mutation=mutation):
                stable = ruleset("stable", PARENT_SHA, MODULE.MAIN_REF)
                if mutation == "bypass":
                    stable["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]
                else:
                    stable["conditions"] = {
                        "ref_name": {"include": ["~ALL"], "exclude": []}
                    }
                client = FakeClient(
                    stable,
                    ruleset("candidate", PARENT_SHA, MODULE.MAIN_REF),
                )
                with self.assertRaises(MODULE.PermitInputError):
                    MODULE.transition(args("advance"), client)
                self.assertEqual(client.puts, [])

    def test_generation_one_bootstrap_stages_enforces_then_finalizes(self) -> None:
        candidate_ref = "refs/heads/codex/autonomous-release-gen2-bootstrap"
        client = FakeClient(
            ruleset(
                "stable",
                MODULE.LEGACY_STABLE_WORKFLOW_SHA,
                MODULE.LEGACY_WORKFLOW_REF,
                enforcement="evaluate",
                conditions=MODULE.legacy_stable_conditions(),
            ),
            ruleset(
                "candidate",
                MODULE.LEGACY_PARENT_WORKFLOW_SHA,
                MODULE.LEGACY_WORKFLOW_REF,
            ),
        )
        bootstrap_args = argparse.Namespace(
            operation="bootstrap-stage",
            parent_sha=MODULE.LEGACY_PARENT_WORKFLOW_SHA,
            candidate_sha=CANDIDATE_SHA,
            candidate_ref=candidate_ref,
            merge_sha=None,
        )
        MODULE.transition(bootstrap_args, client)
        self.assertEqual(client.puts, [MODULE.CANDIDATE_RULESET_ID])

        bootstrap_args.operation = "bootstrap-enforce"
        MODULE.transition(bootstrap_args, client)
        self.assertEqual(
            client.puts,
            [
                MODULE.CANDIDATE_RULESET_ID,
                MODULE.STABLE_RULESET_ID,
            ],
        )
        stable = client.current[MODULE.STABLE_RULESET_ID]
        self.assertEqual(stable["enforcement"], "active")
        self.assertEqual(stable["conditions"], MODULE.expected_conditions("stable"))

        bootstrap_args.operation = "bootstrap-finalize"
        bootstrap_args.merge_sha = MERGE_SHA
        MODULE.transition(bootstrap_args, client)
        self.assertEqual(
            client.puts,
            [
                MODULE.CANDIDATE_RULESET_ID,
                MODULE.STABLE_RULESET_ID,
                MODULE.CANDIDATE_RULESET_ID,
                MODULE.STABLE_RULESET_ID,
            ],
        )
        for ruleset_id in (MODULE.STABLE_RULESET_ID, MODULE.CANDIDATE_RULESET_ID):
            binding = MODULE.workflow_binding(client.current[ruleset_id])
            self.assertEqual(
                (binding["sha"], binding["ref"]), (MERGE_SHA, MODULE.MAIN_REF)
            )

    def test_bootstrap_finalization_compensates_candidate_if_stable_update_fails(
        self,
    ) -> None:
        candidate_ref = "refs/heads/codex/autonomous-release-gen2-bootstrap"
        client = FakeClient(
            ruleset(
                "stable",
                CANDIDATE_SHA,
                candidate_ref,
            ),
            ruleset("candidate", CANDIDATE_SHA, candidate_ref),
            fail_put=MODULE.STABLE_RULESET_ID,
        )
        bootstrap_args = argparse.Namespace(
            operation="bootstrap-finalize",
            parent_sha=MODULE.LEGACY_PARENT_WORKFLOW_SHA,
            candidate_sha=CANDIDATE_SHA,
            candidate_ref=candidate_ref,
            merge_sha=MERGE_SHA,
        )
        with self.assertRaisesRegex(MODULE.PermitInputError, "candidate was restored"):
            MODULE.transition(bootstrap_args, client)
        self.assertEqual(
            client.puts,
            [MODULE.CANDIDATE_RULESET_ID, MODULE.CANDIDATE_RULESET_ID],
        )
        binding = MODULE.workflow_binding(client.current[MODULE.CANDIDATE_RULESET_ID])
        self.assertEqual(
            (binding["sha"], binding["ref"]), (CANDIDATE_SHA, candidate_ref)
        )


if __name__ == "__main__":
    unittest.main()
