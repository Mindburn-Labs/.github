from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


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


def ruleset(kind: str, sha: str, ref: str) -> dict[str, object]:
    stable = kind == "stable"
    return {
        "id": MODULE.STABLE_RULESET_ID if stable else MODULE.CANDIDATE_RULESET_ID,
        "name": MODULE.STABLE_RULESET_NAME if stable else MODULE.CANDIDATE_RULESET_NAME,
        "target": "branch",
        "enforcement": "active" if stable else "evaluate",
        "bypass_actors": [],
        "conditions": MODULE.expected_conditions(kind),
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
    def __init__(self, stable: dict[str, object], candidate: dict[str, object]) -> None:
        self.current = {
            MODULE.STABLE_RULESET_ID: json.loads(json.dumps(stable)),
            MODULE.CANDIDATE_RULESET_ID: json.loads(json.dumps(candidate)),
        }
        self.puts: list[int] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
    ) -> object:
        ruleset_id = int(path.rsplit("/", 1)[1])
        if method == "GET":
            return MODULE.APIResponse(json.loads(json.dumps(self.current[ruleset_id])))
        if method != "PUT" or payload is None:
            raise AssertionError(f"unexpected request {method} {path}")
        updated = json.loads(json.dumps(payload))
        updated["id"] = ruleset_id
        self.current[ruleset_id] = updated
        self.puts.append(ruleset_id)
        return MODULE.APIResponse(updated)


def args(operation: str, *, merge_sha: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        operation=operation,
        parent_sha=PARENT_SHA,
        candidate_sha=CANDIDATE_SHA,
        candidate_ref=CANDIDATE_REF,
        merge_sha=merge_sha,
    )


class AuthorityRulesetBrokerTests(unittest.TestCase):
    def test_request_constructs_bearer_authorization_header(self) -> None:
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"{}"
        with mock.patch.object(MODULE.urllib.request, "urlopen", return_value=response) as urlopen:
            MODULE.GitHubRulesetClient("ruleset-test-token").request(
                "GET",
                "/orgs/Mindburn-Labs/rulesets/1",
            )
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.get_header("Authorization"),
            "Bearer ruleset-test-token",
        )

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

    def test_restore_reverses_a_partial_finalize_in_safe_order(self) -> None:
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

    def test_unexpected_bypass_or_coverage_fails_closed(self) -> None:
        for mutation in ("bypass", "coverage"):
            with self.subTest(mutation=mutation):
                stable = ruleset("stable", PARENT_SHA, MODULE.MAIN_REF)
                if mutation == "bypass":
                    stable["bypass_actors"] = [{"actor_type": "OrganizationAdmin"}]
                else:
                    stable["conditions"] = {"ref_name": {"include": ["~ALL"], "exclude": []}}
                client = FakeClient(
                    stable,
                    ruleset("candidate", PARENT_SHA, MODULE.MAIN_REF),
                )
                with self.assertRaises(MODULE.PermitInputError):
                    MODULE.transition(args("advance"), client)
                self.assertEqual(client.puts, [])


if __name__ == "__main__":
    unittest.main()
