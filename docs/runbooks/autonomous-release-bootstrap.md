# Generation-1 release-authority bootstrap

This runbook is valid only for the transition from authority generation 1 to
generation 2. Later generations are dispatched by the permit workflow and
executed only by
`authority/control-v1:.github/workflows/promote-authority.yml`; the copy on
mutable `main` is not the credential entrypoint.

The bootstrap is not a human approval. The only approval inputs are the exact
generation-1 signed 2-of-2 permit and the fresh generation-2 proof receipts.
The local credential may execute those inputs but cannot make a DENY acceptable.

## Preconditions

- `GH_TOKEN` belongs to the intended `Mindburn-Labs` administrator and has the
  existing organization-ruleset and repository-administration permissions.
- `HELM_AUTHORITY_BOOTSTRAP_OBSERVER_TOKEN` is a distinct short-lived token for
  the installed HELM authority observer App. The script rejects token reuse;
  observer reads and attestation checks never use the executor token.
- `HELM_AUTHORITY_APPROVER_TOKEN` is a third, distinct installation token for
  `helm-authority-approver`. That App has only Pull requests (write) and is
  installed only on the three public autonomous repositories. The broker
  rejects a token scoped to anything other than the single target repository
  and emits a receipt only after GitHub reads back the exact-head review from
  `helm-authority-approver[bot]`.
- The candidate pull request is open, non-draft, based on the current `.github`
  `main`, and its generation-1 permit has a signed `ALLOW` from both configured
  providers.
- `release-permit-verify` was built from the exact Kernel SHA named by the
  generation-1 authority manifest.
- The permit, Sigstore bundle, and trusted context were downloaded from the
  same GitHub Actions run.
- The output directory does not exist. Evidence directories are immutable.
- `HELM_AUTHORITY_PROMOTER_PRIVATE_KEY` and
  `HELM_AUTHORITY_APPROVER_PRIVATE_KEY`, plus their client IDs, exist only in
  the `authority-promotion` environment. Observer material exists only in
  `authority-observer`; none of these values exists at organization or
  repository Actions scope.
- Both authority environments use custom branch policies, have administrator
  bypass disabled, and currently contain zero deployment branch policies.
  This zero-admission state is required before `prepare`; do not point either
  environment at `main` or the candidate branch.
- The bootstrap administrator may change `.github` repository settings. After
  ratification, `prepare` sets `delete_branch_on_merge=false`, verifies the
  setting through both executor and observer reads, and records the transition.
  This preserves the exact candidate ref until post-merge observation and makes
  a parent-permit recovery rerun possible without human intervention.

## Close the credential environments

Before `prepare`, set the source-owned no-bypass state and delete every current
deployment branch policy from both environments. The empty custom-policy set is
intentional: no workflow can load an App key until `finalize` has locked and
independently verified the controller.

```bash
for environment in authority-observer authority-promotion; do
  gh api --method PUT \
    "repos/Mindburn-Labs/.github/environments/$environment" \
    -F wait_timer=0 \
    -F can_admins_bypass=false \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'

  gh api \
    "repos/Mindburn-Labs/.github/environments/$environment/deployment-branch-policies" \
    --jq '.branch_policies[].id' |
    while read -r policy_id; do
      gh api --method DELETE \
        "repos/Mindburn-Labs/.github/environments/$environment/deployment-branch-policies/$policy_id"
    done
done
```

Read back `can_admins_bypass=false`, `custom_branch_policies=true`, and
`total_count=0` for both environments before continuing. `prepare` repeats that
check through the executor and observer identities and fails on any drift.

## Prepare the exact transition

```bash
python3 scripts/bootstrap_authority.py prepare \
  --permit "$EVIDENCE/release-permit.json" \
  --permit-bundle "$EVIDENCE/release-permit.attestation.json" \
  --trusted-context "$EVIDENCE/context.json" \
  --kernel-repository "$WORKSPACE/helm-ai-kernel" \
  --candidate-repository "$PWD" \
  --candidate-authority config/autonomous-release-authority.json \
  --candidate-sha "$CANDIDATE_SHA" \
  --candidate-ref "refs/heads/$CANDIDATE_BRANCH" \
  --candidate-pr "$CANDIDATE_PR" \
  --control-contract config/autonomous-release-control-plane.json \
  --adversarial-corpus tests/fixtures/autonomous-release-adversarial.json \
  --bootstrap-contract config/autonomous-release-bootstrap-v1.json \
  --output-dir "$EVIDENCE/bootstrap"
```

`prepare` verifies the generation-1 ratification and independently confirms the
zero-admission, no-bypass environment state. It stages generation 2, runs and
replays all eight permanent proof cases, activates public machine enforcement,
obtains a fresh generation-2 liveness permit on the authority pull request, and
uses that permit to submit an exact-head approval from the isolated approver
App. It then installs the one-review machine interlock before retiring the two
already-covered repositories from the CODEOWNER-specific organization rule.
The `.github/main` classic one-review setting remains active and is satisfied
by the same distinct machine identity. The terminal artifact is
`bootstrap-ready.json`.

Each proof run must also contain `release-workflow-provenance`, an offline
GitHub-Sigstore marker bound to the exact candidate workflow SHA, proof head,
merge commit, run ID, and attempt. `prepare` rejects a pre-model failure without
that candidate-signed marker, including a same-head failure emitted by the
still-enforcing parent workflow.

Every model-executed proof case must also retain exactly
`release-review-anthropic` and `release-review-openai`. `prepare` and its
independent observer extract the bounded envelopes and require the exact parent
Kernel to regenerate the signed permit bytes and matching `ALLOW`/`DENY` exit
status. A missing envelope, a substituted archive entry, or any reduction
difference fails the bootstrap.

Before machine enforcement, failure restores the staged candidate pin. After
machine enforcement begins, failure leaves the machine rule active; rerun
`prepare` into a new evidence directory. Never disable that rule to recover.

## Finalize without a human decision

Run immediately after `prepare` succeeds:

```bash
python3 scripts/bootstrap_authority.py finalize \
  --permit "$EVIDENCE/release-permit.json" \
  --permit-bundle "$EVIDENCE/release-permit.attestation.json" \
  --trusted-context "$EVIDENCE/context.json" \
  --kernel-repository "$WORKSPACE/helm-ai-kernel" \
  --candidate-repository "$PWD" \
  --candidate-authority config/autonomous-release-authority.json \
  --candidate-sha "$CANDIDATE_SHA" \
  --candidate-ref "refs/heads/$CANDIDATE_BRANCH" \
  --candidate-pr "$CANDIDATE_PR" \
  --control-contract config/autonomous-release-control-plane.json \
  --adversarial-corpus tests/fixtures/autonomous-release-adversarial.json \
  --bootstrap-contract config/autonomous-release-bootstrap-v1.json \
  --ready "$EVIDENCE/bootstrap/bootstrap-ready.json" \
  --output "$EVIDENCE/bootstrap/bootstrap-final.json"
```

`finalize` re-verifies every bound digest, signed permit, and exact-head App
approval; confirms the public approval cutover remains protected by both the
workflow and machine-review interlocks; creates
`authority/control-v1` at the exact reviewed merge SHA behind a staged
update/deletion ban; adds the no-bypass creation ban; independently reads back
the ref, workflow file, active rules, and SHA; and only then adds that one
branch to both credential environments. It then atomically moves
`main` from the exact base SHA to the live PR's current GitHub-generated,
reviewed two-parent merge commit using an exact `beforeOid`/`afterOid`
compare-and-swap, and binds both rulesets to the merged `main` SHA. A stale or
regenerated PR merge fails before the update. It is safe to rerun after an exact
merge or partial ruleset finalization.

Completion requires all of the following live readbacks:

- `.github/main` equals `bootstrap-final.json`'s `merge_sha`;
- `refs/heads/authority/control-v1` equals that same reviewed merge SHA and
  contains `.github/workflows/promote-authority.yml`;
- `HELM Immutable Authority Controller` is active for only that ref in only the
  `.github` repository, has no bypass actors, and denies creation, update, and
  deletion;
- `authority-promotion` and `authority-observer` disable administrator bypass,
  have no required human reviewers, and admit only
  `authority/control-v1`;
- stable ruleset `18924515` is active, has no bypass actors, covers only the
  three proven public repository IDs, and binds the merged workflow on `main`;
- candidate ruleset `18927405` remains evaluate-only and binds the same merged
  workflow on `main`;
- the organization human rule no longer includes `.github` or
  `helm-ai-kernel`, while every private/internal repository remains present;
- `HELM Machine Approval Interlock` is active for the three public autonomous
  repository IDs, requires one non-CODEOWNER approval after the latest push,
  has no bypass actors, and resolves conversations;
- `.github/main` retains its classic one-review count and the exact candidate
  head has an approval from `helm-authority-approver[bot]`;
- private/internal rule failures remain a GitHub entitlement blocker, not a
  reason to remove their human gates.

After the final receipt is persisted and independently copied, revoke the
temporary bootstrap executor, observer, and approver installation tokens and
delete any one-time local App PEM copies. Environment-held App keys remain the
only steady-state credential copies used by Actions.
