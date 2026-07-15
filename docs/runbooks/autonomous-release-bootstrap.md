# Generation-1 release-authority bootstrap

This runbook is valid only for the transition from authority generation 1 to
generation 2. Later generations are promoted by
`.github/workflows/promote-authority.yml`.

The bootstrap is not a human approval. The only approval inputs are the exact
generation-1 signed 2-of-2 permit and the fresh generation-2 proof receipts.
The local credential may execute those inputs but cannot make a DENY acceptable.

## P0 stop: external containment required

Do not run `prepare` or `finalize` while any candidate-controlled
`pull_request` or `workflow_run` path can reach a repository secret,
write-capable App token, or protected environment capability. This runbook does
not close that condition and does not activate authority. In the current state,
the repository-wide docs token is passed to candidate-controlled local reusable
workflow source, and the legacy promotion path remains outside the new
read-only shadow broker.

The shadow broker is diagnostic evidence only. Its bare-Git workflow-tree
comparison does not make candidate CI, candidate scripts, artifacts, or
configuration trusted; it cannot approve, merge, alter rulesets, deploy, or
start this runbook. A PR success, signed `ALLOW`, or shadow artifact is never
an automatic invocation.

## Preconditions

- A separately operated GitHub administration incident path has paused and
  investigated legacy authority execution, inspected prior runs and artifacts,
  and revoked or rotated `MINDBURN_ORG_READ_TOKEN` away from candidate workflow
  access.
- Any future App key, installation scope, environment, ruleset, and
  required-workflow entitlement is provisioned outside candidate code. A
  controlled negative run has proven candidate branches cannot request the
  protected environment capability; an undeclared environment reference is not
  accepted as proof either way.
- Independent live readback records the exact GitHub settings above, and
  private/internal human gates remain intact. The shadow broker has no
  authorization consumer until a later, separately reviewed migration binds
  these receipts.
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
- The bootstrap administrator may change `.github` repository settings. After
  ratification, `prepare` sets `delete_branch_on_merge=false`, verifies the
  setting through both executor and observer reads, and records the transition.
  This preserves the exact candidate ref until post-merge observation and makes
  a parent-permit recovery rerun possible without human intervention.

## Prepare the exact transition

```bash
python3 scripts/bootstrap_authority.py prepare \
  --permit "$EVIDENCE/release-permit.json" \
  --permit-bundle "$EVIDENCE/release-permit.attestation.json" \
  --trusted-context "$EVIDENCE/context.json" \
  --permit-verifier "$EVIDENCE/release-permit-verify" \
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

`prepare` verifies the generation-1 ratification, stages generation 2, runs and
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

## Finalize by explicit external-admin invocation (not automatic)

Only after the P0 containment evidence, `prepare` evidence, and a deliberate
external administrator invocation are all present, run:

```bash
python3 scripts/bootstrap_authority.py finalize \
  --permit "$EVIDENCE/release-permit.json" \
  --permit-bundle "$EVIDENCE/release-permit.attestation.json" \
  --trusted-context "$EVIDENCE/context.json" \
  --permit-verifier "$EVIDENCE/release-permit-verify" \
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

"Not automatic" does not make the permit a human approval: it distinguishes a
deliberate incident/bootstrap invocation from an unsafe side effect of a PR,
`ALLOW`, or shadow run. `finalize` re-verifies every bound digest, signed permit, and exact-head App
approval; confirms the public approval cutover remains protected by both the
workflow and machine-review interlocks; atomically moves
`main` from the exact base SHA to the live PR's current GitHub-generated,
reviewed two-parent merge commit using an exact `beforeOid`/`afterOid`
compare-and-swap, and binds both rulesets to the merged `main` SHA. A stale or
regenerated PR merge fails before the update. It is safe to rerun after an exact
merge or partial ruleset finalization.

Completion requires all of the following live readbacks:

- `.github/main` equals `bootstrap-final.json`'s `merge_sha`;
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
