# Generation-1 release-authority bootstrap

This runbook is valid only for the transition from authority generation 1 to
generation 2. Later generations are promoted by
`.github/workflows/promote-authority.yml`.

The bootstrap is not a human approval. The only approval inputs are the exact
generation-1 signed 2-of-2 permit and the fresh generation-2 proof receipts.
The local credential may execute those inputs but cannot make a DENY acceptable.

## Preconditions

- `GH_TOKEN` belongs to the intended `Mindburn-Labs` administrator and has the
  existing organization-ruleset and repository-administration permissions.
- `HELM_AUTHORITY_BOOTSTRAP_OBSERVER_TOKEN` is a distinct short-lived token for
  the installed HELM authority observer App. The script rejects token reuse;
  observer reads and attestation checks never use the executor token.
- The candidate pull request is open, non-draft, based on the current `.github`
  `main`, and its generation-1 permit has a signed `ALLOW` from both configured
  providers.
- `release-permit-verify` was built from the exact Kernel SHA named by the
  generation-1 authority manifest.
- The permit, Sigstore bundle, and trusted context were downloaded from the
  same GitHub Actions run.
- The output directory does not exist. Evidence directories are immutable.

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
then removes only the already-covered public human approval gates. Its terminal
artifact is `bootstrap-ready.json`.

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

`finalize` re-verifies every bound digest and signed permit, confirms the human
gate removal is still protected by active machine enforcement, atomically moves
`main` from the exact base SHA to the exact reviewed two-parent merge commit,
and binds both rulesets to the merged `main` SHA. It is safe to rerun after an
exact merge or partial ruleset finalization.

Completion requires all of the following live readbacks:

- `.github/main` equals `bootstrap-final.json`'s `merge_sha`;
- stable ruleset `18924515` is active, has no bypass actors, covers only the
  three proven public repository IDs, and binds the merged workflow on `main`;
- candidate ruleset `18927405` remains evaluate-only and binds the same merged
  workflow on `main`;
- the organization human rule no longer includes `.github` or
  `helm-ai-kernel`, while every private/internal repository remains present;
- `.github/main` has no classic required-review count;
- private/internal rule failures remain a GitHub entitlement blocker, not a
  reason to remove their human gates.
