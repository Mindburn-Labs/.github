# ADR 0002: Commit-bound autonomous release permit

## Status

Proposed for evaluation. It is not production-promotion authority.

## Decision

Mindburn Labs will evaluate a centrally required GitHub workflow that reduces
two separately executed, distinct-provider AI reviews into one fail-closed
release permit:

- Anthropic Claude Fable 5;
- OpenAI GPT-5.6 Sol;
- exact repository, pull request, base/head/merge SHA, merge tree, complete
  context digest, workflow SHA, and Actions run binding;
- distinct-provider 2-of-2 quorum;
- a deterministic `DENY` when the reducer receives stale, duplicate, or blocking
  reviews, and a failed required check for missing or malformed evidence;
- P0-P2 findings block; P3 findings remain advisory;
- no commit-trailer, author, label, or prior-review authority;
- no long-lived model credential;
- no shell, write, URL, or memory tool access for either model;
- no `cancel-in-progress` concurrency, because GitHub ruleset workflows do not
  support that setting.

The organization ruleset must point at the wrapper workflow in
`Mindburn-Labs/.github` at `.github/workflows/ci.yml` by exact repository, path,
ref, and commit SHA. The wrapper must load its policy helpers from its own
immutable workflow SHA and pin
the Kernel verifier by exact commit SHA. Target repositories therefore cannot
replace the reviewer prompt, provider quorum, reducer, or final status. The
private `Mindburn-Labs/platform-actions` repository may expose an equivalent
reusable workflow for private consumers, but GitHub does not make private
reusable workflows available to public repositories, so it is not the
organization-wide authority source.

## Safety envelope

The input builder rejects empty changes, binary changes, symlinks, gitlinks,
Git LFS pointers, non-UTF-8 changes, changed blobs larger than 8 MiB, more than
400 changed paths, or a patch larger than 512 KiB. It verifies the
GitHub-generated merge commit has the exact event base and head as parents,
then reviews and tests that merge tree.
Oversized or unsupported work must use a dedicated review lane. Each model
executes in a separate ephemeral job. Only the strict JSON envelope and content
digests flow to the Kernel reducer.

The shared repository-gate baseline requires `make lint` and `make test`.
`make setup` and `make build` run when the target repository defines them. A
repository without a Makefile, lint target, or test target fails closed during
evaluation and must receive an explicit source-owned gate profile before
activation.

The existing `local-validation` check name and push-to-`main` validation remain
intact while the permit is evaluated. The permit records GitHub's actual
`workflow_ref` and immutable `workflow_sha`; it must not assert a task-branch
reference after the ruleset pin changes.

Every model and reducer job rechecks the downloaded context against the current
GitHub workflow SHA, run ID, and run attempt. GitHub failed-job retries may
otherwise reuse an earlier attempt's input artifact while loading a newer
ruleset workflow. Such mixed-generation retries fail closed; operators must
rerun the complete workflow so a new context is minted for the new attempt.

During evaluation the permit is scoped to measuring merge eligibility; it does
not govern merges unless the ruleset is activated after proof. It never
authorizes deployment, production promotion, migrations, key rotation, billing
changes, or any other external side effect. Those authority migrations require
their own policy, evidence, rollback, and fail-closed gates.

Claude Fable 5 is subject to GitHub's disclosed Anthropic retention behavior for
prompts and outputs used by safety classifiers. That fact must remain visible
when the model is enabled for private or internal source.

The two model jobs are separate executions and use different model providers,
but GitHub Copilot remains their shared authentication, orchestration, and
delivery control plane. Provider and model identity are workflow-bound request
parameters, not independent cryptographic attestations from Anthropic and
OpenAI. Activation therefore requires treating Copilot or Actions outage,
misrouting, malformed output, and missing-provider evidence as fail-closed
conditions rather than claiming infrastructure independence.

## No-human target architecture

Removing independent human approval does not mean giving one model or one
workflow unilateral authority. The target is a machine separation-of-powers
system:

1. A versioned **constitution** defines risk classes, evidence schemas, model
   quorum, budgets, rollout bounds, and automatic stop conditions. A candidate
   constitution is evaluated by the previously active immutable version; it
   cannot authorize itself.
2. A deterministic **planner** binds the exact desired change, current state,
   merge tree, production target, budget, and rollback to one intent digest.
3. Distinct-provider **critics** review that digest in isolated, read-only jobs.
   Higher-risk lanes add specialist critics and simulations; they never lower
   the two-provider floor.
4. The HELM Kernel **reducer** accepts only complete, current, schema-valid,
   digest-bound evidence and emits a short-lived permit. Missing, stale,
   conflicting, duplicate-provider, or malformed evidence is `DENY`.
5. A narrow GitHub App or deployment broker **executes** only the action named
   by the permit. Models never receive repository-admin, cloud-admin, billing,
   or production credentials directly.
6. Independent **observers** compare expected and actual state, enforce canary
   and error-budget limits, produce receipts, and automatically roll back or
   freeze the lane on drift. The executor cannot mint its own success receipt.

Risk changes the required evidence rather than reintroducing a person:

- reversible code and documentation: exact-tree tests, two-model quorum, merge
  queue, automatic rollback;
- data, infrastructure, auth, or public behavior: hermetic rehearsal, policy
  simulation, bounded canary, delayed expansion, two-model quorum plus a
  domain critic;
- constitution, reviewer prompt, reducer, ruleset, credential broker, or test
  harness: previous-version ratification, adversarial corpus, time delay, and
  automatic rollback to the last known-good authority bundle;
- destructive or economically unbounded actions: denied until a machine-
  enforceable blast-radius and rollback contract exists.

Before serving clients, this can run in a production-shaped development cell:
synthetic or explicitly non-customer data, isolated accounts and namespaces,
hard spend ceilings, no customer notification channels, reversible migrations,
canary traffic, immutable receipts, and an automatic freeze on any unmet SLO or
evidence invariant. This exercises the real end-to-end product without
pretending that an unbounded production environment is a safe test fixture.

Commit trailers remain metadata, not authorization. Useful provenance comes
from the GitHub actor and app identity, immutable SHAs, signed build and deploy
attestations, permit digests, and observed-effect receipts.

Constitution promotion uses two generations. Rulesets keep version N pinned
while N evaluates the complete N+1 source bundle. Only a valid N-issued permit
may advance the evaluation pin to N+1. N+1 is then exercised on a separate
non-authority pull request before it can become enforcing authority. Failed-job
retries, a branch update, or an administrator editing the pin cannot substitute
for either generation's evidence.

## Rollout

1. Publish the Kernel reducer and public organization workflow; retain the
   private reusable workflow only as a convenience for private consumers.
2. Create the organization ruleset in `evaluate` mode for `~ALL` repositories
   and default branches. Verify effective coverage with live required-workflow
   runs in public, internal, and private repositories; the organization-level
   `~ALL` selector alone is not enforcement evidence. Billing, licensing, or
   plan state that disables rules on private/internal repositories blocks
   activation.
3. Prove `ALLOW` on an exact merge tree, structured `DENY` for stale context,
   provider duplication and blocking findings, and a failed check for a missing
   reviewer, malformed response, or model outage.
4. Before activation, require strict current-base status or a merge queue, prove
   every case in `tests/fixtures/autonomous-release-adversarial.json` against
   both live model jobs, and add a protected lane for changes to workflow, gate,
   test-harness, and Kernel authority files. A target branch must not be able to
   weaken its own required commands or evidence threshold.
5. Activate the machine workflow rule only after live 2-of-2 evidence exists.
6. Then reduce the pull-request rule to zero human approvals while retaining the
   pull-request, deletion, non-fast-forward, and machine-workflow requirements.
7. Rebind the ruleset to merged `main` SHAs and retain rollback payloads.

If any proof fails, the existing human gate remains active.
