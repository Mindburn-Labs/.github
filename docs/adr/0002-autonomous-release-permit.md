# ADR 0002: Commit-bound autonomous release permit

## Status

Accepted for controlled public-repository code-merge authority. Runtime
enforcement remains a GitHub ruleset fact, not a documentation claim. Private
and internal repositories retain their human approval gate until GitHub
restores the paid required-workflow entitlement that the organization is
already billed for. This decision does not authorize customer production,
deployment, billing, data migration, or other external effects.

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
replace the reviewer prompt, provider quorum, reducer, or final status. Model
jobs also receive a sparse, read-only checkout of the exact pinned Kernel
source and tests, so a safety-critical reducer is inspectable evidence rather
than an opaque external commit hash. The private
`Mindburn-Labs/platform-actions` repository may expose an equivalent
reusable workflow for private consumers, but GitHub does not make private
reusable workflows available to public repositories, so it is not the
organization-wide authority source.

## Safety envelope

The input builder rejects empty changes, binary changes, symlinks, gitlinks,
Git LFS pointers, non-UTF-8 changes, changed blobs larger than 8 MiB, more than
400 changed paths, or a patch larger than 512 KiB. It verifies the
GitHub-generated merge commit has the exact event base and head as parents,
then reviews and tests that merge tree.
When the target is the workflow authority repository itself, both the input
builder and Kernel reject a context whose workflow SHA equals the target head
or merge SHA. Version N may evaluate N+1; N+1 cannot evaluate itself.
Oversized or unsupported work must use a dedicated review lane. Each model
executes in a separate ephemeral job. Only the strict JSON envelope and content
digests flow to the Kernel reducer.

Every admitted repository has an explicit source-owned gate profile. There is
no command-discovery or Makefile fallback. The profile names an exact command
vector and SHA-256 digests for every build file that can alter those commands;
missing, changed, non-regular, or symlinked protected files fail before either
model runs. Authority-critical profile changes use the same two-generation
ratification rule as workflow changes.

Every context also binds `config/autonomous-release-authority.json`. The
manifest names a monotonically increasing generation, the exact Kernel SHA,
the SHA-256 digests of the central gate profiles and adversarial corpus, and
the immediately preceding workflow generation. Generation 1 is the explicit
bootstrap; every later generation must name exactly generation N-1 and cannot
name its own workflow SHA as its parent.

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

Permit attestations use GitHub's private Sigstore instance. Required-workflow
runs expose the authority workflow as an absolute URI, while GitHub's
repository persistence endpoint currently compares it with a
repository-relative identity and rejects the otherwise valid certificate. The
integrity-locked signer therefore requests the same GitHub OIDC certificate,
constructs the DSSE bundle locally, and never calls the persistence endpoint.
It uploads the signed Sigstore bundle beside the permit instead.
Consumers verify that exact offline bundle and still require the signer
workflow, signer digest, source digest, and GitHub-hosted runner policy.

Constitution promotion uses two generations. Rulesets keep version N pinned
while N evaluates the complete N+1 source bundle. Only a valid N-issued permit
may advance the evaluation pin to N+1. N+1 is then exercised on a separate
non-authority pull request before it can become enforcing authority. Failed-job
retries, a branch update, or an administrator editing the pin cannot substitute
for either generation's evidence.

Every candidate proof run independently emits a GitHub-OIDC-signed workflow
provenance marker binding the target repository, candidate workflow SHA, head,
synthetic merge commit, run ID, and run attempt. A `PRE_MODEL_REJECT` case is
accepted only when that marker verifies against N+1's exact signer digest. This
prevents a concurrent failure from the still-enforcing N workflow from being
misclassified as candidate evidence.

The model protocol treats the public-development decision to remove human
code-review authorization as an authorized policy input, not as an automatic
finding. Reviewers must instead find concrete failures in the replacement
machine controls or expansion beyond code-merge scope. The protocol also
distinguishes code ratification from live activation: patch-only reviewers
inspect the complete candidate and pinned reducer, while bootstrap and
promotion independently verify Apps, environments, rulesets, ETags, receipts,
and rollback state before any authority changes.

Steady-state GitHub App tokens are minted only by
`actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1`.
That immutable action's `action.yml` defines `client-id` and deprecates the
legacy `app-id` input. Every credentialed job checks the action's live
`app-slug` and `installation-id` outputs against its source-owned App identity
before using the token. The approval broker additionally requires the exact
single-target token scope (the App itself is installed on only the three public
autonomous repositories) and confirms the persisted review author before
emitting a receipt.

The steady-state promotion transaction is deliberately split across isolated
jobs and three GitHub Apps. The approval-only App turns a signed ALLOW into an
exact-head review but cannot read or write contents. The promoter can advance
and restore exact ruleset bindings and run a permanent seven-attack plus
one-ALLOW suite, but cannot write repository contents. A separate job with no
App secret advances `main` only with an exact `beforeOid`/`afterOid`
compare-and-swap to GitHub's reviewed two-parent merge commit. A later promoter
job rebinds only the evaluation ruleset. A separate observer
re-downloads both permits from their originating runs, verifies their GitHub
attestations with the exact previous-generation Kernel, compares the merged
tree and pull request with GitHub state, and reads back both rulesets. The
candidate Kernel executes only inside its isolated evaluation workflow; no
candidate binary is ever run in a job holding promoter or observer credentials.
Only an attested observer `ALLOW` lets a later promoter job activate the stable
ruleset. A second observer produces the final success receipt. Any incomplete
promotion restores both rulesets to version N. After `main` advances, the exact
merge SHA is admitted only as a recovery input proving that state transition;
it is never a forward recovery target. The merged code may remain ahead while
enforcing authority stays at the last fully observed generation. Any automated
repair must obtain a fresh N-issued permit; recovery evidence cannot authorize
activation and no human approval is introduced. This deliberately favors
safety over liveness. The executor therefore cannot mint its own success
receipt.

GitHub's organization-ruleset API has two provider constraints that the broker
must not conceal. Organization-ruleset `GET` requires the same organization
Administration (write) permission as `PUT`, so the observer uses a separate App
identity and an immutable GET-only code path even though GitHub over-grants its
installation token. The mutation broker requires an ETag on every ruleset GET,
re-reads the exact body and ETag, sends that value in `If-Match`, rejects HTTP
412, and performs an exact read-back. A missing ETag is a fail-closed error.

Generation 1 is a one-time source-owned bootstrap because the promotion
workflow cannot trigger from a file that is not yet on the default branch.
`scripts/bootstrap_authority.py` is split into `prepare` and `finalize` phases:

1. verify the generation-1 dual-model ALLOW, GitHub Sigstore provenance,
   trusted context, exact candidate tree, and live environment contract;
2. stage generation 2 in evaluation mode and freshly execute all eight
   permanent proof cases;
3. independently reverify the same signed case artifacts byte-for-byte;
4. activate the machine rule for only the three proven public repositories;
5. trigger and verify a fresh generation-2 ALLOW on the authority pull request;
6. use the signed liveness permit to submit an exact-head review from the
   isolated approval-only App, activate a one-review machine interlock for the
   three public repositories, and only then retire `.github` and Kernel from
   the CODEOWNER-specific organization rule; the `.github` classic one-review
   setting remains active; and
7. reverify the ready receipt, atomically advance `main` to the exact liveness
   merge commit, then bind both machine rulesets to that merged `main` SHA.

If failure occurs before machine enforcement, the staged candidate pin is
compensated to generation 1. After machine enforcement begins, recovery leaves
the public machine gate active and resumes from evidence; it never restores an
unprotected state. The bootstrap credential executes an already signed plan
but is not an approval identity.

## Rollout

1. Publish the Kernel reducer and public organization workflow; retain the
   private reusable workflow only as a convenience for private consumers.
2. Keep the candidate ruleset in `evaluate` mode for the selected proof repos.
   Verify effective coverage with live required-workflow runs. Because GitHub
   currently returns an upgrade error for paid private/internal rule suites,
   the enforcing stable rule is explicitly scoped to the three proven public
   repositories; private/internal human gates remain unchanged.
3. Prove `ALLOW` on an exact merge tree, structured `DENY` for stale context,
   provider duplication and blocking findings, and a failed check for a missing
   reviewer, malformed response, or model outage.
4. Before activation, require strict current-base status or a merge queue, prove
   every case in `tests/fixtures/autonomous-release-adversarial.json` against
   both live model jobs, and add a protected lane for changes to workflow, gate,
   test-harness, and Kernel authority files. A target branch must not be able to
   weaken its own required commands or evidence threshold.
5. Activate the machine workflow rule only after live 2-of-2 evidence and the
   complete permanent adversarial suite exist.
6. Then remove human approval requirements only for repositories already under
   the active machine rule. Preserve deletion, non-fast-forward, conversation,
   and machine-workflow requirements.
7. Rebind the ruleset to merged `main` SHAs and retain rollback payloads.

If any proof fails, the existing human gate remains active.
