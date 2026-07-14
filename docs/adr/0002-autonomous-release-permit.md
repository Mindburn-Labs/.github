# ADR 0002: Commit-bound autonomous release permit

## Status

Proposed for evaluation. It is not production-promotion authority.

## Decision

Mindburn Labs will evaluate a centrally required GitHub workflow that reduces
two independent AI reviews into one fail-closed release permit:

- Anthropic Claude Fable 5;
- OpenAI GPT-5.6 Sol;
- exact repository, pull request, base/head SHA, workflow SHA, and Actions run
  binding;
- distinct-provider 2-of-2 quorum;
- deterministic denial for stale, missing, duplicate, malformed, or blocking
  reviews;
- P0-P2 findings block; P3 findings remain advisory;
- no commit-trailer, author, label, or prior-review authority;
- no long-lived model credential;
- no shell, write, URL, or memory tool access for either model;
- no `cancel-in-progress` concurrency, because GitHub ruleset workflows do not
  support that setting.

The organization ruleset must point at the wrapper workflow in
`Mindburn-Labs/.github` by exact repository, path, ref, and commit SHA. The
wrapper must load its policy helpers from its own immutable workflow SHA and pin
the Kernel verifier by exact commit SHA. Target repositories therefore cannot
replace the reviewer prompt, provider quorum, reducer, or final status. The
private `Mindburn-Labs/platform-actions` repository may expose an equivalent
reusable workflow for private consumers, but GitHub does not make private
reusable workflows available to public repositories, so it is not the
organization-wide authority source.

## Safety envelope

The input builder rejects empty changes, binary changes, more than 400 changed
paths, or a patch larger than 512 KiB. Oversized work must be split into
reviewable changes. Each model executes in a separate ephemeral job. Only the
strict JSON envelope and content digest flow to the Kernel reducer.

The permit governs merge eligibility only. It does not authorize deployment,
production promotion, migrations, key rotation, billing changes, or any other
external side effect. Those authority migrations require their own policy,
evidence, rollback, and fail-closed gates.

Claude Fable 5 is subject to GitHub's disclosed Anthropic retention behavior for
prompts and outputs used by safety classifiers. That fact must remain visible
when the model is enabled for private or internal source.

## Rollout

1. Publish the Kernel reducer and public organization workflow; retain the
   private reusable workflow only as a convenience for private consumers.
2. Create the organization ruleset in `evaluate` mode for `~ALL` repositories
   and default branches.
3. Prove ALLOW on an exact head SHA and DENY for stale SHA, missing reviewer,
   malformed response, provider duplication, model outage, and blocking finding.
4. Activate the machine workflow rule only after live 2-of-2 evidence exists.
5. Then reduce the pull-request rule to zero human approvals while retaining the
   pull-request, deletion, non-fast-forward, and machine-workflow requirements.
6. Rebind the ruleset to merged `main` SHAs and retain rollback payloads.

If any proof fails, the existing human gate remains active.
