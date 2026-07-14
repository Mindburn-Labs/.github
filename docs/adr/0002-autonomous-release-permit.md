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

## Rollout

1. Publish the Kernel reducer and public organization workflow; retain the
   private reusable workflow only as a convenience for private consumers.
2. Create the organization ruleset in `evaluate` mode for `~ALL` repositories
   and default branches.
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
