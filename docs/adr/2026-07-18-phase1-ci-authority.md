# Phase 1 CI authority and private-module boundary

**Status:** owner-approved on 2026-07-18; implementation remains review-gated.

## Decision

1. Keep the protected P0 workflows manually disabled. Do not re-enable any of
   them until an unprivileged pull-request lane, an immutable trusted-broker
   identity, and passing positive and negative canaries exist.
2. Candidate pull-request workflows must use `pull_request`, receive no
   secrets or broker tokens, and never execute candidate code through
   `pull_request_target`.
3. A dedicated least-privilege GitHub App is the intended trusted broker for
   default-branch and release lanes. An organization owner must create or
   nominate that identity; this decision does not create, install, or grant it.
4. `platform-agent-substrate` must become a versioned, immutable,
   integrity-verifiable distribution. Its consumer must remove the local
   sibling `replace` only after a digest-pinned trusted lane and a
   no-credential candidate lane are proven. Do not restore sibling-repository
   read credentials to make Control Plane CI pass.
5. Direct Linear OAuth is approved for delivery tracking. It may be restored
   only through the normal MCP OAuth flow; browser/UI workarounds remain out
   of bounds.

## Consequences

- Current authority and containment pull requests remain draft and unmerged.
- No deployment, publication, release tag, or workflow re-enable follows from
  this document.
- Control Plane dependency-lock work is evidence-only until the module
  distribution and trust lanes above are live-proven.

## Owner authorization checkpoint

- On 2026-07-18, the owner approved the recommended secure remediation path.
  That approval records the intended direction; it does not itself enable a
  contained workflow, merge a pull request, deploy or publish, or grant,
  copy, reveal, or rotate a credential.
- The GitHub App or other trusted-broker identity, its repository scope, and
  any secret-management action remain normal owner-admin changes. Source-owned
  CI work resumes only after their immutable identity and permission evidence,
  followed by the versioned module and no-credential canaries, are available.

## Evidence checkpoint

- On 2026-07-18, `svc-helm-control-plane` CI workflow `283675528` was found
  active during the Phase 1 containment sweep and immediately returned to
  `disabled_manually`. The post-containment check found zero queued and zero
  in-progress runs. This is containment evidence, not a safe CI-lane proof.
- At 17:49Z the same workflow reactivated and started candidate PR run
  `29654669183` (`az/admin-staff-email-domain`,
  `7ca56992f42279facc5cc6dc1521288e4fc73ee4`). The monitor manually disabled
  the workflow and canceled the run; it completed `cancelled` at 17:52:38Z
  with zero queued or in-progress runs and no uploaded artifacts.
- The canceled `preflight-checks` job had already completed its dependency
  token verification and both sibling-repository checkout steps. Cancellation
  therefore does **not** prove non-exposure. The owner decision is to review
  GitHub audit/run evidence and rotate or revoke the potentially exposed
  cross-repository read secret through the approved secret-management path
  after dependency-impact review. This monitor did not read, create, expose,
  or rotate any credential, and the workflow remains disabled.
- GitHub audit evidence identifies human org/repository admin `Hirama` (not
  Actions) as the actor for repeated `workflows.enable_workflow` actions on
  workflow `283675528` at 14:42:52Z, 17:49:09Z, and 17:53:25Z. The latter two
  reactivations occurred during containment and admitted further runs through
  18:20Z. The two retained run records (`29655570053` and `29655674784`) also
  completed dependency-token verification and both sibling checkouts before
  cancellation; neither uploaded artifacts. Audit data provides no reason or
  client origin. The owner decision is to identify and halt this enable path;
  if it cannot be stopped, review the actor's workflow-enable authority
  through the normal admin process, while preserving manual disable. This
  monitor made no access-control or account mutation.
- At 20:34:52Z the audit log recorded another enable action by
  `peycheff-com`. At 20:39Z the monitor found workflow `283675528` active and
  returned it to `disabled_manually` with zero queued and zero in-progress
  runs. Five runs from the active window completed successfully:
  `29655008227`, `29655016274`, `29655321084`, `29655570053`, and
  `29655674784`. Their `preflight-checks` jobs completed the dependency-token
  verification and both sibling-repository checkout steps. This proves the
  candidate credential path executed; it does not prove credential
  exfiltration. The owner must preserve the audit/run evidence, halt the
  enable path, and perform approved secret-impact review before any credential
  retirement or replacement. The workflow remains manually disabled.
- Owner attribution clarification: `peycheff-com` is Ivan's core-team GitHub
  account. This is owner-side workflow-state drift rather than an unknown
  external actor; it does not make the candidate credential path safe or
  authorize re-enabling the workflow.
- At 20:44:44Z the same owner account enabled the workflow again. The monitor
  found it active before any queued or in-progress run and restored
  `disabled_manually`. No new run record was created during that short window.
  This is not GitHub `concurrency` cancellation behavior; it is repeated
  owner-side workflow-state drift and must be stopped at its source rather
  than countered by an auto-enable or retry workflow.
- At 21:36Z a live workflow-state poll again found `283675528` active. The
  monitor immediately restored `disabled_manually`; a follow-up query found
  zero queued and zero in-progress runs. The latest admitted runs included
  successful push run `29661391187` for `b098f44830d9c9dc74b873fcba1548420624cdc8`
  and successful pull-request run `29661358781` for
  `44206473a5d9b1ebcd40e8341047cac94d580721`. This confirms that the
  automatic candidate path remains executable whenever workflow state drifts;
  it does not identify the actor or make those successful runs merge, release,
  or production proof.
