# Phase 1 CI authority and private-module boundary

**Status:** superseded on 2026-08-11 by the HELM-366 governed full-authority
decision and the current estate policy. Historical evidence below is retained.

## Supersession

`mindburnlabs` and `peycheff-com` are Ivan's human GitHub accounts and remain
organization owners/admins. Agents retain full delivery authority through
those accounts. The controlling boundary is now exact, single-use human
approval before each privileged Actions, release, production, access, secret,
or settings mutation—not account demotion, a standing containment instruction,
or automatic counter-mutation.

The current policy is `Mindburn-Labs/docs` `ai/estate-policy.md`; the canonical
operator procedure is `Mindburn-Labs/docs_for_team`
`skills/helm-privileged-ops/SKILL.md`. Linear `HELM-366` records the 2026-08-10
release cancellation/disable incident and remains open until source controls,
live state detection, separately approved recovery, release convergence, and a
clean recurrence audit are all proved. The 2026-07-18 decisions and event log
below are historical context only where they conflict with those sources.

### Scheduled detector contract

The `.github` scheduled detector is a read-only observer, not a continuous or
self-protecting control. Each run fails closed unless the credential-visible
repository set exactly matches `repo-manifest.yaml`, checks each repository's
Actions permission and workflow states, and reconciles workflow enable/disable
audit events from the source-controlled lower bound in
`config/workflow-state-policy.json`. An audit event remains a violation until a
reviewed entry ties its immutable document ID and observed fields to a durable
approval record. Manual dispatch is intentionally absent so branch-selected
workflow code cannot receive the organization read credential.

A successful run proves only the scope that run observed. Disabling this
workflow, or disabling Actions for the `.github` repository, prevents the run
that would report the change. Closing that gap requires a watchdog in a
separately administered execution domain with protected source, a least-
privilege credential able to read the organization repository inventory,
Actions permissions, workflow states, and audit log, plus a missed-heartbeat
alert for this schedule. Creating that identity, secret, execution path, or
repository setting is a privileged architecture change requiring its own exact
owner approval and authoritative readback; this source PR performs none of
those changes and does not close HELM-366 by itself.

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

## Review-gated source containment set

The following draft pull requests remove the automatic `pull_request` event
from a token-bearing workflow. They are intentionally narrow: they preserve
the existing trusted-main and manual behavior while the workflow remains
manually disabled. None is merged or evidence of a safe CI, release, or
production lane.

- `svc-helm-control-plane#194` at `32ef5e4`: Continuous Integration and Docs
  Truth.
- `svc-agent-sandbox-runner#11` at `c9d50f1`: Continuous Integration and Docs
  Truth.
- `helm-ai-kernel#607` at `34725714`: Docs Truth.
- `integration-mindburn-platform#129` at `b36b082`: Continuous Integration.
- `gitops-apps#45` at `f671ef6`: Continuous Integration.
- `gitops-platform#142` at `fb6d247`: Continuous Integration.

All six branches passed local `actionlint` and `git diff --check` before
push. A live state poll after push found every tracked P0 workflow manually
disabled. `dev-orchestration` remains contained without an additional source
patch: its current default-branch Docs Truth workflow is callable/manual only,
and the former `docs-truth-self.yml` no longer exists on that branch.
