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

## Evidence checkpoint

- On 2026-07-18, `svc-helm-control-plane` CI workflow `283675528` was found
  active during the Phase 1 containment sweep and immediately returned to
  `disabled_manually`. The post-containment check found zero queued and zero
  in-progress runs. This is containment evidence, not a safe CI-lane proof.
