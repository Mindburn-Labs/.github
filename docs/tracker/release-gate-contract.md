# Tracker Release Gate Contract

## Objective

`Done` on a release-bound issue means a verified release is complete. A merged
pull request alone is not enough.

## Required Release Gates

Each release key has a `Gate` issue in `Mindburn-Labs/helm-tracker`. The issues
that ship in a release are its sub-issues, or are linked from its body. The Gate
issue closes as completed only with verification evidence.

| Release key | Gate subject | Source evidence |
| --- | --- | --- |
| `helm-ai-kernel` | HELM AI Kernel | kernel release artifact, pinned image/chart, EvidencePack |
| `helm-enterprise` | HELM Enterprise | enterprise boundary sync, validation report, EvidencePack |
| `app-mindburn-web-site` | Mindburn public site | build artifact, deploy URL, production smoke |
| `compiler-serving` | Compiler serving | model card, serving health, evaluation report |

## Status Handling

GitHub Projects has no Merged/Verifying state; use Status `In Review` for it.

1. A PR for a release-bound issue uses `Refs #N`, not `Closes #N`, so merging does
   not close the issue.
2. When the PR merges, set the issue's Status to `In Review`. It stays open while
   verification is pending.
3. When the release completes and verification evidence is attached or linked on
   the Gate issue, close the included issues as completed and set Status `Done`.
4. If verification is missing, failed, or waived, the issue stays open in
   `In Review` and the release note records the risk.
5. `Done` is allowed only for issues included in a completed release or for
   non-release work with explicit source-owned completion evidence.

## Machine Authority Boundary

The tracker is a delivery-record system. Its issues, project automation, linked
evidence, and status changes do **not** authorize a pull-request merge,
deployment, or production release. The same boundary applies to a draft or green
PR, CI, DCO, a human review, `/review`, `/ultrareview`, labels, identity, and
commit trailers: they may be required evidence, but none is merge or release
authority by itself.

The 2-of-2 model-review release permit and its `helm-authority-*` App interlock
were retired; releases follow the agent-delivery model
(`docs/architecture/agent-delivery.md` in Mindburn-Labs/docs). A release requires
its manifest/GitOps, immutable artifact, deployment, smoke, rollback, and
EvidencePack evidence; the tracker cannot substitute for any of those receipts.

## Release Note Minimum

Each release note must include:

- release key and version or deployment id
- linked issues
- validation commands or CI runs
- runtime smoke evidence where applicable
- skipped checks, waivers, and residual risk
- rollback path or reason rollback is not applicable

## Admin Setup Checklist

- Open one `Gate` issue per release key above, using the HELM release or contract
  gate form.
- Keep release completion manual: closing the Gate issue and its included issues
  is a human or agent action after the evidence is read, not an automation.
- Review the first release under each key before relying on any project workflow
  that moves items to `Done`.

## Non-Goals

- This document does not configure GitHub by itself.
- This repository is not release evidence.
- Tracker state, automation, and attached evidence never approve a protected
  merge, deployment, or release.
- Do not move production, security, or protected-boundary issues to `Done` based
  only on GitHub merge state.
