# Linear Project Status Cadence

Source issue: MIN-411.

## Objective

Every active project should have a current, source-backed Linear status update
or a documented reason no update exists. Status updates must report evidence and
blockers without inflating readiness claims.

## Cadence

- Weekly window: Friday 14:00-15:00 UTC.
- Update all active projects before the window closes.
- If a project has no meaningful movement, post that explicitly instead of
  inventing progress.
- If a project is blocked on admin access, secret access, review, merge, deploy,
  or production evidence, mark it `atRisk` or `offTrack`.

## Update Template

Each status update must include:

```md
Health: onTrack | atRisk | offTrack

Evidence:
- Source-owned artifact, PR, release, test, deployment, or runtime proof.

Blockers:
- Current blocker or "none".

Next proof path:
- The next action that would make the project state more true.

Claim boundary:
- What this update does not prove.
```

## Claim Rules

Project updates must not claim:

- production readiness without runtime or release evidence
- security closure without finding lifecycle evidence or an EvidencePack
- customer availability from demos, fixtures, or synthetic data
- `Done` from PR merge alone

## Done Gate

This issue can move to `Done` only when:

- project status updates are enabled in Linear admin/UI
- every active project has a current update or documented no-update reason
- updates include health, evidence, blockers, and next proof path
- no update overstates production, readiness, security, or customer truth

## Connector Boundary

The current Linear MCP tools can create project status updates. They cannot
prove the workspace/project admin setting is enabled, enforce the weekly
cadence, or safely infer every project's health without a separate audit.
