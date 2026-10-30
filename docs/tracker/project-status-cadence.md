# Tracker Project Status Cadence

## Objective

The HELM Delivery project carries a current, source-backed status update, with a
section for each active Track, or a documented reason no update exists. Status
updates must report evidence and blockers without inflating readiness claims.

## Cadence

- Weekly window: Friday 14:00-15:00 UTC.
- Post one GitHub Projects status update on HELM Delivery before the window
  closes. Give each active Track its own section.
- If a Track has no meaningful movement, say so explicitly instead of inventing
  progress.
- If a Track is blocked on admin access, secret access, review, merge, deploy, or
  production evidence, set the project status to `At risk` or `Off track`.

## Update Template

Each status update must include:

```md
Status: On track | At risk | Off track

Track: <name>
Evidence:
- Source-owned artifact, PR, release, test, deployment, or runtime proof.

Blockers:
- Current blocker or "none".

Next proof path:
- The next action that would make the Track state more true.

Claim boundary:
- What this update does not prove.
```

## Claim Rules

Project updates must not claim:

- production readiness without runtime or release evidence
- security closure without finding lifecycle evidence or an EvidencePack
- customer availability from demos, fixtures, or synthetic data
- `Done` from PR merge alone

## Acceptance

The cadence is in effect when:

- every active Track has a current update section or a documented no-update reason
- updates include status, evidence, blockers, and next proof path
- no update overstates production, readiness, security, or customer truth

## Tooling Boundary

`gh` and the GraphQL API can read project items and fields. Whether a status
update was posted on time, and its status value, are read from the project's
status updates; nothing here enforces the cadence or infers a Track's health
without a separate audit.
