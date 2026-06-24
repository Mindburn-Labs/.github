# Linear View Catalog

Source issue: MIN-458.

## Objective

Define the saved Linear views that make the workspace usable as a roadmap
execution ledger. This document is the setup contract for Linear UI/admin work;
it is not proof that the views are already configured.

## Portfolio Views

| View | Filter intent |
| --- | --- |
| `Portfolio: Active Projects` | active projects and non-canceled issues grouped by project |
| `Portfolio: At Risk` | active projects or issues with blocked, at-risk, off-track, or release-blocker signals |
| `Release Blockers` | issues labeled `risk:release-blocker` or `type:release-gate` that are not Done |
| `Protected Boundary` | issues labeled `risk:protected-boundary`, `helm:kernel`, `helm:enterprise`, or `helm:boundary-sync` |

## Agent Views

| View | Filter intent |
| --- | --- |
| `Agent Ready` | active issues labeled `agent:codex-ready` or otherwise ready for delegated implementation |
| `Codex Active` | active issues delegated to Codex, excluding Kirill-owned work |
| `Claude Review` | active issues labeled for Claude/review handoff |
| `Needs Human Decision` | active issues labeled `agent:needs-human-decision` |
| `Merged / Verifying` | issues in `Merged/Verifying` status |
| `Projectless Triage` | triage issues without a project |
| `Invalid Source / No-Go` | issues in `Invalid Source/No-Go` or labeled `truth:invalid-source` |

## Product Views

| View | Filter intent |
| --- | --- |
| `Product: HELM` | HELM product labels including kernel, enterprise, launchpad, evidencepack, and boundary-sync |
| `Product: Titan` | Titan product labels only; do not treat Titan proof as HELM proof |
| `Product: Pilot` | Pilot product labels only |
| `Product: OrgGenome` | OrgGenome compiler, inference, and serving labels |
| `Product: Mindburn Platform` | platform, infra, GitOps, public site, and docs-platform labels |

## Risk Views

| View | Filter intent |
| --- | --- |
| `Risk: Protected Boundary` | protected-boundary and kernel/enterprise boundary-sync issues |
| `Risk: Release Blocker` | release blockers and release gates |
| `Risk: R3 External Effect` | issues labeled or templated as R3 external-effect work |
| `Risk: R4 Key Material` | issues labeled or templated as R4 key-material work |
| `Risk: Compliance` | compliance, legal, audit, FRIA, and evidence-retention work |
| `Risk: Security Incident` | security incident template or security-incident labels |
| `Risk: Invalid Source / No-Go` | invalid-source, no-go, duplicate, canceled, or truth-conflict review queues |

## Done Gate

MIN-458 can move to `Done` only when:

- each required view exists in Linear
- each view filter matches this catalog
- a reviewer verifies sample membership for each category
- views do not mix Pilot/Titan/OrgGenome proof into HELM source truth

## Connector Boundary

The current Linear MCP issue tools can update issues and comments. They cannot
create or verify saved workspace views. This catalog defines the view contract
for a Linear UI/admin pass.
