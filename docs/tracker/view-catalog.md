# Tracker View Catalog

## Objective

Define the saved HELM Delivery project views that make the project usable as a
roadmap execution ledger. This document is the setup contract for the web UI; it
is not proof that the views are already configured.

Views use the project's fields (Status, Priority, Track, Area), issue types, and
the labels `area:*`, `risk:release-blocker`, `agent:needs-human-decision`, and
`wayfinder:*`.

## Portfolio Views

| View | Filter intent |
| --- | --- |
| `Board by Status` | board layout grouped by Status, open and recently closed items |
| `Active by Track` | open items grouped by Track |
| `At Risk` | open items that are `Urgent`, labeled `risk:release-blocker`, or blocked by an open issue |
| `Release Blockers` | open items labeled `risk:release-blocker` or of type `Gate` that are not `Done` |

## Agent Views

| View | Filter intent |
| --- | --- |
| `Triage` | Status `Triage` |
| `Ready for Agents` | Status `Todo`, no `agent:needs-human-decision` label, no standing `Agent claim:` comment |
| `Needs Human Decision` | open items labeled `agent:needs-human-decision` |
| `In Review` | Status `In Review`, including merged PRs awaiting verification |
| `Wayfinder` | open items labeled `wayfinder:*`, grouped by parent |
| `Closed Without Work` | items closed as `not planned` or `duplicate`, for review of no-go and duplicate decisions |

## Area Views

| View | Filter intent |
| --- | --- |
| `Area: Security` | Area `security`, open |
| `Area: Kernel and Contracts` | Area `kernel` or `contracts`, open |
| `Area: Console and Company AI OS` | Area `console` or `company-ai-os`, open |
| `Area: Connectors and Platform` | Area `connectors` or `platform`, open |
| `Area: Docs (public truth)` | Area `docs-public` or type `Docs`, open |

## Acceptance

The catalog is in effect when:

- each required view exists in HELM Delivery
- each view filter matches this catalog
- a reviewer verifies sample membership for each category
- views do not mix OrgGenome proof into HELM source truth

## Tooling Boundary

`gh` and the GraphQL API can read and update items and fields. They are not
assumed to create or verify saved views; this catalog defines the view contract
for a web UI pass.
