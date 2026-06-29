# Linear Workspace Admin Guardrails

Source issue: MIN-410.

## Objective

Configure Linear AI/Agents, Asks, Customer Requests, and personalization around
Mindburn's source-truth operating model. These settings must help route work;
they must not fabricate readiness, approvals, customers, or production state.

## Agent Instructions

Workspace agent guidance must require:

1. Read the root `AGENTS.md` and `CLAUDE.md` before non-trivial work.
2. Read local project instructions before editing a repo.
3. Create a worktree for non-trivial implementation.
4. Preserve user-owned dirty state.
5. Keep HELM Kernel and Enterprise protected-boundary rules intact.
6. Treat RLM traces, comments, and handoffs as evidence only, never source
   truth.
7. Do not move issues to `Done` without source-owned completion evidence.

## Asks

Asks can collect routing questions, clarification, and lightweight status.
They must not:

- approve protected-boundary work
- waive release gates
- replace source-truth evidence
- convert `Merged/Verifying` into `Done`

## Customer Requests

Use Customer Requests only for real external customer, buyer, partner, or user
feedback. Do not create customer requests from internal speculation, demo
fixtures, synthetic personas, or market-size assumptions.

## Personalization

Workspace personalization may improve routing and summaries, but it must keep
these precedence rules:

1. source code and route registries
2. generated contracts and SDKs
3. release manifests and signed artifacts
4. GitOps desired state
5. runtime deployment evidence
6. runbooks and architecture docs
7. Linear comments and agent summaries

## Done Gate

This issue can move to `Done` only after:

- Linear workspace AI/Agents settings include the agent instructions above
- Asks and Customer Requests are configured with the boundaries above
- one sample Ask and one sample Customer Request are reviewed for compliance
- a reviewer records the applied settings or screenshots in Linear

## Connector Boundary

The current Linear MCP issue tools can edit issues, comments, labels, and links.
They cannot configure workspace AI/Agents, Asks, Customer Requests, or
personalization settings. This document is the source-truth guardrail for the
admin setup; it is not the setup itself.
