# Tracker Agent Guardrails

## Objective

Keep agents that read and write the tracker aligned with Mindburn's source-truth
operating model. The tracker routes work; it must not fabricate readiness,
approvals, customers, or production state.

GitHub has no workspace-level AI settings, Asks, or Customer Requests objects to
configure. These guardrails live in the instructions agents read:
`AGENTS.md` and `CLAUDE.md` at the workspace root,
`TRACKER.md` in `Mindburn-Labs/docs_for_team`, and
`agents/issue-tracker.md` in `Mindburn-Labs/docs`.

## Agent Instructions

Agent guidance must require:

1. Read the root `AGENTS.md` and `CLAUDE.md` before non-trivial work.
2. Read local project instructions before editing a repo.
3. Create a worktree for non-trivial implementation.
4. Preserve user-owned dirty state.
5. Keep HELM Kernel and Enterprise protected-boundary rules intact.
6. Treat RLM traces, comments, and handoffs as evidence only, never source truth.
7. Do not close an issue as completed or move it to `Done` without source-owned
   completion evidence.

## Routing Questions

Questions to a human collect clarification and lightweight status in issue
comments. They must not:

- approve protected-boundary work
- waive release gates
- replace source-truth evidence
- turn an `In Review` release-bound issue into `Done`

## Customer Feedback

File customer feedback only for real external customer, buyer, partner, or user
feedback, and say who it came from. Do not create feedback issues from internal
speculation, demo fixtures, synthetic personas, or market-size assumptions.

## Precedence

Agent summaries must keep these precedence rules:

1. source code and route registries
2. generated contracts and SDKs
3. release manifests and signed artifacts
4. GitOps desired state
5. runtime deployment evidence
6. runbooks and architecture docs
7. tracker comments and agent summaries

## Acceptance

The guardrails are in effect when:

- the agent instruction files above carry the instructions in this document
- one sample feedback issue and one sample agent-written closure are reviewed for
  compliance
- a reviewer records the result on the issue that adopted this change
