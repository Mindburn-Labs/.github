# Runbook

## Local Validation

Run:

```sh
make lint
```

## Tracker Release Gates

Use `docs/tracker/release-gate-contract.md` when filing release Gate issues and
handling merge automation. PR merge leaves a release-bound issue open in Status
`In Review`; release completion with evidence is what permits the project Status
`Done` and a completed close.
Neither state transition authorizes a protected merge, deployment, or release.
Those actions require the source-owned machine authority and runtime evidence
defined by the contract. The current manifest records production promotion as
disabled and the release status as `not_released`.

## Boundaries

Do not use this repository to declare canonical product topology. Update the canonical architecture and roadmap docs first, then mirror public-facing changes here.
