# Runbook

## Local Validation

Run:

```sh
make lint
```

## Linear Release Gates

Use `docs/linear/release-gate-contract.md` when configuring Linear Releases and
merge automation. PR merge may move linked issues to `Merged/Verifying`;
release completion with evidence is what permits the **Linear status** `Done`.
Neither state transition authorizes a protected merge, deployment, or release.
Those actions require the source-owned machine authority and runtime evidence
defined by the contract. The current manifest records production promotion as
disabled and the release status as `not_released`.

## Boundaries

Do not use this repository to declare canonical product topology. Update the canonical architecture and roadmap docs first, then mirror public-facing changes here.
