# Runbook

## Local Validation

Run:

```sh
make lint
```

## Linear Release Gates

Use `docs/linear/release-gate-contract.md` when configuring Linear Releases and
merge automation. PR merge should move linked issues to `Merged/Verifying`;
release completion, with evidence, is what permits `Done`.

## Boundaries

Do not use this repository to declare canonical product topology. Update the canonical architecture and roadmap docs first, then mirror public-facing changes here.
