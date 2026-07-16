# Mindburn Labs Organization Repository

This repository owns the Mindburn Labs organization profile, default repository guidance, baseline metadata, and the machine-readable GitHub organization inventory.

## Canonical Inventory

The canonical inventory is `repo-manifest.yaml`.

Current verified state:

- 43 repositories in the `Mindburn-Labs` GitHub organization.
- 43 active repositories.
- No repositories are archived.
- Production release readiness is tracked in `integration-mindburn-platform/manifests/release-candidate.yaml`.
- Final-state evidence is tracked in `integration-mindburn-platform/manifests/final-state-evidence.yaml`.

## Source Truth

Repository inventory does not prove production readiness. When there is a conflict, use this precedence:

1. Source code and route registries.
2. Generated contracts and SDKs.
3. Release manifests and signed artifacts.
4. GitOps desired state.
5. Runtime deployment evidence.
6. Runbooks and architecture docs.
7. Organization inventory.

## Operating Rules

- Keep `repo-manifest.yaml` synchronized with `gh repo list Mindburn-Labs --limit 200 --json name,isArchived,visibility,updatedAt`.
- Do not mark production released in org docs. Production status belongs in the integration release manifest and GitOps evidence.
- Do not use floating tags or mutable image references in production release evidence.
- Keep the organization profile factual, compact, and free of release claims that belong to source or GitOps repos.
- Keep retired org slugs out of tracked org-repository source; `make lint` runs the recurrence guard.

## Validation

```bash
make lint
```

Docs Truth changes have one canonical runtime source and two exact-byte
bindings. The workflows check out the runner from an immutable
`Mindburn-Labs/dev-orchestration` commit and verify its SHA-256 before
execution. `.github/scripts/docs-truth-org.rb` is a review mirror of those
bytes; `make lint` verifies the same digest and runs the mirror's self-tests.
The mirror is not a second runtime authority.

The secret-backed pull-request lane must keep candidate-controlled policy and
executable ledger data out of the trusted runner boundary. It binds the subject
to the caller repository, derives the base from the event, rejects candidate
changes to Docs Truth policy inputs, rejects generated or nonempty
`truth_gate` rows, and reports the result on the exact candidate head. A green
local run or status is evidence only; merge authority remains a separate
source-owned permit and approval-only App interlock.
