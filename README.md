# Mindburn Labs Organization Repository

This repository owns the Mindburn Labs organization profile, default repository guidance, baseline metadata, and the machine-readable GitHub organization inventory.

## Canonical Inventory

The canonical inventory is `repo-manifest.yaml`.

Current verified state:

- 65 repositories in the `Mindburn-Labs` GitHub organization.
- 64 active repositories.
- `orggenome-compiler` is archived.
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

## Validation

```bash
make lint
```
