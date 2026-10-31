# Mindburn Labs Organization Repository

This repository owns the Mindburn Labs organization profile, default repository guidance, baseline metadata, and the machine-readable GitHub organization inventory.

## Canonical Inventory

The canonical inventory is `repo-manifest.yaml`.

The inventory covers every repository in the GitHub organization, including
separate products and tooling. Product scope does not exclude an existing
repository from the inventory.

<!-- BEGIN GENERATED REPOSITORY INVENTORY -->
46 repositories: 46 active, 0 archived; 8 public, 36 private, 2 internal.

Public repositories: `.github`, `cycleseal`, `distillscan`, `gatescan`, `helm-agent-integrations`, `helm-ai-kernel`, `homebrew-tap`, `platform-actions`.

Internal repositories: `docs_for_team`, `tg-knowledge-scraper`.
<!-- END GENERATED REPOSITORY INVENTORY -->

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

- Reconcile the per-repository entries with `gh repo list Mindburn-Labs --limit 300 --json name,isArchived,visibility,updatedAt`; inventory reconciliation never changes live visibility.
- Derive summary and count blocks with `ruby scripts/generate-repo-inventory.rb --write`. `make check` rejects summary or README drift.
- Include `--docs-root <docs-checkout>` to regenerate and check topology and the current estate-plan inventory blocks. Pass `--github-json <readback.json>` to require exact agreement with a saved GitHub readback before generating or checking.
- Historical survey tables retain their original counts; generated current-inventory blocks supersede them for current repository totals.
- Do not mark production released in org docs. Production status belongs in the integration release manifest and GitOps evidence.
- Do not use floating tags or mutable image references in production release evidence.
- Keep the organization profile factual, compact, and free of release claims that belong to source or GitOps repos.
- Keep retired org slugs out of tracked org-repository source; `make lint` runs the recurrence guard.

## CI

`.github/workflows/ci.yml` calls
`Mindburn-Labs/platform-actions/.github/workflows/ci.yml@v2` like every other
repository; the required check is `ci / gate`.

## Validation

```bash
make check
```
