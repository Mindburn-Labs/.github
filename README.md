# Mindburn Labs Organization Repository

This repository owns the Mindburn Labs organization profile, default repository guidance, baseline metadata, and the machine-readable GitHub organization inventory.

## Repository inventory

The totals below summarize the checked-in [repository manifest](repo-manifest.yaml).
Use the [inventory drift check](#inventory-drift) to compare it with GitHub.

<!-- BEGIN GENERATED REPOSITORY INVENTORY -->
48 repositories: 48 active, 0 archived; 8 public, 38 private, 2 internal.

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

## Inventory drift

Compare the manifest against a saved GitHub readback from an account with
access to the organization inventory.

```sh
gh repo list Mindburn-Labs --limit 300 --json name,isArchived,visibility > readback.json
ruby scripts/generate-repo-inventory.rb --check --github-json readback.json
```

## Operating rules

- Derive summary and count blocks with `ruby scripts/generate-repo-inventory.rb --write`. `make check` rejects summary or README drift.
- Include `--docs-root <docs-checkout>` to regenerate and check topology and the current estate-plan inventory blocks.
- Historical survey tables retain their original counts.
- Do not mark production released in org docs. Production status belongs in the integration release manifest and GitOps evidence.
- Do not use floating tags or mutable image references in production release evidence.
- Keep the organization profile factual, compact, and free of release claims that belong to source or GitOps repos.
- Keep retired org slugs out of tracked org-repository source; `make lint` runs the recurrence guard.

## CI

The [CI workflow](.github/workflows/ci.yml) runs this repository’s `make check`
through the shared `platform-actions` workflow. The required check is `ci / gate`.

## Validation

```bash
make check
```
