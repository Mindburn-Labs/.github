# Mindburn Labs Organization Repository

This repository owns the Mindburn Labs organization profile, default repository guidance, baseline metadata, and the machine-readable GitHub organization inventory.

## Canonical Inventory

The canonical inventory is `repo-manifest.yaml`.

Current verified state:

- 48 repositories in the `Mindburn-Labs` GitHub organization.
- 47 active repositories.
- 1 repository is archived.
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

## Autonomous Release Permit

`.github/workflows/ci.yml` is the public, centrally bindable workflow for a
fail-closed machine quorum. It requires the exact
GitHub merge tree, deterministic repository gates, separately executed Claude
Fable 5 and GPT-5.6 Sol provider reviews, and the source-owned HELM Kernel
reducer. GitHub Copilot remains the shared control plane for both model jobs.
Every repository has an explicit digest-locked gate profile; no target-owned
fallback can weaken the required commands. Promotion requires previous-
generation ratification, all seven permanent attacks plus one inert ALLOW
canary, independent evidence replay, an exact compare-and-swap merge, and final
ruleset readback. A separate approval-only GitHub App converts the signed ALLOW
into an exact-head review; it has no contents, Actions, ruleset, or deployment
authority. The merge token and ruleset-admin App key never coexist in one job.

The enforcing rule is intentionally public-only while GitHub's paid
private/internal required-workflow entitlement returns an upgrade error.
Private/internal human approvals remain in place. This code-merge authority is
not deployment, customer-production, billing, or migration authority; those
effects require separate bounded permits and receipts.

## Validation

```bash
make test
```
