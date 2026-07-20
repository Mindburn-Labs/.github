# Changelog: .github-repo

All notable changes to the `.github` organization configurations repository will be documented in this file.

## [Unreleased]

- Added the `authority/control-v1` parent control ref, successor-only CAS lane,
  environment-scoped App credentials, zero-admission bootstrap state, no-bypass
  environment policy, and exact organization-ruleset/ref readback. The parent
  is non-creatable, non-deletable, and non-force-pushable; the separately named
  control-updater may advance only from a verified durable final receipt to an
  independently observed successor, so mutable pull-request or `main` workflows
  cannot obtain release-authority secrets.

### Changed
- Added the MIN-408 Linear release gate contract for release pipelines,
  merge-to-verification behavior, and evidence-backed `Done` transitions.
- Removed the deleted `orggenome-compiler` archive from the verified organization inventory.

## [1.0.2] - 2026-06-01

### Changed
- Rewrote `repo-manifest.yaml` as the verified GitHub organization inventory: 69 repositories, 68 active repositories, and `orggenome-compiler` archived.
- Separated repository existence from production release readiness. Production remains gated by signed release artifacts, GitOps evidence, approvals, rollback rehearsal, and soak evidence.
- Replaced hardcoded local workspace paths in organization guidance with `$MINDBURN_WORKSPACE_ROOT`, allowing `~/Code/Mindburn-Labs` only as Ivan's local example.
