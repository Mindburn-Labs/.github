# Changelog: .github-repo

All notable changes to the `.github` organization configurations repository will be documented in this file.

## [Unreleased]

### Changed
- Bound concurrent docs-truth ledger contracts to an expiring source PR head and exact added path instead of trusting a free-text exemption.
- Added the MIN-408 Linear release gate contract for release pipelines,
  merge-to-verification behavior, and evidence-backed `Done` transitions.
- Removed the deleted `orggenome-compiler` archive from the verified organization inventory.
- Dropped the 14 repositories deleted on 2026-10-01 (HELM-900: `app-developer-portal`,
  `contracts-autonomous-release-canary`, `contracts-autonomous-release-lab`, `demo-repository`,
  `helm-compiler-lab`, `integration-ai-flows`, `orggenome-compiler`, `platform-agent-capabilities`,
  `platform-mcp-registry`, `platform-policies`, `platform-templates`, `svc-agent-control-plane`,
  `svc-high-risk-loop-bridge`, `worker-helm-launch-worker`) from `repo-manifest.yaml`, recorded them
  under `deleted_repositories`, and removed them from `manifest-local-policy.yaml` and the
  ecosystem-map name lists.

## [1.0.2] - 2026-06-01

### Changed
- Rewrote `repo-manifest.yaml` as the verified GitHub organization inventory: 69 repositories, 68 active repositories, and `orggenome-compiler` archived.
- Separated repository existence from production release readiness. Production remains gated by signed release artifacts, GitOps evidence, approvals, rollback rehearsal, and soak evidence.
- Replaced hardcoded local workspace paths in organization guidance with `$MINDBURN_WORKSPACE_ROOT`, allowing `~/Code/Mindburn-Labs` only as Ivan's local example.
