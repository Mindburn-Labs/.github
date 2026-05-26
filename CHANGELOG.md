# Changelog: .github-repo

All notable changes to the `.github` organization configurations repository will be documented in this file.

## [1.0.1] - 2026-05-26

### Changed
- Rewrote `repo-manifest.yaml` as a reality-based post-migration inventory. The manifest now distinguishes GitHub-published repos, unpublished local target repos, target-only aliases, active transition shells, and verification blockers instead of claiming symbolic production completeness.
- Replaced hardcoded local workspace paths in organization guidance with `$MINDBURN_WORKSPACE_ROOT`, allowing `~/Code/Mindburn-Labs` only as Ivan's local example.
