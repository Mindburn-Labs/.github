# Coverage Ledger: .github-repo

Generated: `2026-05-26T18:35:52.502139+00:00`

## Completed Automated Coverage

- Repository mapper completed: `True`
- Attack-surface ranking completed: `True`
- Exhaustive task queue completed: `True`
- Grep baseline completed: `True`
- Offline tool runner completed: `True`

## Ranked Surface Snapshot

| Rank | Score  | File                            | Tags                                                                                                                           |
| ---- | ------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 1    | 156.69 | profile/README.md               | entrypoint, authn/session, authz/tenant, crypto/secrets, filesystem/path, parser/decoder, secret handling, agentic-ai boundary |
| 2    | 155.83 | repo-manifest.yaml              | entrypoint, authz/tenant, crypto/secrets, filesystem/path, parser/decoder, agentic-ai boundary                                 |
| 3    | 128.6  | README.md                       | authn/session, authz/tenant, crypto/secrets, filesystem/path, parser/decoder, secret handling, agentic-ai boundary             |
| 4    | 65.32  | agent.yaml                      | agentic-ai boundary, authz/tenant, parser/decoder, secret handling                                                             |
| 5    | 64.32  | Makefile                        | deployment/config, parser/decoder, agentic-ai boundary                                                                         |
| 6    | 50.0   | AGENTS.md                       | agentic-ai boundary, authz/tenant, parser/decoder                                                                              |
| 7    | 47.46  | .github/workflows/ci.yml        | deployment/config, deployment/supply chain, authz/tenant                                                                       |
| 8    | 36.0   | .github/CODEOWNERS              | authz/tenant                                                                                                                   |
| 9    | 33.0   | CHANGELOG.md                    | authz/tenant, filesystem/path, parser/decoder                                                                                  |
| 10   | 33.0   | CODEOWNERS                      | authz/tenant, parser/decoder                                                                                                   |
| 11   | 21.0   | catalog-info.yaml               | authz/tenant                                                                                                                   |
| 12   | 18.0   | observability/alerts.yaml       | filesystem/path, parser/decoder                                                                                                |
| 13   | 16.0   | SECURITY.md                     | secret handling                                                                                                                |
| 14   | 10.0   | docs/runbook.md                 | injection/query                                                                                                                |
| 15   | 0.0    | .devcontainer/devcontainer.json |                                                                                                                                |

## Baseline Lead Categories

| Category            | Count |
| ------------------- | ----- |
| agentic-ai boundary | 34    |
| crypto              | 6     |
| filesystem/path     | 2     |

## Offline Tool Execution

| Tool | Status                               | Exit |
| ---- | ------------------------------------ | ---- |
| none | no offline applicable tools executed |      |

## Skipped Tool Examples

- `gitleaks`: binary not found: gitleaks
- `detect-secrets`: no matching project files detected
- `semgrep`: network-backed tool skipped; rerun with --allow-network if approved
- `bandit`: binary not found: bandit
- `pip-audit`: binary not found: pip-audit
- `npm-audit`: network-backed tool skipped; rerun with --allow-network if approved
- `pnpm-audit`: network-backed tool skipped; rerun with --allow-network if approved
- `yarn-audit`: network-backed tool skipped; rerun with --allow-network if approved
- `osv-scanner`: binary not found: osv-scanner
- `cargo-audit`: network-backed tool skipped; rerun with --allow-network if approved
- `govulncheck`: network-backed tool skipped; rerun with --allow-network if approved
- `gosec`: binary not found: gosec
- `brakeman`: binary not found: brakeman
- `bundle-audit`: binary not found: bundle-audit
- `composer-audit`: binary not found: composer

## Deferred Or Needs-Validation Coverage

- All heuristic leads remain `lead-needs-validation` unless later promoted into `findings.raw.json` with evidence.
- Dynamic exploit reproduction, sanitizer/fuzzer harnesses, and source patches were not executed because this run is report-only and multi-repo breadth-first.
- No vulnerability should be treated as confirmed unless it appears in `findings.deduped.json` with confirmed/high confidence and validation evidence.
