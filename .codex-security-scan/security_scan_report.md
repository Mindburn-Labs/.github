# Security Scan Report: .github-repo

Generated: `2026-05-26T18:35:52.576702+00:00`

## Scope And Mode

- Repository: `/Users/ivan/Code/Mindburn-Labs/.github-repo`
- Mode: Exhaustive Mythos
- Remediation: report-only
- Network-backed scanners: skipped

## Result

No confirmed vulnerabilities were promoted in this automated report-only pass.

That does not mean the repository is vulnerability-free. The run created ranked surfaces, hunt tasks, offline tool outputs, and lead queues for follow-up validation.

## Metrics

- Files inventoried: `17`
- Ranked files: `17`
- Hunt tasks: `41`
- Heuristic leads: `42`
- Offline tools executed: `0`
- Offline tools skipped: `19`

## Top Ranked Surfaces

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

## Lead Categories

| Category            | Count |
| ------------------- | ----- |
| agentic-ai boundary | 34    |
| crypto              | 6     |
| filesystem/path     | 2     |

## Artifact Links

- `repo_map.json`
- `attack_surface_ranked.json`
- `task_queue.json`
- `baseline_grep_findings.json`
- `tool_runs/tool_run_summary.json`
- `threat_model.md`
- `coverage.md`
- `validation_log.md`
- `patch_plan.md`
- `findings.raw.json`
- `findings.deduped.json`
- `findings_report.md`

## Residual Risk

- Baseline leads require manual reachability and exploitability validation before reporting as vulnerabilities.
- Dynamic tests, fuzzing, local exploit reproductions, and source patches were intentionally not performed in this breadth-first report-only run.
