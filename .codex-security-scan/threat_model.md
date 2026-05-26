# Threat Model: .github-repo

Generated: `2026-05-26T18:35:52.501969+00:00`

## Scope

- Repository: `/Users/ivan/Code/Mindburn-Labs/.github-repo`
- Mode: Exhaustive Mythos, report-only
- Network-backed scanners: not run
- Source mutations: not allowed by this run

## Repository Shape

- Inventoried files: `17`
- Dependency manifests: `0`
- Config/deployment files: `2`
- Generated hunt tasks: `41`

## Dominant Languages

- `Other`: 10
- `YAML`: 5
- `JSON`: 2

## Entry Points And Boundaries

- `profile/README.md`: entrypoint, authn/session, authz/tenant, crypto/secrets, filesystem/path, parser/decoder, secret handling, agentic-ai boundary
- `repo-manifest.yaml`: entrypoint, authz/tenant, crypto/secrets, filesystem/path, parser/decoder, agentic-ai boundary

## High-Value Assets And Security Decisions

- `authz/tenant`: 10 ranked files/tasks
- `parser/decoder`: 9 ranked files/tasks
- `agentic-ai boundary`: 6 ranked files/tasks
- `filesystem/path`: 5 ranked files/tasks
- `secret handling`: 4 ranked files/tasks
- `crypto/secrets`: 3 ranked files/tasks
- `entrypoint`: 2 ranked files/tasks
- `authn/session`: 2 ranked files/tasks
- `deployment/config`: 2 ranked files/tasks
- `deployment/supply chain`: 1 ranked files/tasks
- `injection/query`: 1 ranked files/tasks

## Assumptions

- Findings require local reproduction, deterministic static reachability, or manual validation before being treated as confirmed vulnerabilities.
- Baseline grep and offline tool hits are leads only and are preserved in artifacts for follow-up.
- Report-only mode records remediation guidance but does not patch source files.
