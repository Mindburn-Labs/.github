# AGENTS.md

This repo controls organization profile and the production repository manifest.

Run `make lint` before edits when the command exists. Treat `repo-manifest.yaml` as the current machine-readable GitHub org inventory, not as production deployment evidence. If it conflicts with source code, route registries, OpenAPI, release artifacts, tier config, GitOps manifests, or runtime deployment manifests, the source artifact wins.

Use `$MINDBURN_WORKSPACE_ROOT` for workspace references. Ivan's local example is `~/Code/Mindburn-Labs`; do not hardcode that path as a platform invariant.

## SHA-pinned release permit sources

When a workflow ruleset is pinned solely by SHA, GitHub emits `github.workflow_ref` as `<repository>/<path>@<workflow_sha>`. The input normalizer and kernel verifier must accept this form only when the suffix exactly matches the validated `workflow_sha`; never restore a mutable `ref` for compatibility. Changes require matching- and mismatching-SHA regression tests plus a runtime permit check.

Protected paths:

- `profile/README.md`
- `repo-manifest.yaml`
- `.github/workflows/**`
