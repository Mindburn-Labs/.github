# AGENTS.md

<!-- helm-sdlc-baseline:v1 -->
Apply the [HELM SDLC baseline](https://github.com/Mindburn-Labs/docs/blob/main/ai/sdlc.md).
Before implementation, define the outcome and observable acceptance conditions.
Use the existing tracker and isolated worktree; verify in proportion to risk with
the owning repository's checks. Bind results to the tested source and configuration.
Missing, skipped or inconclusive required checks are not passes. Report source,
CI, release, deployment, runtime and user acceptance separately; verify applicable
rollback, restoration and external-effect recovery. Use `Refs` while acceptance
work remains and `Closes` only when the whole issue is fulfilled. Preserve existing
authority boundaries and never bypass failed checks or move published tags.
<!-- /helm-sdlc-baseline -->

This repo controls organization profile and the production repository manifest.

`make lint` validates the manifest, baseline YAML, and guard scripts (plus the HELM ecosystem map when `$MINDBURN_WORKSPACE_ROOT` is set); `make test` adds the Python unit tests; `make check`, which CI runs, is `make test`. Treat `repo-manifest.yaml` as the current machine-readable GitHub org inventory, not as production deployment evidence. If it conflicts with source code, route registries, OpenAPI, release artifacts, tier config, GitOps manifests, or runtime deployment manifests, the source artifact wins.

Use `$MINDBURN_WORKSPACE_ROOT` for workspace references. Ivan's local example is `~/Code/Mindburn-Labs`; do not hardcode that path as a platform invariant.

Protected paths:

- `profile/README.md`
- `repo-manifest.yaml`
- `.github/workflows/**`

## Privileged GitHub operations

`mindburnlabs` and `peycheff-com` are Ivan's human GitHub accounts. Both must
remain Mindburn-Labs owners/admins, and agents use their full authority for
delivery.

Actions cancel, rerun, enable, disable, or dispatch; release, tag, or package
changes; production promotion; access or secret changes; and organization or
repository setting, ruleset, or App changes are agent work. Follow the
`helm-privileged-ops` procedure: confirm the exact target, read live state,
act once, read the result back from the API, and log the record. No human
approval step. Spending decisions stay with Ivan. Policy:
`docs/ai/estate-policy.md` in Mindburn-Labs/docs.
