# AGENTS.md

This repo controls organization profile and the production repository manifest.

`make lint` validates the manifest, baseline YAML, and guard scripts (plus the HELM ecosystem map when `$MINDBURN_WORKSPACE_ROOT` is set); `make test` adds the Python unit tests. Treat `repo-manifest.yaml` as the current machine-readable GitHub org inventory, not as production deployment evidence. If it conflicts with source code, route registries, OpenAPI, release artifacts, tier config, GitOps manifests, or runtime deployment manifests, the source artifact wins.

Use `$MINDBURN_WORKSPACE_ROOT` for workspace references. Ivan's local example is `~/Code/Mindburn-Labs`; do not hardcode that path as a platform invariant.

Protected paths:

- `profile/README.md`
- `repo-manifest.yaml`
- `.github/workflows/**`

## Privileged GitHub operations

`mindburnlabs` and `peycheff-com` are Ivan's human GitHub accounts. Both must
remain Mindburn-Labs owners/admins, and agents may use their full authority for
delivery. Credential capability is not human approval.

Before any Actions cancel, force-cancel, rerun, enable, disable, or dispatch;
release, tag, or package mutation; production promotion; access or secret
change; or organization/repository setting, ruleset, or App change, load
`helm-privileged-ops` and stop for its exact single-use approval packet. An
instruction to continue, finish, ship, or resolve an incident is not approval
for any privileged effect or retry. A source PR never authorizes the operation
it describes.
