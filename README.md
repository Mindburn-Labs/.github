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

### Current status: P0 hold; shadow evidence only

No machine merge, ruleset activation, deployment, or credentialed promotion is
currently authorized from this repository. Same-repository pull requests still
execute candidate workflow code before any later `workflow_run` broker. In
particular, `.github/workflows/docs-truth.yml` passes
`MINDBURN_ORG_READ_TOKEN` to a local reusable workflow resolved from that
candidate commit. That is a credential-boundary P0, not a safe automation
path. The source routes credentialed promotion through an explicit
`workflow_dispatch` controller on `authority/control-v1`, rather than a
`workflow_run`; its live controller lock and environment policy are still
unverified and must not be treated as active authority.

`.github/workflows/authority-broker.yml` is deliberately a read-only, default-
branch **shadow** experiment. It fetches exact Git objects into a bare store,
does not check out or execute candidate content, and compares the complete
candidate workflow tree with the immutable parent. Its short-retention artifact
is diagnostic only: it cannot approve, merge, alter rulesets, deploy, mint an
App token, or activate authority. It also does not prove that candidate
Makefiles, scripts, dependencies, configurations, artifacts, or the legacy CI
lane are safe. No workflow consumes its artifact as a promotion predicate.
Because the controller is dispatched during the permit workflow while this
broker starts only after that workflow completes, shadow evidence may arrive
after controller work. If the pull request closes or `main` advances first, the
broker deliberately withholds trusted shadow evidence rather than treating a
default-branch run whose source may include the candidate as trusted. It is not
a sequencing, hold, cancel, or authorization control.

Before any future transition, a separately operated GitHub administration
incident path must pause and investigate candidate and authority-controller
execution, revoke or rotate the repository-wide docs token, prove candidate
paths cannot request protected
environment capabilities with a controlled negative run, and preserve
private/internal human gates. A successful next-generation permit can
automatically request a dispatch of the immutable controller; that request is
not proof of credential isolation, merge authority, ruleset activation,
deployment, or P0 closure. A shadow artifact has no authorization effect.

### Target design (not current release authority)

`.github/workflows/ci.yml` contains the proposed public, centrally bindable
workflow for a fail-closed machine quorum. The design requires the exact
GitHub merge tree, deterministic repository gates, separately executed Claude
Fable 5 and GPT-5.6 Sol provider reviews, and the source-owned HELM Kernel
reducer. GitHub Copilot remains the shared control plane for both model jobs.
Every repository has an explicit digest-locked gate profile; no target-owned
fallback can weaken the required commands. The proposed promotion protocol would
require previous-
generation ratification, all seven permanent attacks plus one inert ALLOW
canary, independent evidence replay, an exact compare-and-swap merge, and final
ruleset readback. A separate approval-only GitHub App converts the signed ALLOW
into an exact-head review; it has no contents, Actions, ruleset, or deployment
authority. The merge token and ruleset-admin App key never coexist in one job.
Every adversarial proof run carries an offline GitHub-Sigstore marker bound to
the exact candidate workflow SHA and run, so a concurrent parent-workflow
failure cannot satisfy candidate evidence.
Both the promoter and independent observer download the exact two raw provider
review envelopes and require the immutable parent Kernel to reproduce the
candidate's `ALLOW` or `DENY` permit byte for byte; a candidate-authored summary
cannot stand in for reduction evidence.
The permit workflow has no App secret. It dispatches promotion only for an
exact next-generation authority change, and the secret-bearing transaction can
run only from the permanently locked `authority/control-v1` workflow ref.
Organization rules deny creation, update, and deletion of that ref with no
bypass actors. Both authority environments disable administrator bypass and
admit only that ref, so neither a pull request nor mutable `main` can load the
promoter, observer, or approver credentials.
Credentialed jobs also bind the pinned token action's live App slug and
installation ID before use; the approval broker independently checks exact
repository scope and the persisted GitHub review actor.

The enforcing rule is intentionally public-only while GitHub's paid
private/internal required-workflow entitlement returns an upgrade error.
Private/internal human approvals remain in place. This code-merge authority is
not deployment, customer-production, billing, or migration authority; those
effects require separate bounded permits and receipts.

## Validation

```bash
make test
```
