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

`.github/workflows/ci.yml` is the public, centrally bindable workflow for a
fail-closed machine quorum. It requires the exact
GitHub merge tree, deterministic repository gates, separately executed Claude
Fable 5 and GPT-5.6 Sol provider reviews, and the source-owned HELM Kernel
reducer. GitHub Copilot remains the shared control plane for both model jobs.
Every repository has an explicit digest-locked gate profile; no target-owned
fallback can weaken the required commands. Promotion requires previous-
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
Successor ratification structurally parses the candidate workflow with
Ruby/Psych into an AST-preserving projection before it evaluates authority
semantics. That preserves YAML scalar spellings (including the `on` trigger
key) and rejects duplicate keys, aliases, merge keys, and custom tags. The
previous immutable workflow is the complete parent-owned allowlist: candidate
top-level keys, triggers, permissions, absence of defaults/concurrency,
known-job graph, job execution fields, ordered steps, action SHAs, inputs,
environment, scripts, and artifact paths must all match it exactly. The only
permitted successor differences are the three declared Kernel checkout refs
and the matching `prepare` `KERNEL_SHA`. The approval chain is also modeled
explicitly: its immutable broker checkout and verifier build remain ordered,
the approval-only App action SHA and step ID are exact, and that App token has
one consumer only—the exact-head approval step. Comments, repeated text, or
an unreviewed execution surface cannot constitute authority evidence.
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
