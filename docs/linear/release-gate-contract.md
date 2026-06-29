# Linear Release Gate Contract

Source issue: MIN-408.

## Objective

Linear `Done` means a verified release is complete. A merged pull request alone
is not enough.

## Required Release Pipelines

| Pipeline | Release key | Source evidence |
| --- | --- | --- |
| HELM AI Kernel | `helm-ai-kernel` | kernel release artifact, pinned image/chart, EvidencePack |
| HELM Enterprise | `helm-enterprise` | enterprise boundary sync, validation report, EvidencePack |
| Titan | `titan` | Titan release manifest, deployment proof, smoke evidence |
| Pilot | `pilot` | Pilot release manifest, deployment proof, smoke evidence |
| Mindburn public site | `app-mindburn-web-site` | build artifact, deploy URL, production smoke |
| Compiler serving | `compiler-serving` | model card, serving health, evaluation report |

## Status Automation

Configure Linear Releases and workflow automation with these rules:

1. A linked PR merge moves the issue to `Merged/Verifying`.
2. A release completion moves included issues to `Done` only after verification
   evidence is attached or linked.
3. If release verification is missing, failed, or waived, the issue remains
   `Merged/Verifying` and the release note records the risk.
4. `Done` is allowed only for issues included in a completed release or for
   non-release work with explicit source-owned completion evidence.

## Release Note Minimum

Each release note must include:

- release key and version or deployment id
- linked issues
- validation commands or CI runs
- runtime smoke evidence where applicable
- skipped checks, waivers, and residual risk
- rollback path or reason rollback is not applicable

## Admin Setup Checklist

- Create the six Linear release pipelines above.
- Add automation: PR merge -> `Merged/Verifying`.
- Add automation: verified release completion -> `Done`.
- Keep release completion manual if Linear cannot test evidence links directly.
- Review the first release in each pipeline before enabling unattended moves to
  `Done`.

## Non-Goals

- This document does not configure Linear by itself.
- This repository is not release evidence.
- Do not move production, security, or protected-boundary issues to `Done`
  based only on GitHub merge state.
