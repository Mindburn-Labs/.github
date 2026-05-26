# Mindburn Labs, Inc.

**Execution-grade infrastructure for autonomous software.**

> _You cannot mathematically regulate the latent space of a neural network._
> _But you can — and must — regulate the physics of its execution._

---

### What We Build

We build the middleware between intelligence and execution. AI models are becoming commoditized — incredibly smart, cheap, and ubiquitous. But they have zero executive authority. **AI proposes. Deterministic systems govern.**

| Product                                               | Description                                                                                                                         | Stack                    |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| **[HELM](https://github.com/Mindburn-Labs/helm-ai-kernel)** | The deterministic execution layer for the agent economy. Fail-closed policy enforcement, cryptographic receipts, replayable proofs. | Go · WASI · Ed25519      |

---

### Repositories

Mindburn Labs has approved and locally executed a layered polyrepo topology, but publication and verification are not complete. The current architecture and audit artifacts live under `$MINDBURN_WORKSPACE_ROOT/docs/architecture/`, `$MINDBURN_WORKSPACE_ROOT/docs/migration/`, and `$MINDBURN_WORKSPACE_ROOT/integration-mindburn-platform/`. Ivan's local example is `~/Code/Mindburn-Labs`.

Implementation reality wins: source code, route registries, OpenAPI, generated SDKs, release artifacts, tier config, GitOps manifests, and runtime deployment manifests override narrative docs. Local target repos that are not present in the GitHub organization are blockers, not production-ready repos.

| Repo                                                                      | Visibility | Purpose                                                          |
| ------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------- |
| [`helm-ai-kernel`](https://github.com/Mindburn-Labs/helm-ai-kernel)                    | 🌐 Public  | HELM AI Kernel — Go core, protocols, SDK, documentation          |
| [`pilot`](https://github.com/Mindburn-Labs/pilot)                                      | 🌐 Public  | Experimental Pilot gateway (adjacent, not HELM AI Kernel)        |
| [`helm-ai-enterprise`](https://github.com/Mindburn-Labs/helm-ai-enterprise)            | 🔒 Private | HELM AI Enterprise — enterprise overlays, connectors, metering   |
| [`titan`](https://github.com/Mindburn-Labs/titan)                         | 🔒 Private | Titan Trading System — bio-mimetic algorithmic trading           |
| [`mindburn`](https://github.com/Mindburn-Labs/mindburn)                   | 🔒 Private | Corporate website — [mindburn.org](https://mindburn.org)         |
| [`orggenome-compiler`](https://github.com/Mindburn-Labs/orggenome-compiler)| 🔒 Private | OrgGenome Compiler GPU clusters                                  |
| [`docs-platform`](https://github.com/Mindburn-Labs/docs-platform)         | 🔒 Private | Dedicated product documentation sites                            |
| [`mindburn-admin`](https://github.com/Mindburn-Labs/mindburn-admin)       | 🔒 Private | Private company operating system and admin infrastructure        |

---

### HELM AI Kernel — Open Source

HELM is the missing layer in the agent stack: deterministic policy enforcement with replayable proofs.

- **Above:** orchestration frameworks, agent UIs, tool catalogs
- **Below:** clouds, hardware, identity, payments
- **Missing:** the enforcement plane that every agentic app reuses

**Open-core model:** the kernel, ProofGraph, and EvidencePacks are open source (HELM AI Kernel). Enterprise governance, certified connectors, and dispute replay are commercial (HELM AI Enterprise).

```
Models propose. HELM decides and records.
```

[![HELM AI Kernel](https://img.shields.io/badge/HELM_AI_Kernel-Open_Source-blue?style=flat-square&logo=go)](https://github.com/Mindburn-Labs/helm-ai-kernel)
[![Standard](https://img.shields.io/badge/Standard-v1.3-green?style=flat-square)](https://github.com/Mindburn-Labs/helm-ai-kernel)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://github.com/Mindburn-Labs/helm-ai-kernel/blob/main/LICENSE)

---

### How We Build

Most of what we ship gets built with AI assistance — not replacing developers, but proving that a small team can ship production-grade systems by leveraging AI the right way.
