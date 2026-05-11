# Mindburn Labs, Inc.

**Execution-grade infrastructure for autonomous software.**

> _You cannot mathematically regulate the latent space of a neural network._
> _But you can — and must — regulate the physics of its execution._

---

### What We Build

We build the middleware between intelligence and execution. AI models are becoming commoditized — incredibly smart, cheap, and ubiquitous. But they have zero executive authority. **AI proposes. Deterministic systems govern.**

| Product                                               | Description                                                                                                                         | Stack                    |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| **[HELM](https://github.com/Mindburn-Labs/helm-oss)** | The deterministic execution layer for the agent economy. Fail-closed policy enforcement, cryptographic receipts, replayable proofs. | Go · WASI · Ed25519      |

---

### Repositories

| Repo                                                                      | Visibility | Purpose                                                          |
| ------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------- |
| [`helm-oss`](https://github.com/Mindburn-Labs/helm-oss)                   | 🌐 Public  | HELM open-source kernel — Go core, protocols, SDK, documentation |
| [`pilot`](https://github.com/Mindburn-Labs/pilot)                         | 🌐 Public | Experimental Pilot gateway (adjacent, not HELM OSS)              |
| [`helm`](https://github.com/Mindburn-Labs/helm)                           | 🔒 Private | HELM commercial — enterprise overlays, connectors, metering      |
| [`titan`](https://github.com/Mindburn-Labs/titan)                         | 🔒 Private | Titan Trading System — bio-mimetic algorithmic trading           |
| [`mindburn`](https://github.com/Mindburn-Labs/mindburn)                   | 🔒 Private | Corporate website — [mindburn.org](https://mindburn.org)         |
| [`orggenome-compiler`](https://github.com/Mindburn-Labs/orggenome-compiler)| 🔒 Private | OrgGenome Compiler GPU clusters                                  |
| [`docs-platform`](https://github.com/Mindburn-Labs/docs-platform)         | 🔒 Private | Dedicated product documentation sites                            |
| [`mindburn-admin`](https://github.com/Mindburn-Labs/mindburn-admin)       | 🔒 Private | Private company operating system and admin infrastructure        |

---

### HELM — Open Source

HELM is the missing layer in the agent stack: deterministic policy enforcement with replayable proofs.

- **Above:** orchestration frameworks, agent UIs, tool catalogs
- **Below:** clouds, hardware, identity, payments
- **Missing:** the enforcement plane that every agentic app reuses

**Open-core model:** the kernel, ProofGraph, and EvidencePacks are OSS. Enterprise governance, certified connectors, and dispute replay are paid.

```
Models propose. HELM decides and records.
```

[![HELM](https://img.shields.io/badge/HELM-OSS-blue?style=flat-square&logo=go)](https://github.com/Mindburn-Labs/helm-oss)
[![Standard](https://img.shields.io/badge/Standard-v1.3-green?style=flat-square)](https://github.com/Mindburn-Labs/helm-oss)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://github.com/Mindburn-Labs/helm-oss/blob/main/LICENSE)

---

### How We Build

Most of what we ship gets built with AI assistance — not replacing developers, but proving that a small team can ship production-grade systems by leveraging AI the right way.
