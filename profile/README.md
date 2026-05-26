# Mindburn Labs, Inc.

**infrastructure for deterministic software execution.**

---

### What We Build

We build production-grade middleware for deterministic policy verification, high-integrity transaction execution, and strict cryptographic audit logging.

| Core Engine | Description | Primary Stack | Repository |
| :--- | :--- | :--- | :--- |
| **HELM** | The deterministic execution layer for the agent economy. Fail-closed policy enforcement, cryptographic receipts, replayable proofs. | Go · WASI · Ed25519 | [🌐 helm-ai-kernel](https://github.com/Mindburn-Labs/helm-ai-kernel) |
| **Pilot** | The open-source autonomous founder operating system core for workflow orchestration and capabilities execution. | Python · TypeScript | [🌐 pilot](https://github.com/Mindburn-Labs/pilot) |

---

### Core Architecture Principles

To enable absolute sovereignty and deterministic execution, our software engineering processes strictly adhere to three architectural pillars:

1.  **Decoupled & Contract-First Interface Design**
    All system boundaries are governed by explicit, backward-compatible API definitions. Communication is strictly structured through statically validated REST (OpenAPI), Event-Driven (AsyncAPI NATS), and Protobuf (Buf Connect) schemas.
    
2.  **Fail-Closed Policy Enforcement**
    Security is not advisory; it is compile-time and runtime-enforced. Inter-process communication and task execution route through sandboxed enclaves (WASI runtimes) with strict execution boundaries and real-time cryptographic audit logging.
    
3.  **Stateless Determinism & Replayability**
    Computations must yield mathematically identical outcomes regardless of the environment. Every execution step is verified, signed, and packaged into tamper-proof proof graphs for historical audit compliance.

---

### Zero-Trust Secure SDLC

All organization repositories operate under a **zero-trust security architecture**:
*   **OIDC Token Federation**: Direct, passwordless OpenID Connect federation is used for container publishing and cloud deployments.
*   **Zero Static Keys**: Storing long-lived cloud credentials or environment tokens in repository variables is **strictly forbidden**. All secrets route dynamically through secure cloud brokers.
*   **Vulnerability Gates**: Continuous automated dependency updates (Dependabot/Renovate) and automatic Push Protection are enabled across all repositories.

---

### Collaboration & Support

*   **Contributing**: We welcome developers and researchers to contribute to our open-source repositories (`helm-ai-kernel` and `pilot`). Please refer to each repository's local `CONTRIBUTING.md` for specific onboarding and licensing details.
*   **Security Disclosures**: Please report potential security vulnerabilities to our engineering team following the instructions in [SECURITY.md](https://github.com/Mindburn-Labs/.github/blob/main/SECURITY.md).
