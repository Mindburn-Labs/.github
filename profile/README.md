# Mindburn Labs, Inc.

**Models propose. HELM governs execution.**

We build HELM, the fail-closed execution authority for AI agents: every consequential agent action passes a policy boundary, returns an ALLOW / DENY / ESCALATE verdict, and leaves a signed, offline-verifiable receipt.

**No receipt, no production.**

---

### What We Build

| Product | Description | Stack | Links |
| :--- | :--- | :--- | :--- |
| **HELM AI Kernel** | Public, self-hostable execution boundary for AI agents. Fail-closed policy enforcement, MCP server quarantine, signed receipts, replayable EvidencePacks. Apache-2.0. | Go · WASM (wazero) · Ed25519 | [Repo](https://github.com/Mindburn-Labs/helm-ai-kernel) · [Docs](https://helm.docs.mindburn.org/helm-ai-kernel) |
| **HELM AI Company OS** | Reviewed-access operating layer for governed company work around the same Kernel boundary. | Go · TypeScript | [Overview](https://mindburn.org/helm/company-ai-os/) |

Company site: [mindburn.org](https://mindburn.org/) · Documentation: [helm.docs.mindburn.org](https://helm.docs.mindburn.org/) · Integration examples: [helm-agent-integrations](https://github.com/Mindburn-Labs/helm-agent-integrations)

---

### How HELM Works

```text
proposal → HELM boundary → ALLOW / DENY / ESCALATE → signed receipt → verification
```

1. **Fail-closed by default.** Unknown or unapproved actions are denied. Unknown MCP servers stay quarantined until a human approves them.
2. **Deterministic evidence.** Receipts and EvidencePacks are canonicalized with JCS (RFC 8785) + SHA-256 and signed with Ed25519, so anyone can verify them offline. Evidence is tamper-evident and replayable.
3. **Contract-first boundaries.** Public surfaces are governed by versioned schemas (OpenAPI, Protobuf, JSON Schema); changes are checked for backward compatibility.

Orchestration decides what to attempt; HELM decides what may execute.

---

### Security Posture

*   **OIDC token federation** for container publishing and cloud deployments; long-lived static credentials in repository variables are forbidden.
*   **Automated dependency and vulnerability gates** (Renovate, push protection, CodeQL) across organization repositories.
*   **Security disclosures**: see [SECURITY.md](https://github.com/Mindburn-Labs/.github/blob/main/SECURITY.md) or the live policy at [mindburn.org/security](https://mindburn.org/security/).

---

### Collaboration

Contributions to the open-source repositories (`helm-ai-kernel`, `helm-agent-integrations`) are welcome — see each repository's `CONTRIBUTING.md`. For HELM evaluation or reviewed access, use [mindburn.org/contact](https://mindburn.org/contact/).
