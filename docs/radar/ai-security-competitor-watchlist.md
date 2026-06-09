# AI Security Competitor Watchlist

Source: Mindburn Labs Strategic Radar, MIN-491.

This watchlist operationalizes the 2026-06-08 AI security competitor
intelligence report as a monthly radar input. It is not HELM source truth, does
not prove product readiness, and does not replace Kernel, Enterprise,
control-plane, Console, GitOps, or release evidence.

## Monthly Refresh Contract

Run once per calendar month, or sooner when a listed competitor launches a
material execution-authority, agent-security, or enterprise-control-plane
capability.

Order of review:

1. Straiker
2. Native
3. Tenzai
4. Gray Swan
5. Jazz

Record every refresh as a dated note or Linear comment on MIN-491 until a
dedicated radar tracker is available.

## Source Gap Checklist

For each competitor, record `found`, `not found`, or `not checked` for every
source class below. Do not collapse missing evidence into a positive claim.

| Source class | Required evidence to capture |
| --- | --- |
| Case studies | Customer names, deployment scope, dated claims, and whether the source is first-party or third-party. |
| Conferences | Talk title, event, date, speaker, abstract, and whether slides or video are available. |
| Hiring | Role title, location, seniority, team, listed product surface, and posting date. |
| Marketplace listings | Platform, listing URL, launch date, integration category, and stated permissions or data access. |
| Product launches | Release date, announced capability, affected category, pricing or packaging signal, and source URL. |

## Competitor Lanes

### Straiker

Default priority because the 2026-06-08 report treats Straiker as the closest
runtime agent-security competitor pressure. Track launches and proof language
first, then map each finding to HELM Kernel, Enterprise, Console, or public
positioning surfaces.

Required classification:

- Does the claim describe runtime agent protection, testing, monitoring, or
  execution authority?
- Does the source show signed receipts, offline-verifiable evidence, or only
  dashboard/report language?
- Does the claim pressure HELM Kernel proof paths, Enterprise reviewer flows,
  or public category positioning?

### Native

Track cloud-control and enterprise-context claims as downstream control-plane
pressure only. Native-style adapters must remain context-only unless source
repos implement HELM execution authority.

Required classification:

- Cloud-control context
- Downstream policy or posture input
- Execution authority claim
- Connector or marketplace signal

### Tenzai

Track exploit-chain, red-team, and agent-security test evidence as upstream
finding inputs. Tenzai-style findings may feed CompanyArtifactGraph or
ProofGraph inputs only after source-owned intake models exist.

Required classification:

- External finding source
- ProofGraph input candidate
- Policy regression evidence candidate
- Standalone pentest or eval claim

### Gray Swan

Track model and agent evaluation claims as eval pressure, not HELM execution
authority. Gray Swan-style evidence can inform conformance cases only when
mapped to deterministic HELM verdict, receipt, and replay expectations.

Required classification:

- Eval benchmark
- Model-safety filter
- Agent behavior test
- HELM conformance candidate

### Jazz

Track DLP, data-risk, and insider-risk claims as context or downstream control
pressure. Jazz-style evidence does not replace HELM policy decisions,
receipts, or EvidencePacks.

Required classification:

- DLP context
- Insider data-risk context
- Downstream control-plane signal
- Execution-blocking claim

## Output Template

Use this compact packet for each monthly refresh.

```md
## AI security competitor watchlist refresh: YYYY-MM

Report source: 2026-06-08 AI security competitor intelligence report
Linear: MIN-491

### Straiker
- Case studies:
- Conferences:
- Hiring:
- Marketplace listings:
- Product launches:
- HELM pressure:
- Source gaps:

### Native
- Case studies:
- Conferences:
- Hiring:
- Marketplace listings:
- Product launches:
- HELM pressure:
- Source gaps:

### Tenzai
- Case studies:
- Conferences:
- Hiring:
- Marketplace listings:
- Product launches:
- HELM pressure:
- Source gaps:

### Gray Swan
- Case studies:
- Conferences:
- Hiring:
- Marketplace listings:
- Product launches:
- HELM pressure:
- Source gaps:

### Jazz
- Case studies:
- Conferences:
- Hiring:
- Marketplace listings:
- Product launches:
- HELM pressure:
- Source gaps:
```

## Done Gate

A refresh is complete only when it names source-owned evidence or explicitly
marks a source class as `not found` or `not checked`. Linear backlog state is
secondary to source truth.
