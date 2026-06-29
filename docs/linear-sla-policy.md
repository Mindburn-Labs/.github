# Linear SLA Policy

Source issue: MIN-409.

## Objective

Configure only the SLAs a four-person team can honor. Normal backlog work must
not create automatic SLA noise.

## Required Policies

| Work type | Linear signal | SLA |
| --- | --- | --- |
| Security incident | `Security Incident` template or security incident label | 24h |
| Release blocker | `risk:release-blocker` or release-gate label | 48h |
| R3 external-effect issue | R3/protected-boundary label or issue template field | 72h |
| R4 key-material issue | R4/key-material label or issue template field | 72h |
| Normal work | all other backlog items | no default SLA |

## Admin Checklist

1. Disable any workspace-wide SLA that applies to normal backlog items.
2. Create targeted SLA policies for the four rows above.
3. Confirm sample normal issues have no SLA breach timer unless they have a due
   date.
4. Confirm one sample issue per targeted policy receives the expected timer.
5. Keep `agent:needs-human-decision` on this issue until Linear admin settings
   are applied in the UI or an admin-capable connector exists.

## Done Gate

This issue can move to `Done` only when:

- the Linear SLA settings match the policy table
- normal backlog items do not receive noisy SLA timers
- a reviewer records at least one sample issue for each targeted SLA

## Connector Boundary

The current Linear MCP issue tools can edit issues, comments, labels, and links.
They cannot configure workspace SLA policy administration. This document is the
source-truth policy for the admin setup; it is not the setup itself.
