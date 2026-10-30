# Tracker SLA Policy

## Objective

Define only the SLAs a four-person team can honor. Normal backlog work must not
create automatic SLA noise.

GitHub has no native SLA timers. The policy is carried by a recorded `Target date`
on the HELM Delivery project item and a saved view that lists what is due. Nothing
here assumes an automation that nags or escalates.

## Required Policies

| Work type | Tracker signal | SLA |
| --- | --- | --- |
| Security incident | Area `security` with Priority `Urgent`, and the issue states it is an incident | 24h |
| Release blocker | label `risk:release-blocker`, or a `Gate` issue carrying that label | 48h |
| R3 external-effect issue | a `Risk tier: R3` line in the Outcome block | 72h |
| R4 key-material issue | a `Risk tier: R4` line in the Outcome block | 72h |
| Normal work | all other items | no default SLA |

## How the clock works

1. The clock starts when the signal first applies: issue creation, or the moment
   the label, Area, or risk-tier line is added, whichever is later.
2. At triage, set `Target date` on the project item to the date the SLA expires
   (a 24h SLA is due the next day). Items without a targeted signal get no
   `Target date` from this policy.
3. An item meets its SLA when it reaches Status `Done`, or a written residual-risk
   or blocker note is linked on the issue before the date.
4. If the signal is removed because the classification was wrong, clear the
   `Target date` and say why in a comment.

## Admin Checklist

1. In the HELM Delivery project, create the view `SLA due`: open items with a
   `Target date`, sorted by `Target date`, grouped by Priority.
2. Create the view `Release blockers`: open items with label
   `risk:release-blocker`.
3. Confirm sample normal items carry no `Target date`.
4. Confirm one sample item per targeted row gets the expected `Target date`.

## Acceptance

The policy is in effect when:

- the `SLA due` and `Release blockers` views exist and match this table
- normal items show no SLA date
- a reviewer records at least one sample item for each targeted row

## Tooling Boundary

`gh` and the GraphQL API can read and update project items and fields, including
`Target date`. Saved project views are configured in the web UI; this document is
the policy for that setup, not the setup itself.
