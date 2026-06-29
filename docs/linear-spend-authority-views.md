# Spend Authority Linear View Checklist

Source issue: MIN-479. Related view catalog: MIN-458.

## Objective

Expose Mindburn Spend Authority in Linear admin views without attaching
Pilot/Titan or non-HELM market/trading scope to HELM source truth.

## Required Labels

Spend Authority issues should use these labels when applicable:

- `product:spend-authority`
- `roadmap:spend-authority`
- `rt:mindburn-spend-authority`
- `risk:financial-risk`
- `layer:spend`
- `type:spend-ledger`
- `type:spend-contract`

## View Updates

| View area | Required inclusion |
| --- | --- |
| Portfolio views | include active `product:spend-authority` and `roadmap:spend-authority` issues |
| Product views | add `Product: Spend Authority` or include Spend Authority in HELM product views with explicit boundary text |
| Risk views | include `risk:financial-risk`, spend release blockers, and legal/compliance spend contract issues |
| Release/train views | include `rt:mindburn-spend-authority` only after the release pipeline exists |
| Public-trust/docs review views | include unsafe credit-market, resale, yield, trading, and customer-proof language checks |

## Leakage Guard

Do not attach Pilot, Titan, or OrgGenome issues to Spend Authority unless the
issue explicitly says that product is a downstream HELM consumer or adapter.

Unsafe examples:

- treating Titan proof as HELM proof
- mixing Pilot operational scope into HELM Spend Authority
- describing provider credits as resale, trading, yield, marketplace, or cash redemption
- claiming customer usage from demos, fixtures, or synthetic data

## Future Issue Requirements

Future Spend Authority issues need:

- project
- owner or delegate
- source-truth path
- labels above where applicable
- due date only when scheduled
- acceptance criteria
- validation and Done gate

## Done Gate

MIN-479 can move to `Done` only when:

- the relevant Linear views visibly include Spend Authority with matching filters
- no Pilot/Titan/OrgGenome issue is incorrectly attached to Spend Authority
- release/train views include `rt:mindburn-spend-authority` only where releases are configured
- public-trust/docs review views include unsafe-language checks
- a reviewer records UI/admin verification or explicitly accepts the remaining UI limitation

## Connector Boundary

The current Linear MCP tools cannot create saved views, release views, or remove
cycle membership. This checklist defines the admin pass; it is not proof that
the Linear UI has been configured.
