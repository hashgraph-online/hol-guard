# Command Extension Registry and Decision Floors

## Status

Accepted. This contract governs schema-v2 built-in command extensions while final decisions remain in Guard's existing policy, memory, approval, and receipt systems.

## Registry authority

The registry validates all extensions before evaluation:

- IDs, semantic versions, aliases, dependencies, conflicts, and rule ownership are deterministic and unique.
- Required extensions must come from the built-in source. Local-admin and signed managed definitions cannot claim required status.
- Aliases resolve to one canonical extension and cannot shadow another extension ID.
- Dependencies must exist and form an acyclic graph. Conflicting extensions cannot coexist.
- Matcher indexes are conservative. Recognized executable and keyword hints reduce candidate work; unknown matcher types remain always evaluated.
- Indexes select candidates only. Matchers remain the source of rule evidence, and registry order remains stable.

## Decision floor

An extension emits evidence and a minimum action. It never grants an allow or replaces workspace policy.

| Required | Severity | Rule mode | Minimum action |
| --- | --- | --- | --- |
| no | any | disabled | allow |
| no | any | monitor | monitor |
| no | any | review | review |
| no | any | enforce | block |
| no | any | required | review |
| yes | low, medium, high | any | at least review |
| yes | critical | any | block |

Additional invariants:

1. Multiple matches retain all evidence. The strongest minimum action controls; severity breaks ties.
2. A trusted built-in safe variant suppresses only evidence from its declaring rule and matched segment.
3. Required status is immutable outside built-in definitions. External configuration cannot add a safe variant to a required rule.
4. Parser uncertainty with sensitive evidence raises the minimum action to review.
5. Remembered decisions require the full security identity. They are evaluated after extension evidence and cannot weaken a required floor.
6. Workspace and managed policy may preserve or strengthen the floor. Final approval and block authority remains outside extensions.

## Compatibility

Existing action classes remain the controlling runtime classification when the compatibility detector supplies one. Structured rules add ordered evidence, unioned risks, a controlling rule ID, and a minimum action without changing policy storage or approval contracts.

Inspection exposes the floor and controlling rule for debugging. It remains side-effect-free and does not claim that final policy was evaluated.
