# ADR 0012: Fleet Extension Configuration

- **Status:** Accepted
- **Target:** `release/3.2`
- **Cloud counterpart:** `points-portal/main`

## Context

Team and Enterprise workspaces need to administer supported Extension outcomes and approved Custom Extension definitions across a continuously changing fleet. Existing Managed Controls already owns policy composition, signed delivery, atomic application, acknowledgements, rollback, and last-known-good behavior. Fleet Extension Configuration therefore extends that authority model rather than introducing a second policy system.

## Decision

1. Guard Cloud stores immutable, workspace-scoped intent and assignment objects. HOL Guard consumes only signed, device-bound projections.
2. Shared JSON contracts and frozen digest vectors are byte-identical across Cloud and Core. The manifest pins every shared file by UTF-8 byte length and SHA-256.
3. Cloud never receives raw executable paths, command lines, source, environment values, tokens, secrets, or globally correlatable local identities.
4. Portable Custom Extensions use opaque workspace identifiers and exact locally approved variant evidence. A semantic or identity change requires new approval.
5. Managed restrictive authority may only tighten supported built-in Extension or permission semantics. It cannot target Custom Extensions or silently broaden protection.
6. Unsupported or semantically mismatched runtimes are excluded. There is no semantic-loss downgrade.
7. Readers validate bounded UTF-8 payloads, reject unknown fields, normalize only documented defaults, and produce domain-separated deterministic digests.
8. Contract resources are loaded through `importlib.resources`, so installed wheels behave the same as source checkouts.
9. Later Fleet batches must compose with existing Managed Controls signed delivery, atomic apply, recovery, acknowledgement, feature-flag, and operations boundaries.

## Consequences

- Cloud and Core contract changes require synchronized review and drift verification.
- Fleet enrollment remains dynamic without republishing immutable intent.
- Local users may tighten protection but cannot weaken managed or required floors.
- Failure is explicit and privacy-safe; stale, ambiguous, unsupported, replayed, or partially applicable authority fails closed.
