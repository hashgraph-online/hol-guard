# ADR 0005: Protection Center presentation semantics

Status: Accepted for the `release/3.0` Protection Center implementation.

## Context

HOL Guard's extension-control system has security-grade canonical objects for extensions, permissions, rules, authority layers, managed policy, preview, proofs, and revisions. Those objects are appropriate for enforcement and diagnostics but impose unnecessary cognitive load when used as the default product vocabulary.

The Protection Center needs to be understandable to a first-time or low-technical user without changing any security fact.

## Decision

### User-facing naming

| Canonical/internal concept | Default user-facing concept |
|---|---|
| Extensions workspace | Protection Center |
| Extension | Protection module |
| Permission | Protection setting |
| Rule | Detection |
| Provenance | Setting source / Managed by |
| Global lockdown | Emergency Lockdown |
| Inherit | Recommended |
| Semantic blast radius | What will change |

The navigation label is **Protections**. Existing `/extensions` routes and all persisted canonical identifiers remain unchanged.

### Presentation density

The product supports three display-only densities:

- **Simple** is the default and answers status, purpose, behavior, reason, and next action.
- **Advanced** adds policy source, configurability, dependencies, and other operator context.
- **Developer** adds canonical IDs, versions, digests, matcher data, rules, permissions, CLI/API diagnostics, and other implementation details.

Density is a non-sensitive local presentation preference. It must never alter a request payload, effective policy, approval behavior, or server state.

### Canonical authority boundary

- The canonical registry and daemon are the source of security truth.
- The client may normalize and translate server-authoritative facts.
- Components must not implement a competing effective-policy resolver.
- Server preview remains authoritative for a mutation's effective result.
- Unknown or malformed security state renders non-permissively with an actionable error.

### Local and Cloud separation

Local protection status, explanations, recovery, local configuration, and local testing are not subscription-hostage features. Cloud value is continuity and scale: cross-device sync and history, retention, advanced search, alerts, evidence workflows, policy versioning, organization policy, team/agent coordination, audit, and integrations according to authoritative entitlements.

Cloud connectivity or billing state must never cause a protected local device to be labeled unprotected.

### Immutable security invariants

The presentation overhaul must not weaken:

1. immutable detector severity and baseline risk;
2. fixed and required controls;
3. signed organization policy;
4. the rule that local policy cannot weaken a managed block;
5. Emergency Lockdown dominance;
6. fail-closed authority health;
7. server-authoritative preview/apply;
8. exact one-use proof binding;
9. stale revision/catalog/authority conflict rejection;
10. direct-route authentication and secret-safe URLs;
11. foreground trust requirements for recovery;
12. installed-wheel, real-daemon verification.

### No-placeholder rule

A visible tab or primary action must complete a real flow in the current build. Later-batch functionality is hidden rather than represented by `coming soon` or non-functional controls. Existing deep links to unavailable presentation sections may redirect to the nearest functional section without changing canonical route identity.

## Consequences

The compatibility route and security model remain stable while the default UX becomes task-first. Technical data remains accessible, but it is deliberately disclosed rather than imposed on every user. Copy mappings and presentation-state mappings become tested product contracts.
