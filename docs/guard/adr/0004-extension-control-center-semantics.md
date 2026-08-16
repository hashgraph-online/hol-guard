# ADR 0004: Extension Control Center semantics

- Status: Accepted
- Date: 2026-08-09
- Scope: Guard local command extension inspection and policy control

## Context

Guard already has three distinct concepts that the dashboard must not collapse into a single toggle:

1. **Extension**: a broad capability boundary that owns command action classes, stable rules, and independently controllable permissions.
2. **Permission**: a canonical capability identifier that may govern one or more rules and carries configurability, relationship, risk-tier, and baseline-floor metadata.
3. **Rule**: a stable detector identity whose matcher, severity, risk classes, rule version, and evidence are detector facts.

The existing extension-control authority stores `enabled` and `disabled` wire states. A disabled extension or permission does not disable Guard protection. It causes the governed capability to resolve as blocked. The UI therefore uses capability language such as **Allowed**, **Blocked**, **Inherited**, **Required**, **Managed**, and **Lockdown** rather than implying that protection itself is being switched off.

## Decision

### Canonical identity and metadata

The built-in command extension registry remains the source of truth for extension, permission, and rule metadata. The dashboard consumes the daemon catalog and does not maintain a second registry of command names, matcher behavior, risk classes, or safer alternatives.

Every user-addressable target uses the registry's canonical stable ID. Aliases are accepted only for lookup and are immediately canonicalized before a shareable detail URL or mutation is formed. Unknown, malformed, duplicate, oversized, or cross-extension identities fail closed at the client boundary and are still validated by the daemon.

### Detector facts versus policy treatment

Rule severity, matcher kind, matcher evidence, risk classes, stable rule ID, and rule version are immutable detector facts. Policy may alter effective treatment within Guard's hard and managed floors, but it never rewrites those facts. UI and receipts must show baseline facts beside effective policy when an override exists.

Batch 1 is read-only below the existing broad extension control. Later batches add permission controls and bounded rule-treatment overrides without changing detector truth or matcher logic.

### Authority and precedence

All persistent control changes reuse the existing versioned, tamper-evident extension-control authority, catalog digest binding, revision checks, idempotency keys, approval gate, proof issuance, and apply path. No localStorage or dashboard-owned policy file is an authority source.

Resolution is restrictive:

1. Unsupported or unhealthy authority fails closed.
2. Global lockdown dominates capability controls outside trusted recovery surfaces.
3. Hard safety floors cannot be weakened.
4. Signed cloud restrictions cannot be weakened unless a future managed policy explicitly delegates a bounded range.
5. Required built-in protections remain non-configurable outside the resolver's explicit semantics.
6. Local strengthening is allowed.
7. Local weakening, when introduced, requires bounded scope, risk acceptance, justification, expiry by default, and proof.

The dashboard renders provenance from built-in defaults, local administrator layers, signed cloud layers, authority health, and global lockdown. It does not infer a weaker state than the daemon resolver.

### Routing and secret handling

`/extensions` is the overview and `/extensions/:extensionId` is the canonical detail route. Only allowlisted, bounded, non-secret view state is serialized into the query string. Session tokens, approval credentials, TOTP codes, proof IDs, raw command text, and sensitive local paths are never copied into detail URLs or browser history.

The legacy dashboard router currently selects the Extensions workspace only at `/extensions`. The entrypoint bridges nested extension paths to that workspace without retaining fragments or dispatching a second public route; the canonical nested path is restored before user interaction. This bridge is compatibility glue, not an authority boundary.

### Migration

Existing extension authority schema `1.0.0` is read without migration in Batch 1. The read-only drill-down must not alter authority revisions. The first schema-changing migration is reserved for the scoped rule-treatment work and must be fail-closed, deterministic, idempotent, and covered by fixtures before it is activated.

## Non-goals

This decision does not authorize:

- user-authored regexes, shell fragments, JavaScript, Python, globs, or executable matchers;
- editing signed cloud policy locally;
- changing baseline detector severity or historical evidence;
- running commands from the Test Lab;
- a general-purpose policy language or extension marketplace;
- a dashboard-only persistence layer.

## Consequences

The dashboard has a larger validation and presentation surface, but policy meaning remains centralized in Guard. A catalog or schema change that affects canonical identities must update the generated baseline fixture intentionally. Browser tests may exercise presentation with mocked edge states, but batch acceptance requires an installed wheel, real daemon, production dashboard, and real Chromium browser.

## Implementation references

- `src/codex_plugin_scanner/guard/runtime/command_extensions.py`
- `src/codex_plugin_scanner/guard/runtime/command_permission_catalog.py`
- `src/codex_plugin_scanner/guard/runtime/extension_control_resolver.py`
- `src/codex_plugin_scanner/guard/runtime/extension_control_authority.py`
- `src/codex_plugin_scanner/guard/daemon/extension_control_api.py`
- `dashboard/src/extension-controls-normalize.ts`
- `dashboard/src/extension-control-center-model.ts`
- `dashboard/src/extensions-workspace.tsx`
