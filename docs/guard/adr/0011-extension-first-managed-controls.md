# ADR 0011: Extension-First Managed Controls

- Status: Accepted
- Date: 2026-08-19
- Decision ID: `hol-guard.extension-first-managed-controls.v1`
- Canonical decision: `contracts/managed-controls/v1/product-decision.json`

## Context

HOL Guard 3.0 introduces Extensions and permissions as stable Local capability boundaries over detector rules. Guard Cloud already provides policy versioning, simulation, review, rollout, acknowledgement, rollback, exceptions, routing, and audit evidence. Presenting Extensions and Cloud policies as parallel configuration systems would duplicate concepts, increase cognitive load, and make authority unclear.

The product must preserve complete Local protection while making Guard Cloud materially more valuable for cross-device and workspace governance. It must also preserve existing routes, technical `GuardPolicy` types, policy bundle wire contracts, and contextual policy precedence during the 3.0 release.

## Decision

### Product model

Extensions define what HOL Guard can protect. Guard Cloud Control Sets define how that protection is governed across people, devices, agents, environments, and time.

The shared definitions are:

- **Extension:** a stable Local capability boundary for a protected tool or capability domain.
- **Permission:** an independently configurable capability inside an Extension.
- **Detector rule:** a Local implementation detail that recognizes evidence for a permission. It emits evidence, not authority.
- **Local setting:** a device-specific Extension or permission preference.
- **Remembered rule:** a contextual decision remembered from an approval.
- **Control Set:** a versioned, scoped, simulated, reviewed, signed, deployed, acknowledged, and auditable collection of Extension controls and contextual rules in Guard Cloud.
- **Managed restriction:** a signed workspace restriction that can disable an Extension, disable a permission, or activate global lockdown and cannot be weakened locally.
- **Deployment:** delivery of a signed Control Set version to an eligible runtime cohort with acknowledgement, drift, pause, rollback, and audit state.
- **Exception:** a time-bounded, reviewed contextual deviation. In release 3.0, an exception cannot weaken a managed restriction.

### Authority boundaries

1. The Local Extension registry is authoritative for detector facts, stable Extension IDs, stable permission IDs, dependencies, implied permissions, required floors, configurability, replacement metadata, and delegated protection.
2. Guard Cloud targets Extension and permission identities. It does not recreate or replace Local detector matchers in the default authoring path.
3. Current contextual policy precedence remains unchanged unless a separately negotiated contract explicitly says otherwise.
4. Non-weakenable authority is represented by `managed-restrictive`, negotiated independently, signed, and limited in release 3.0 to Extension disable, permission disable, and global lockdown.
5. Local settings and remembered decisions may tighten protection. They cannot weaken required floors or managed restrictions.
6. Package-manager Extensions with `delegated_protection: package-firewall` are governed by the package firewall contracts rather than duplicated command-policy rules.
7. Unsupported clients must not receive a fallback that silently drops Extension enforcement semantics.

### Authority modes

- `personal-shared`: shared posture for a user's authorized devices. Local tightening remains valid.
- `workspace-shared`: shared workspace posture. Local tightening remains valid.
- `managed-restrictive`: signed workspace floor that cannot be weakened locally.

### Product language

- Guard Cloud's customer-facing surface is **Managed controls**.
- The primary Cloud object is a **Control Set**.
- Local `/extensions` remains **Extensions** and describes tools and capabilities protected on this device.
- Local `/policy` remains a compatibility route but is labeled **Rules & exceptions**.
- Technical names such as `GuardPolicy`, policy bundle, policy document, policy version, and compatibility route names remain where they are protocol or implementation contracts.

### Compatibility

Existing `/policy`, `/guard/policy`, policy APIs, `GuardPolicy` types, canonical policy documents, and policy bundle names remain valid. New product labels do not require a breaking route or wire-format migration.

### Shared contract and drift prevention

Both repositories maintain byte-identical copies of:

- `docs/guard/adr/0011-extension-first-managed-controls.md`
- `docs/guard/managed-controls-glossary.md`
- `contracts/managed-controls/v1/product-decision.json`

HOL Guard tests validate the local shape and semantics. The Guard Cloud release workflow owns the cross-repository byte comparison against `hol-guard` `release/3.0`. The paired release is conformant only when that workflow is present and green after both paired pull requests land. Until then, cross-repository conformance is pending rather than assumed.

## Consequences

### Positive

- Local protection remains complete and understandable without Cloud.
- Cloud value moves to fleet governance, review, simulation, rollout, drift, exceptions, and evidence instead of duplicating detector authoring.
- Users see one clear Extension posture surface and one contextual Rules & exceptions surface locally.
- Paid plans can provide stronger governance without weakening the free product.
- Existing policy routes and wire contracts remain compatible.

### Costs

- Runtime capability negotiation, catalog synchronization, compatibility evaluation, and atomic application must be implemented before managed restrictions are enabled.
- Cloud must maintain a read model of Local catalogs without becoming the detector source of truth.
- Product copy, accessibility labels, documentation, and analytics require coordinated migration.

## Rejected alternatives

### Replace policy with Extensions

Rejected because contextual decisions, approvals, exceptions, routing, simulation, rollout, and audit are not Extension metadata.

### Keep policy and Extensions as independent editors

Rejected because it duplicates controls, obscures precedence, and asks administrators to recreate detector knowledge already owned by Local.

### Paywall Local Extensions

Rejected because Local safety is the protection floor. Cloud monetization must come from governance and coordination, not intentionally weaker local enforcement.

### Give all Cloud rules absolute precedence

Rejected for release 3.0 because it would silently change contextual policy semantics and could create security and compatibility regressions.
