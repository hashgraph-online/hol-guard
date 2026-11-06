# Protection Center

Protection Center is the human-facing control surface for command protection modules in HOL Guard 3.x.

## Information architecture

- The existing **Protect** area remains the general protection-health surface.
- **Modules** opens Protection Center.
- The compatibility routes remain `/extensions` and `/extensions/:id` so existing links and automation do not break.
- Simple mode is the default. Advanced and Developer modes progressively reveal implementation detail.

## Local protection boundary

Protection Center is a local security surface. Local evaluation, blocking, settings integrity, Test Lab, and settings repair do not depend on a Guard Cloud subscription or on Cloud availability.

Guard Cloud is optional continuity and coordination. The UI may explain Cloud history, cross-device continuity, or organization coordination, but Cloud state must never disable or hide local protection controls. Plan limits must come from authoritative entitlement state when present. The client must not invent device, retention, or storage quotas.

Local dashboard sessions are accepted only for the daemon's explicit Protection Center route allowlist and remain subject to same-origin and session-expiry checks. Forged, expired, or foreign-origin dashboard requests must fail closed.

## Protection settings

User-facing choices are:

- **Use recommended**
- **Block matching actions**
- **Allow when Guard would otherwise permit**

Quick profiles are Recommended, Stricter, Strict local, and Custom. Organization-managed settings remain read-only on the device.

Every write follows the existing preview, proof, approval, and apply flow. After apply, editing stays locked until the effective state is refreshed. Stale drafts must be rebased or discarded rather than applied against a newer settings revision.

## Settings history

Settings history is sourced from the authenticated local authority transition chain. Guard verifies the chain before presenting history.

Choosing an earlier version does not perform an immediate rollback. It prepares only the historical **device** layer as a draft against the current revision. The current organization layer remains in force. The user must still review the change and complete the normal proof-bound approval flow.

## Settings integrity repair

When settings integrity is tampered or recovery is required, Protection Center exposes guided repair through the existing local approval gate. Repair does not create an alternate write path.

## Test Lab

Test Lab evaluates a bounded command against the current local protection state without executing it.

Security requirements:

- no subprocess or shell execution
- no command persistence
- no Activity entry or approval creation
- no Guard Cloud upload
- no raw command in the response payload
- bounded command and result sizes
- authenticated local daemon transport

Test Lab is an explanatory tool, not an execution sandbox.

## Activity and privacy

Activity uses Guard's existing redacted command-activity evidence. Simple mode does not expose raw commands, local paths, proof material, tokens, canonical rule IDs, or module IDs.

Protection Center telemetry is allowlisted and coarse. It may describe presentation density, known plan ID, Cloud connection state, broad result, or category. It must not carry commands, paths, secrets, tokens, proof IDs, rule IDs, or module IDs.

## Protection module authoring

A protection module should provide human-readable presentation metadata in addition to its canonical Developer identifiers:

- name
- plain-language description
- at least one executable or ecosystem example
- risk or action language
- safer guidance

Missing presentation metadata must not cause local enforcement to fail. The UI falls back conservatively while Developer mode retains canonical identifiers for diagnosis.

## Compatibility and parity

Protection Center is a presentation layer over the same extension-control catalog, effective state, preview, proof, apply, and runtime evaluation contracts used elsewhere in Guard. It must not create separate enforcement semantics.

Any CLI or API caller using those contracts should observe the same effective settings and Test Lab decision semantics as the dashboard.

The installed-wheel release gate verifies Protection Center against the packaged dashboard and real local daemon, including signed-session Test Lab evaluation, proof-bound settings apply, daemon restart persistence, settings restore, Cloud-independent local behavior, and browser artifact capture.

Before merge, the release branch is composed into the feature branch and the exact composed head is re-run through the protected PR checks so Protection Center is validated against the current `release/3.0` tree rather than a stale base.
