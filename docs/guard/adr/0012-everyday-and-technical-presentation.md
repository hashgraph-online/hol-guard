# ADR 0012: Everyday and Technical presentation modes

Status: Accepted for implementation on `release/3.0`.

## Context

HOL Guard already has one authoritative local dashboard and security-grade decision, extension, policy, proof, and receipt contracts. Raw commands, paths, identifiers, and implementation vocabulary are still used as primary copy on several surfaces. A mainstream desktop product needs intent and consequence first without hiding material safety evidence or creating a second policy resolver.

## Decision

1. **Everyday Mode** is the default presentation and does not require a persistent badge.
2. **Technical Mode** is a free presentation preference. It is not a security posture, entitlement, authority, approval, scope, memory, or decision field.
3. ADR 0005 remains authoritative except that its Simple, Advanced, and Developer density section is superseded by Everyday and Technical modes.
4. The product keeps one route tree, data model, form state, queue, and component tree. Contextual disclosure may reveal exact evidence in Everyday Mode when a safe decision requires it.
5. Core owns action semantics, identity binding, redaction, retention, and the canonical local preference. React, Tauri, and Cloud must not parse shell strings to create user-facing meaning.
6. The explanation path is deterministic, local, side-effect free, bounded, and has no model or network dependency.
7. Presentation mode never appears in an approval or execution payload and cannot change enforcement.
8. Both modes always retain the authoritative outcome, material consequences, confidence or mismatch warning, actor, safe target summary, and the controls needed to decide safely.
9. Technical evidence is shown only when retained and authorized. Missing content renders an explicit unavailable reason; switching modes cannot reconstruct omitted data.
10. Managed policy, Emergency Lockdown, and degraded authority health may require technical evidence to be disclosed, but cannot use presentation mode to weaken or conceal enforcement.
11. Desktop is a write-through affordance to Core. Its cache is non-authoritative and must reconcile before claiming a saved change.
12. Cloud may sync a convenience profile later, but local explicit choice wins, offline use remains complete, and Cloud cannot force Technical Mode.
13. Local protection, local approvals, Everyday Mode, and Technical Mode remain free. Solo sells continuity and history, not protection or technical visibility.

## Identity and mismatch behavior

`guard.action-explanation.v1` binds to the current action identity and, for commands, the canonical security identity. A mismatch is not silently accepted. The UI says: “Guard could not verify the explanation for this action. Review the technical details or stop the action.”

## Consequences

Friendly copy becomes a versioned contract rather than client heuristics. Existing explicit `simple` migrates to `everyday`; `advanced` and `developer` migrate to `technical`; missing or unknown values safely resolve to `everyday` with a non-sensitive diagnostic. Route changes, Core restart, Cloud logout, and Cloud disconnection do not reset the local explicit preference.

## Implementation baseline

The EVM-001–100 foundation was reconciled and validated against `release/3.0` at `d6f3eae11e67c82e0436d951c0b6d8c769858e1d`. The reconciliation regenerated source-bound command decision evidence and passed the focused Core presentation/explanation contracts plus the complete dashboard test and production-build commands before the final review/CI gate.
