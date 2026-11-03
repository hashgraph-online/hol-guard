# Scoped retained-copy erasure primitives

The evidence library can now remove known copies for one app/workspace across the legacy cache and every prepared or retained generation. It follows authenticated generation lineage, stable scope and exact producer identities, and measured legacy worker keys. It removes pending reviewed text, mapped source/target cache slots and abandoned generation staging files. An expired metadata entry retains the original source-key mapping for safe explicit retry without retaining note text. No SDK process or source-file read is required.

The current cache can be borrowed after the affected SDK domain closes. Matching live slots refuse deletion; unrelated apps and workspaces keep their cache leases and committed data. Other cache roots still require native ownership and real SQLite-owner checks. All generation records are authenticated and existing cache owners acquired before record mutation. Damaged lineage refuses; unknown legacy hashes are not guessed or silently claimed as erased.

The native ScopeRemoval primitive holds the profile lifecycle lease and publishes a private, profile-bound authenticated intent before deletion. Its MAC role differs from runtime selection and command approval. Intent contains bounded hashes and a nonce, with no source paths, source text, grants or executable locators. Explicit resume authenticates that same intent and uses its captured data mapping without reopening an SDK scope. Partial work keeps the admission-blocking marker. Scope completion removes the marker last and preserves exact configuration, selection, last-good and key bytes. An absent lifecycle key can be provisioned to authenticate the intent; this creates no runtime selection or access grant. Corrupt, tampered, wrong-role or copied-profile intents refuse scoped deletion; separately authorized full erase remains available for damaged private metadata.

## Integration after this primitive checkpoint

The later [scoped-deletion integration](CIGAR_SCOPED_DELETION.md) now connects native Clear notes/Withdraw and authenticated off-state resume. A bounded native index and sealed lineage establish attribution; unknown legacy entries refuse before intent/SDK mutation. Actual local saved/memory SDK cases cover the integrated flow. UI controls and the broader release/recovery matrix remain unfinished.

The integrated path acquires intent before SDK mutation, closes the affected domain, purges copies, completes intent and rebuilds fresh scope views. Its native resume operation works while off or with corrupt settings, without starting CIGAR or restoring grants. The original primitive evidence below remains bound to its earlier source/image.

Qualify this complete route with the real SDK after an upgrade, including multiple apps/workspaces, imported and newly admitted notes, source withdrawal, interrupted deletion and explicit off-state resume. Finish the remaining process-loss/unknown-write matrix, inactive-data readmission and lineage/capacity work. P7/P8 public controls and P9/P10 qualification remain required; the full P0–P10 goal is active and incomplete.

## Validation at the primitive checkpoint

Nine new context-library cases cover prepared text and legacy copies, a borrowed generation with an unrelated live slot, real native slot ownership, absence/foreign-cache refusal, exact legacy keys, interrupted record writes before/after rename, corrupt lineage, workspace isolation and abandoned staging. Seven native cases cover dropped/unacknowledged intent, interrupted completion, a busy live slot, wrong-role/tampered markers copied-key/profile replay and completed-switch last-good preservation. These are native serializer/filesystem tests, not SDK release qualification.

The context suite passes 88 tests on stable Rust and Rust 1.88, with 13 SDK cases gated. Strict Rust 1.88 context Clippy passes. Native selection/privacy tests pass 45, Service 13 and protected-writer 19; eight Service SDK cases remain gated. Native Rust 1.88, formatting and authority/I/O/privacy checks pass. Native Clippy retains 36 errors in hash-verified unchanged baseline source files with zero new errors. The 66 production unused-entry warnings remain visible while private coordinator and scope-erasure routes are unconnected.

The previous actual SDK full-erasure case remains separately recorded in [durable full-erasure evidence](evidence/receipts.json), on its original executing image. It is not a real-SDK acceptance test for these new scoped primitives. No original b47380, newer SDK, managed-interpreter end-to-end, installed/frozen or additional-platform claim follows.

[Evidence](evidence/receipts.json) binds current source identities, current native/context images, passing checks, the corrected test-compilation failure and logs. Existing user work, original acceptance/log, live profile/hooks/preview, upstream SDK source, system Python, Guard approvals and Git staging/history remain unchanged.
