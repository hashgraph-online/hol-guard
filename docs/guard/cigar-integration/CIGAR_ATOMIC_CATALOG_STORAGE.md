# Atomic first publication of CIGAR catalog state

The first signed catalog import now publishes its owner key and retained cache together. A process interruption before publication leaves no committed pair; an interruption afterward leaves both files visible. Retrying the authorized import reclaims only bounded, recognized unpublished staging objects. This closes the earlier key-created/cache-missing interval for newly initialized catalogs without selecting, enabling or restarting CIGAR.

The signed catalog schema, installed receipts and native/CLI/HTTP actions remain unchanged. Existing complete flat-file catalogs remain readable and refresh in place with their original key. Guard does not silently migrate them, regenerate a missing key or infer trust from a storage label.

## Publication and recovery

New catalogs use the private `cigar-catalog-state` directory with separate `key` and `catalog.json` files. Public roots and optional feed configuration retain their existing fixed profile files. Key and cache contents use the same profile-bound MAC and signed catalog/identity/withdrawal contracts as before.

The protected writer creates a private unpublished directory under the pinned Guard home, writes and syncs both files, syncs the staging directory, then performs an atomic no-overwrite directory rename. It syncs the parent before reporting success. Each directory/file is owner-checked, private, stable and accessed through pinned file descriptors; links and unsafe file types refuse. The key stays immutable for later cache updates. Existing read-only cache permissions/ACLs are respected before atomic replacement.

The implementation uses the safe `rustix` no-replacement rename API. The workspace already resolved `rustix` 1.1.5. Cargo's offline lock flow added only that dependency edge to `hol-guard-runtime`, with no package version changes. The runtime's `forbid(unsafe_code)` remains intact.

Publication verifies the exact retained pair used to build the next cache, then compares that same pair again at the writer boundary. This keeps identity history, cumulative withdrawals and the immutable key in one update snapshot. Completion recovery also verifies and republishes the identical pair; a progress checkpoint cannot replace native cache authentication or import an older catalog.

Failures after rename remain unknown outcomes until current protected state is inspected. The existing explicit refresh recovery can confirm matching authenticated bytes without network or SDK work. A normal signed import can retry through its ordinary current-authority/checkpoint checks. Neither path resets the withdrawal ledger or restores grants.

Unpublished directory cleanup validates every candidate before removing anything. It accepts only bounded native temporary names, private directories and the two fixed regular-file children; unknown children, links or missing ownership protections refuse. Later cache updates similarly reclaim only bounded recognized unpublished files. Passive catalog inspection does not convert staging state into authority or create a new key.

A missing member of a committed pair still fails closed. An empty/unsafe committed directory, mixed flat/directory layouts, tampered MAC or a profile-copied cache cannot trigger fallback or reinitialization. An already incomplete historical flat pair still needs its original authenticated state; this change does not invent lost keys, checkpoints or withdrawal history.

## Verification

Seven protected-I/O tests pass, with one internal subprocess helper ignored in ordinary test enumeration. Two parent cases launch that helper and verify exit 86 at nine real process-loss boundaries:

| Boundary | State observed by a new process |
| --- | --- |
| Staging directory created | No committed pair |
| Staged key synced | No committed pair |
| Staged cache synced | No committed pair |
| Staging directory synced | No committed pair |
| Initial directory renamed | Complete new pair |
| Parent directory synced | Complete new pair |
| Replacement cache staged/synced | Previous cache and original key |
| Replacement cache renamed | New cache and original key |
| Replacement directory synced | New cache and original key |

Each parent then retries or confirms the observed state, verifies staging cleanup and preserves unrelated files. Other I/O cases cover exact compare-and-swap, immutable keys, existing flat pairs, mixed/incomplete layouts, read-only cache refusal, linked state, unknown orphan children and post-rename error reconciliation.

Three additional signed-provider cases prove authenticated first-publication recovery, withdrawals surviving unknown update outcomes, and existing flat signed caches/installed receipts remaining usable without migration or key regeneration. The complete registry suite passes 118 tests with five SDK-gated cases. Protected configuration passes 26 with its internal helper ignored; Service passes 17 with 12 SDK-gated cases; off-state saved-data recovery passes 10. These counts overlap the focused suites and are not summed as distinct tests.

Rust 1.88 production compilation and Rust formatting pass. Native authority/I/O/privacy gates pass. Clippy retains 36 baseline errors in 23 hash-verified unchanged sources and zero new errors; two unused production helpers remain. Python/CLI/HTTP framing is unchanged from the prior 76-test checkpoint, whose source identities remain recorded separately.

The actual final 0.14.1 SDK workflow is executed again on the new storage image. Catalog publication and a deliberately paused synthetic feed refresh retain the serving actor, existing context, exact preferences/generation and complete reviewed notes/expiry. Normal re-verification, explicit switch, Ready cancellation/exclusion and latest-data rollback retain their existing acceptance. The real SDK case does not inject process loss into the serving SDK; the nine process exits exercise native storage separately.

The initial compilation failure is retained: direct FFI violated the runtime's unsafe-code prohibition, and a directory-entry conversion treated a Result as an Option. Both were corrected before passing checks. No approval rule was weakened.

[Evidence](evidence/receipts.json) binds source/image/log identities, exact inputs, lockfile changes, failures and preservation. Qualification is local macOS ARM64, final SDK 0.14.1, external Python 3.14.7/3.14.10 and test-only catalog roots/receipts. Synthetic feed transport remains separate from production HTTPS qualification. Linux has a safe implementation path but is not qualified by this run.

These process-exit checks are not power-loss, disk-loss, installed/frozen or every-platform acceptance. The remaining P6/P9 crash/cleanup/data-choice matrix, P7 pin/update/retention policy, off-state selection and managed-slot removal, production feed/trust, P8 UI/walkthroughs and P10 platform/approval/load/performance/maintainer-bump evidence remain required. The full P0–P10 goal stays active and incomplete. Original workspace/tutorial work, integration acceptance/log, execution approvals, live profile/hooks/preview, upstream SDK and system Python remain preserved.
