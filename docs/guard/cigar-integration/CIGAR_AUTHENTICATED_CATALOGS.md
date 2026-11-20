# Authenticated CIGAR catalog distribution

Guard can now accept a signed catalog without changing its application code or replacing its serving CIGAR runtime. One native resolver supplies release listing, normal SDK installation/re-verification, private Python setup, offline artifact import and installed receipt resolution. A catalog import changes release metadata only. It does not install, select, enable, switch or grant source access.

This records the offline distribution checkpoint in P7. The later [bounded native refresh checkpoint](CIGAR_CATALOG_REFRESH.md) adds explicit feed configuration and cancellable jobs; production feed/trust publication remains unqualified. Metadata reports `remote_feed_configured: false` until an operator configures a valid feed. No production key or feed is invented.

## Compatible build updates

For an SDK compatible with a shipped adapter, maintainers provide a new exact build entry, locked SDK/dependency and interpreter artifacts as appropriate, qualification receipts and a signed higher-revision catalog. Users import that catalog, choose opaque IDs from release/interpreter metadata, then prepare or reverify the chosen installation beside the current runtime. Activation continues through the existing explicit prepare/commit workflow and reconnect acknowledgement. Breaking API, worker or storage contracts still require a qualified Guard adapter or Guard release.

The catalog binds source/manifest identity and exact bytes independently of the SDK version string. A candidate and final build may share a version while retaining different build identities. A synthetic 0.14.2 fixture proves a compatible data-only entry resolves without an application-code edit; it is not real newer-SDK qualification.

## Public roots and signed imports

Catalog authority is configured separately through the existing advanced native operator command:

```text
hol-guard-runtime context-assistance-install-operator --stdin
```

The strict `guard-cigar-install-operator.v1` request requires an absolute `guard_home`, explicit `operator_approved: true` and `operation.action: configure_catalog_trust`. Its `authority` is `guard-cigar-catalog-authority.v1`, with at most eight separately reviewed Ed25519 public keys. Each key has `key_id`, lowercase `public_key_hex`, `not_before`, `not_after` and `revoked`. Multiple configured keys support deliberate rotation. This operation does not accept a private signing key. Root configuration and import both respect effective verification policy and the profile lifecycle lease.

The same advanced command accepts `operation.action: import_catalog` with a local `file`, read through bounded protected native I/O. Root configuration is unavailable through resident/browser requests. A catalog envelope cannot supply or replace trusted roots.

The ordinary CLI supports:

```text
hol-guard context catalog
hol-guard context versions
hol-guard context catalog-import < signed-catalog.json
```

The nested `guard context` route provides the same controls. `catalog` reports source, checkpoint, freshness, configured key IDs, diagnostics and cumulative withdrawals without probing Python. `versions` lists authenticated bundled or imported release metadata. `catalog-import` reads at most 1 MiB of signed UTF-8 catalog data from stdin. It forwards exact text to Rust for signature/schema/policy/storage decisions.

Authenticated `GET /v1/context-assistance/catalog` derives the fixed read action. Existing `POST /v1/context-assistance/versions` accepts `input.action: import_catalog` and `signed_catalog`; existing operator/session authorization and the settings approval gate precede mutation. Approval proofs remain outside the CIGAR request. Paired context consumers receive no runtime-administration capability.

Only signed-catalog imports receive the 4 MiB resident request allowance. Ordinary versions requests retain 64 KiB. HTTP framing allows 4 MiB on the versions endpoint; all other endpoint body limits retain their previous value. The signed envelope itself remains limited to 1 MiB by native catalog verification. Existing bounded response limits and optional-work routing remain in force. Lifecycle conflicts and stale configuration generations return HTTP 409.

## Retained trust and offline operation

The native protected writer keeps public roots in `cigar-catalog-trust.json` and optional feed configuration in its separate fixed file. New retained state uses an [atomically published private directory](CIGAR_ATOMIC_CATALOG_STORAGE.md) containing separate `key` and `catalog.json` files. Existing complete `cigar-catalog.key`/`cigar-catalog.json` flat pairs remain supported without migration. The retained catalog has a domain-separated owner MAC bound to the canonical Guard home. Stored facts include the exact originally signed text, roots and time at acceptance, immutable byte identities and cumulative SDK/interpreter withdrawals. No SDK code, source grants or execution authority is serialized there.

New imports reject unknown, revoked or inactive keys, bad signatures, duplicate/unknown fields, future/expired payloads, replay, same-revision equivocation and reused build IDs with different immutable bytes. History survives omission from later catalogs. Qualification and acquisition-origin metadata can refresh while exact artifact identities remain fixed. Permanent withdrawal survives omission or an attempted later unwithdrawal; known withdrawn bytes cannot be selected for a new runtime or used as rollback.

An existing owner-verified SDK/interpreter receipt can resolve offline after catalog expiry, key revocation or a malformed current root configuration, using its original authenticated metadata and the retained withdrawal/history checks. Omission alone does not withdraw an installed build. Fresh installation, setup, re-verification and artifact import require current signature authority. These distinctions do not stop an already serving actor when catalog metadata changes, and offline receipt resolution does not bypass fresh protected-artifact, adapter, feature or interpreter verification before execution.

Passive bundled inspection creates no profile stores. Tampered or copied cache state, a missing cache/key pair member or invalid retained history fails closed; Guard does not discard the ledger, regenerate a missing key or silently fall back to bundled trust. Current root configuration can be repaired explicitly without replacing authenticated installed metadata. Saved-note erasure preserves catalog trust files because they contain no reviewed evidence.

Catalog/root publication shares the long profile lifecycle lease with installation and runtime switching, then uses the short protected-writer lock for exact compare-and-swap publication. A Ready switch excludes publication until it commits or finishes cancellation cleanup. Import while CIGAR serves ordinary context requires no runtime shutdown, configuration revision change or grant refresh.

[Atomic first publication](CIGAR_ATOMIC_CATALOG_STORAGE.md) now removes that new-profile interval: six process exits during initialization expose no committed pair or a complete pair, and three update exits preserve the key with the previous or new cache. Explicit retry/recovery retains normal signature/checkpoint/MAC checks. Already missing/tampered committed state still fails closed; original keys/history are never invented. Power/disk-loss and the remaining crash matrix are not qualified by these process exits.

## Validation and remaining scope

Nine native catalog tests cover data-only additions, separate authority, exact preferences/off behavior, replay/equivocation/identity reuse, expiry/revocation continuity, permanent SDK/interpreter withdrawal, tamper/profile-copy/missing state, lifecycle exclusion/key rotation, bounded import framing and repairable current-root errors. The catalog-aware registry suite passes 107 tests with five SDK-gated cases. Service, protected configuration, off-state saved-data and native route suites pass separately. Python CLI/HTTP/native framing passes 73 tests, including the existing HTTP body reader.

A separately executed actual SDK case imports a signed catalog through the bound native request evaluator while CIGAR is serving. A normal install request then re-verifies the existing exact installation through the imported catalog. The source actor, configuration bytes/generation and complete reviewed notes/expiry remain unchanged. Ready cancellation preserves the source; catalog publication is excluded by the Ready lease; forward switch and last-good rollback preserve the latest reviewed vector without reviving removed notes. Lost-reply retry and Stop/off-state inspection preserve their existing behavior.

This case uses local macOS ARM64 final SDK 0.14.1, external Python 3.14.7/3.14.10 and test-only catalog keys/qualification receipts. It does not qualify the historical b47380 candidate, a real newer SDK, managed-Python end-to-end, installed/frozen delivery, real CLI/HTTP-with-SDK operation or other platforms. Test-only roots are compiled only in test fixtures.

The first actual run exposed a read-only job poll racing a configuration generation change. The native stale-generation fence stayed intact; the test now retries only this exact read-only stale response within its existing deadline. The initial failure remains evidence. Mutating actions still require exact current generation and explicit consent. The earlier compile and Ruff failures are also retained as non-acceptance results.

Rust 1.88 compilation, Rust/Python formatting, Ruff and native authority/I/O/privacy gates pass. Clippy retains 36 baseline errors in 23 hash-verified unchanged sources and zero new errors; two unused production helpers remain. All new/refactored source modules fit the 500-line guideline. The existing 4,445-line HTTP server receives only one import and two framing-budget conditions; it is recorded as a pre-existing size exception, not refactored as part of this work.

[Evidence](evidence/receipts.json) records exact sources, separate test images, logs, actual inputs, failures and preservation. Remaining P6 crash/cleanup/data-choice work, P7 production feed qualification/pins/update/retention/off-state selection/removal, P8 UI/walkthroughs and P9/P10 real approved newer bytes, installed/frozen/platform, approval/load/performance and maintainers' next-bump qualification are still required. The full P0–P10 goal remains active and incomplete. Existing workspace/tutorial work, original integration acceptance/log, execution approvals, live profiles/hooks/preview, upstream SDK and system Python remain preserved.
