# CIGAR upgrade architecture reassessment

Recorded 2026-10-26. This addendum supersedes conflicting assumptions in the initial upgrade plan. The original local integration acceptance remains historical evidence.

## Finding and decision

Retain the existing persistent isolated SDK process and Rust-owned authority, source admission, graph/broker contract, resource bounds and asynchronous control path. The integration already has the correct process boundary. Avoid a general plugin system or importing the SDK into Guard's Python host.

The remaining coupling is concrete: lib.rs pins one SDK version; artifacts.rs equates SDK/core/manifest identities to it; runtime.rs and broker_domain.rs compare handshakes to it; registry v1 stores only local candidates; status/history client readers require 0.14.1. Changing a constant would neither qualify new bytes nor supply a safe update lifecycle. Configuration changes currently revoke the actor, and the engine owns in-memory pairings/scopes, so transparent session transfer cannot be assumed.

Use one declarative release catalog, a small Guard-shipped adapter table and immutable installation slots. Catalog entries carry exact SDK/core/protocol/build/source identities, dependency and artifact hashes, platform/ABI, storage and feature compatibility, provenance, and separate qualification. A compatible release addition is data and qualification work; incompatible contracts require a reviewed shipped adapter. Remote executable adapters are excluded.

## Current upstream evidence

GitHub v0.14.1 was published on 2026-10-26 at 18:58:17Z. Upstream PR 40 is merged; its final qualification reports fourteen installed platform/runtime cells. These are upstream results, not Guard integration qualification. The old local candidate source remains b47380e5a5cbeaaad5a61cab3372e9e67368732f.

The final macOS ARM64 wheel is hol_cigar-0.14.1-py3-none-macosx_11_0_arm64.whl, 4,168,720 bytes, SHA-256 91bc332b2cd34df0482dde0e25e337f2d2883f87d655c9c1387f126e591e18a2. The release manifest SHA-256 is 472b722b5029f8dd3c7051c7d7d17a5909d251cf2ba3e0ae20ed9d7cf5b0b7f2. These observed public hashes are not a production signing authority.

Sources:
- https://github.com/hashgraph-online/hol-cigar/releases/tag/v0.14.1
- https://github.com/hashgraph-online/hol-cigar/pull/40

Version equality does not imply build equality. Support candidate-to-final and rebuilt same-version artifacts as distinct immutable identities. Compare release versions using PEP 440 for ordering only; resolve exact builds by authenticated identity. Never automatically select older/withdrawn bytes as a fallback.

## Minimize disruption

1. Discovery, catalog refresh and status read bounded metadata without probing interpreters, ingesting sources or starting CIGAR.
2. Prepare, install and verify a replacement alongside the current runtime. Download/build/qualification failure leaves the old selection untouched.
3. Keep installed selections across Guard upgrades. A newer bundled catalog offers a build; it does not silently select it. Manual/pinned is the default. A future opt-in policy may schedule prepared compatible updates at a safe point.
4. Preflight data and feature compatibility before interruption. Use a short serialized cutover with expected-generation checks and a durable journal. Never upgrade an active environment in place.
5. Preserve enabled/off intent, settings, source/app consent and Guard approvals. Preserve reconstructible evidence and host consent where supported. Mint fresh CIGAR generations, grants and snapshots; never copy stale live authority.
6. Existing pairings are engine-memory authority. Do not promise session continuity until a tested native rebind mechanism checks the same live authenticated client, policy and exact source scope. Otherwise show the explicit reconnect requirement before switching.
7. Health-check the replacement, retain the last working compatible installation/data generation, and use the same transaction for rollback. Reconcile uncertain outcomes before retry. Withdrawn builds are ineligible for automatic rollback.
8. Keep CIGAR setup, install, selection, activation, source grants and optional sharing/persistence/execution consent distinct. Optional update failure must not stall Guard command evaluation.

## Delivery and evidence

Execute the initial plan P0-P10 with this addendum and CIGAR_UPGRADE_GOAL.md. Start with exact schemas/fixtures and native profile resolution, then evolve registry/history, bounded acquisition, data preparation, durable switch/recovery, native operator contracts, and the existing workspace UI.

The first real build-transition qualification can use the old candidate and the genuinely rebuilt published 0.14.1 under explicit local test enrollment. Do not expose a vulnerable or withdrawn historical candidate as a recommended rollback. Genuine newer-version A-to-B-to-A remains a separate release-dependent qualification; clearly labeled future-version fixtures prove catalog-only extensibility without pretending to qualify a nonexistent release.

A Guard release must package the same adapters, bundled catalog, installer/bootstrap resources, and optional locked SDK artifacts through one manifest flow. Reproduce installed-wheel and frozen behavior. Provide a release-entry generator and CI checks so maintainers do not edit active SDK pins in Rust, Python and TypeScript.

Production remote catalog keys/hosting remain external prerequisites. Implement authenticated refresh/import with explicit unavailable states when no authorized root exists; never ship generated test keys or trust archive-supplied keys. Preserve old local-candidate enrollment as an explicit advanced operator path.

## Acceptance

- Compatible release/build additions require catalog/lock/qualification data only.
- Unknown/incompatible/unqualified/tampered/withdrawn releases cannot activate by changing version labels.
- Legacy candidate records and historical evidence stay readable under their original identities.
- Installing a replacement leaves an active runtime operational and an opted-out profile off.
- Switching, cancellation, failed activation, crash recovery and rollback preserve correct selection/data and do not revive old authority.
- Guard approvals and synchronous-hook behavior remain correct.
- Exact artifact tests are separated from synthetic future-version fixtures and upstream qualification.
- UI/tutorial work is preserved, and local/installed/frozen checks and remaining platform/trust limitations are recorded.
