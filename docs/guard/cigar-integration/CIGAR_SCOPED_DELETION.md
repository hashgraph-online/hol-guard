# Scoped deletion and off-state recovery across upgrades

Native Clear notes and source withdrawal now publish an authenticated deletion intent before changing the affected SDK domain. They remove matching legacy, current, prepared and retained copies, invalidate the old native contexts and rebuild only that scope from current grants and remaining sources. Successful deletion preserves the serving SDK, other app/workspace scopes, exact preferences, selected installation/data pair and last-good journal.

The fixed private cigar-scopes.json index records native app/workspace attribution for cache slots when a freshly authorized scope opens. Its profile-bound MAC role is separate from selection, deletion intent and command approval. Entries contain hashes and a fixed cache-location type, with no source paths, source text, grants, executable paths or SDK credentials. Authenticated generation lineage supplies historical source/target mappings. Current native leases and SQLite ownership remain mandatory for deletion.

The index is bounded to 64 rows and 32 KiB. Admission prunes absent generation locations and obsolete keys in the currently owned cache. Missing keys for existing signed metadata refuse rather than being regenerated. Metadata inspection authenticates existing index data without provisioning it; explicit full erasure can remove a corrupt private index along with the stores it describes.

Before accepting scoped deletion, every existing saved slot must be attributable. Old opaque entries with no native mapping refuse before intent publication or SDK mutation. They are neither guessed nor silently deleted. An operator can explicitly erase all saved CIGAR data to repair such legacy state. This preserves unrelated data and keeps an unaccepted deletion from interrupting the current scope.

The access-reduction action resume_erasure authenticates a pending scoped intent, revokes any remaining native runtime authority, waits for real SDK/cache cleanup and finishes deletion without starting CIGAR or recreating grants. It works while disabled and with corrupt settings, preserving exact settings bytes. Read routes reject it. Partial or unknown outcomes retain the marker; passive inspection reports repair required. Full erasure also removes the index before removing selection/key and the final intent.

## Actual SDK acceptance

Saved and memory-only cases each use three scopes across two apps and two workspaces. They perform a real Service switch, clear one scope, preserve another app's complete reviewed vector/original expiry and retained context, preserve the other workspace, and then withdraw that workspace's source. Successful scoped work retains the same serving actor/SDK. The saved case proves deletion of the original legacy copy and refusal of an injected empty unattributed legacy slot before SDK mutation.

Each case admits a new review after the first clear, interrupts a second clear after purging data, verifies the admission fence, stops CIGAR, disables it and explicitly resumes deletion. Resume preserves the disabled settings and selection/last-good bytes and starts no SDK. Only a later explicit enable/activate and fresh native grants reopen scopes. Erased notes do not return, saved evidence for the other app survives restart, and memory mode creates no saved-evidence or generation store.

These cases use exact final CIGAR 0.14.1 artifacts on local macOS ARM64 with external CPython 3.14.7/3.14.10 and a test-qualified target. They do not qualify original b47380, a genuinely newer SDK, managed-interpreter end-to-end, installed/frozen packages or other platforms.

## Validation and remaining work

Context tests pass 93 on stable Rust and Rust 1.88; strict 1.88 context Clippy passes. Native selection/ownership/privacy tests pass 50, Service 13, protected writer 19 and off-state data 10. The two new SDK cases are explicitly executed; ten Service SDK cases remain gated in ordinary runs. Native Rust 1.88, formatting and authority/I/O/privacy checks pass. Native Clippy retains 36 errors in hash-verified unchanged source files with zero new errors. At this scoped-deletion checkpoint, 60 unused production entry warnings remained while public switch/rollback controls were unconnected. The later [operator-controls checkpoint](CIGAR_UPDATE_OPERATOR_CONTROLS.md) connects those entries and records the remaining two helpers.

Earlier failures remain in the evidence: an incorrect new test error label, a missing qualified type in the test fixture, the first memory test's attempt to export an empty review, and a new large enum variant lint. The empty-domain check now queries actual SDK revision/digest and memory storage status through a test-only helper; it does not invent an empty reviewed transfer or alter the production transfer contract. The recovery owner is boxed without weakening its lease lifetime.

Complete the remaining P6 process-loss/unknown-write/Stop/cleanup matrix, inactive-data readmission, lineage/capacity and explicit feature/data choices. Finish P7/P8 policy, catalog, CLI/HTTP/Versions UI controls and walkthroughs, then P9/P10 real release, installed/frozen/platform, approval, transport/load and performance qualification. Production trust/hosting and genuine approved newer bytes remain prerequisites. The full P0–P10 goal remains active and incomplete.

[Evidence](evidence/upgrades-scoped-deletion-20261028.json) binds final source/image/log identities and retained failures. Original user work, acceptance/log, live profile/hooks/preview, upstream SDK source, system Python, Guard approvals and Git staging/history are unchanged.
