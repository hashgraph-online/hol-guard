# Durable full deletion across CIGAR upgrades

Explicit full saved-data deletion publishes a private cigar-erasure.json intent before closing active scopes or deleting persisted data. It owns the cross-process profile lease used by preparation and switching. The marker cannot select a runtime, enable a feature or grant access; even corrupt or linked marker presence refuses new data admission and activation.

Deletion closes current SDK/cache owners, clears the selected cache, removes the original legacy saved-evidence root and all retained/prepared generations, then removes the selection journal/key. The marker is removed last after bounded stores are verified empty. Clearing the legacy root fixes a gap where erasing a selected generation could leave its original saved source copy behind. No destination comes from SDK metadata or marker JSON.

An interrupted or busy deletion retains its intent. Passive inspection reports repair required without retrying mutation. Fresh explicit erase obtains the profile lease and validates the exact private marker bytes before continuing. Unacknowledged intent publication is observed on retry rather than blindly republished. Corrupt contents can be repaired by explicit erase; unsafe file ownership, permissions, links or busy real cache owners refuse safely.

Preparation, activation, maintenance, policy checks and backend opening honor the marker. Active Clear and offline Forget saved data converge on the same owner. Requested preferences remain unchanged, disabled users remain disabled, and erasure or repair does not start an SDK process. Stop revokes native runtime authority independently of saved preferences.

## Validation and remaining work

Four native fault/ownership tests cover interruption after legacy deletion, lost intent-publication acknowledgment before deletion, read-only/symlink markers, corrupt generation metadata and a busy real cache owner. All38 selection,13 Service,19 protected-writer and seven off-state saved-data tests pass. Rust1.88, formatting and native authority/I/O/privacy gates pass. Clippy reports36 errors in hash-verified unchanged baseline sources and zero new errors;60 unused production entry warnings remain visible until public controls are connected.

The actual final CIGAR0.14.1 test performs a saved-mode upgrade, proves a legacy source copy remains, interrupts Clear after removing that copy and verifies the selected generation still exists behind the durable fence. Compile and Activate refuse while pending. Explicit Forget saved data then removes all generations, selection references/key and intent while preserving exact preferences. Corrupt-intent repair also succeeds while disabled without restarting the SDK or restoring the old scope.

This qualifies one local macOS ARM64 case with external CPython3.14.7/3.14.10 and a test-qualified target. It does not qualify original b47380, genuinely newer SDK bytes, managed-interpreter end-to-end, installed/frozen packages or other platforms. Other process-loss/unknown-write boundaries remain to be exercised. Per-scope withdrawal/note deletion across retained/prepared copies is separate unfinished work, alongside inactive-data readmission, lineage/capacity, public controls and final P9/P10 qualification. The full P0–P10 goal stays active and incomplete.

[Evidence](evidence/upgrades-full-erasure-20261027.json) binds exact source/image/check identities and logs. Original acceptance/log, live profile/hooks/preview, upstream SDK source, system Python, Guard approvals and Git staging/history are unchanged.
