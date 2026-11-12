# Private saved context evidence

Context assistance defaults to memory. In **Protection → Context assistance → Sources, limits and runtime details**, **Evidence storage → Save locally** optionally retains admitted evidence between runtime sessions. Saving this preference does not grant files, connect AI apps or enable sharing. The selected runtime must still pass the actual final CPython 3.14, CIGAR 0.14.1 and approved worker checks.

Start or explicitly recheck the runtime to run the separate native persistence doctor. It writes only synthetic evidence in a private qualification namespace, closes and restores the SDK store into a fresh epoch, rebuilds a fresh native catalog/client and verifies cited compilation. Its result is independent of the sharing check. Recheck while off leaves the saved enable preference off. A historical successful check is not an active capability.

## Recovery and permissions

Saved evidence belongs to a bounded app/workspace cache key. Starting a new runtime restores no native source grants, prepared history, AI app credentials, broker tickets, pending proposals, reviews or execution permissions. A user must grant the workspace and selected files again. Rust reads those files through the normal protected path and verifies the SDK's stored provenance against the fresh native catalog before permitting reuse. A saved file locator is never source permission.

Reviewed shared notes can survive only while their complete original source basis remains selected, current and unexpired. Changed, omitted, unsafe or unavailable bases withhold the notes. Native action and receipt sources are reset under current authority. Old context handles and old app connections remain invalid. Preparation or recovery does not confirm execution or approve a command.

Private operator storage uses the broker API without enabling AI app access. Sharing remains a separate explicit preference, with fresh independently authorized app connections. A saved store does not enlarge a connection's source permissions.

## Retention and resource bounds

The retention setting accepts 1–720 hours and applies to prepared history, saved evidence and reviewed shared notes. Native maintenance checks stored expiry before reopening saved evidence and sweeps inactive expired stores without starting an SDK process. Resident startup detects existing saved data and schedules an immediate native sweep; subsequent sweeps run every 30 seconds and read the current retention preference, including while assistance is off. Opening context controls also arms maintenance after a new saved namespace appears. An active actor maintains its own stores. An absent saved namespace stays absent and creates no housekeeping thread. With the app fully closed, deletion waits for a later native maintenance opportunity; expired data cannot be readmitted first. Wall-clock anchors detect observed rollback but provide no trusted offline clock.

| Limit | Bound |
| --- | --- |
| Saved workspace/app stores | 8 |
| Aggregate logical file lengths | 528 MiB |
| Native metadata per file | 128 KiB |
| SDK checkpoint | 12 MiB |
| SDK database | 32 MiB |
| SDK rollback journal | 33 MiB and 64 records |
| Reviewed shared-note text | 16 KiB across at most 32 documents |

These are bounded file lengths, not RSS measurements, filesystem physical allocation or free-space reservations. The synthetic qualification namespace has its own bound and cannot consume a user's eight cache slots.

## Data and repair controls

**Data & repair → Context data and repair → Saved context evidence** reports metadata only: saved/active stores, logical bytes, unresolved writes, invalid records and expired slots. It remains available while assistance is off, a runtime is unverified or the settings file is malformed. Inspecting or removing saved files never imports, probes or starts the SDK.

**Remove saved evidence** ends current context access, waits for native SDK cleanup and removes the strictly bounded Guard-owned files, including inactive stores. The enable preference stays as saved; starting/checking and fresh grants are required before use again. **Clear all context data** also clears current in-memory context, history, origins and connections. **Clear context history** affects only prepared history. **Turn off** stops the runtime and revokes access while retaining eligible saved evidence for a later explicit opt-in. Every action preserves Guard approvals and durable Guard receipts.

Busy, malformed or uncertain storage is reported explicitly. Repair refuses to delete a store still owned by a live SQLite worker, including an orphan left after a Guard crash. Missing or unsafe storage does not trigger recursive deletion or automatic permission repair. A failed deletion must not be represented as success.

Human note admission spans SDK and native metadata commits. The native side stages a hash-only intent and acknowledges admission only after both commits are confirmed. Unknown outcomes require reconciliation against actual stored provenance and versions; they are never automatically retried. If committed note text lacks its native record, the store is preserved and marked repair-required for explicit removal rather than reconstructing lost text.

## Storage protection and qualification

Rust owns all private I/O: current-user directories with exact 0700 permissions, 0600 single-link regular files, pinned identities, fixed names and descriptor-relative operations. Storage refuses links, replacements, unknown files, excessive sizes and live owners. Private POSIX files do not provide Guard-level encryption, physical secure erasure or isolation between hostile users sharing an account. Windows persistence remains unavailable pending its platform implementation and qualification.

The [product persistence evidence](evidence/receipts.json) and [execution log](EXECUTION_LOG.md) record the exact local candidate, packages, native/installed/browser results and failed attempts. Installed acceptance on `5fe31cc1` proves private runtime stop/restart, fresh grants, cited reuse and off-state removal, alongside the separate two-MCP sharing/proposal/revoke regression.

The separate [shared persistence restart test](evidence/receipts.json) qualifies full Python daemon and native resident restart on those same installed bytes. Old connected MCP clients, scopes and snapshots are refused. Fresh grants and newly paired clients recover reviewed cited notes; unadmitted proposals and prepared history do not return.

[Headless retention acceptance](evidence/receipts.json) qualifies the `8fccb141` installed build at its recorded scope. A third actual daemon/resident removes an aged disposable record under the current retention preference before any context request, while assistance stays off without an SDK runtime, check or job. The test controls only its fixture record's age. Current `ed5011ac` [matching backend/browser acceptance](evidence/receipts.json) covers persistence restart/removal and supported execution flows; [performance qualification](evidence/receipts.json) includes real on-mode work and observed worker resources. The [final source audit](evidence/receipts.json) preserves the older retention receipt's identity rather than counting it as a rerun. Other platforms, full Desktop/public release and model/human or memory benefits remain outside [local acceptance](ACCEPTANCE.md).
