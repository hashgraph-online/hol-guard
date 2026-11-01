# Native engine preparation and admission boundary

The native engine can now capture its existing app/workspace intent, prepare a
fresh target engine outside the old actor, and compare a final semantic snapshot.
This is an implemented P6 component. The [native selection owner](CIGAR_NATIVE_SELECTION.md)
now journals exact SDK/data pairs and connects fresh Service verification to the
recorded generation and compatible interrupted-commit recovery. Live switch
jobs, all rollback/recovery effects and Versions controls remain required.

## Capturing live intent

Only the old actor constructs `UpgradeCapture`. It contains pinned native roots,
the exact selected file paths/content hashes, app and notes permissions, current
policy, and bounded historical observations. It has no wire deserializer and
contains no old SDK view, client, retained context, agent session or execution
handoff. Preparation currently accepts a runtime change with the same effective
preferences; accepted feature/data differences remain transaction-owner work.

Reviewed saved notes use the actual SDK provenance and protected generation
layer. A semantic stamp binds the scope, exact producer, source and note
revisions, original creation/expiry, dependency content and reviewed document
hash. Capture time and source manifest bookkeeping are excluded. Ordinary
queries update lease observation in memory, not the saved manifest on every
read. Native tests prove serving and preparation preserve that file and the
semantic snapshot; a newly admitted review invalidates the earlier capture.

Source/cache handles retain one shared private root lock and active-slot
registry. Cloning a handle cannot bypass slot ownership or deletion protection.
A zero-scope generation is ready without any note transfer, preserves unmapped
source keys, and has no ability to read another scope's notes. All prior cache,
generation, retention and size bounds remain in force.

## Building the replacement

`UpgradeCapture::build` runs outside the old actor. It rechecks the current
workspace policies, rereads only the previously granted files and requires the
same content before SDK admission. New cache keys bind the complete producer,
even when the native worker executable is unchanged. Notes enter fresh SDK
brokers through the existing source APIs; no opaque SQLite copy is used.

Logical scope IDs and source/app intent survive. SDK views, contexts and agent
sessions are rebuilt or left unavailable for fresh authorization. An existing
execution lane requires a newly measured and prewarmed target lane. The caller
must still obtain the reconnect acknowledgement and perform final policy,
source, settings, cancellation and generation checks before publishing it.

Readonly history retains its original timestamps, SDK labels and producer
metadata. New target observations receive the target producer. Added provenance
is included in the original per-entry/total byte limits, with normal bounded
eviction; transferring history cannot extend its retention or make it current
execution evidence.

Memory-only reviewed notes currently refuse preparation with
`context_upgrade_data_unsupported` instead of silently losing text. Their
ephemeral transfer path is required before the complete workflow is exposed.
Likewise, inactive/unmapped saved data and its required SDK files must remain
protected until the native owner maps or expires it.

## Bounded cutover admission

`RuntimeActor::pause_at_boundary` first closes admission, then queues a barrier.
Ordinary calls check admission both before queuing and at dispatch, so a caller
already holding the old actor cannot mutate after the final snapshot. Actor
maintenance pauses too. The existing queue capacity and six-second deadline
remain unchanged; no SDK mutation is automatically retried.

Dropping a boundary guard resumes only a still-live source actor before shutdown.
Consuming it for `close_and_wait` cannot resume a stopped generation. Queue depth
and pause state are atomic metadata reads. The transaction owner must invalidate
its native context/handoff epoch, stop the old actor, wait for the existing
bounded cleanup acknowledgement, and commit/reconcile exact SDK/data selection.

## Current evidence and remaining work

The actual test uses final 0.14.1 bytes deliberately enrolled through v1, plus a
test-qualified catalog target on another Python producer. It prepares two app
scopes beside a serving actor, preserves a new reviewed edit, refuses changed
source content and older snapshots, preserves historical producer labels, and
requires fresh SDK authority. A deterministic queued-request race verifies the
barrier, safe pre-stop resume and irreversible shutdown. A fixture-only settings
transition exercises the resulting engine; it does not prove an atomic native
switch or the original b47380 candidate. [Evidence](evidence/receipts.json)
records the exact image and limits.

Still required: central live Service switch jobs, final native epoch/observation
coordination and all known/uncertain rollback effects; restart reconciliation
at every boundary; explicit rollback using latest reviewed data; cancellation,
Stop and settings races; per-scope deletion across retained/prepared generations;
ready-generation pruning and disk capacity; accepted feature changes and the
memory-note path. Keep workspace I/O outside the final narrow boundary where
possible; current capture still performs existing policy/source checks on the
actor, and broad workload qualification remains P9/P10 work. Public controls,
installed/frozen/platform tests and production catalog trust remain unfinished.
