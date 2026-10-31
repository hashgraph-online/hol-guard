# Prepared evidence generations

The native data layer can prepare reviewed notes beside the current CIGAR
runtime. It preserves the old checkpoint and uses the SDK's source APIs to
populate a fresh broker. It never copies an undocumented SQLite database.
Selection, activation and rollback transactions are still P6 work.

## Provenance and scope

`EvidenceSlot::export_reviewed_notes` requires an active verified runtime, its
measured persistence capability and the exact SDK storage directory backing the
slot. Guard's protected manifest must match the SDK's actual note revision and
digest. The SDK's provenance and the currently admitted source catalog must
agree on every dependency. The exported value contains data and content hashes;
it has no deserializer, credential, file grant, principal or execution handoff.

`EvidenceScope` binds an app and its canonical workspace namespace. Existing
worker-keyed slots remain readable; new slots bind that namespace to the exact
SDK/profile/dependency and interpreter producer fingerprint. Managed interpreter
bindings include the full distribution. Advanced external interpreters retain
their existing executable identity contract.

Import requires a fresh target broker and fresh native admission of the exact
source content. Missing or changed sources refuse before the target note write.
The SDK receives the original reviewed-note provenance and a narrowed expiry,
with dependency revisions from its new domain. Guard preserves the source
creation time and cannot reset retention by creating another generation.
Historical SDK labels and source note versions remain metadata; revisions in a
fresh target belong to that target's new epoch.

A native journal precedes the SDK mutation. If the SDK write succeeds but the
native commit is interrupted, explicit recovery reads the actual SDK revision
and provenance after fresh source admission, then completes the native commit.
It never resubmits the SDK mutation or restores an old view/context.

## Durable preparation

`EvidenceGenerationStore` owns the private `evidence-generations` namespace.
Preparation compares a fresh protected source snapshot before and after writing
the prepared record. Requests are idempotent for the same exact target/snapshot;
reusing an ID for another request is refused. A changed source leaves the
preparation unavailable for use and preserves the current runtime/data.

Each record has a separate local HMAC role bound to the Guard profile home and
generation ID. This role cannot qualify a release or authenticate a catalog.
Key files are pinned and rechecked; missing, altered, moved or unsafe records
refuse. Metadata listing displays no reviewed text or source-ID dependency set.
An explicit reload verifies the MAC before reconstructing an opaque transfer.

A target cache has its own eight-slot / 528 MiB bound. The store permits at most
three generations: room for current, retained and pending data. A decoded
preparation is limited to 1 MiB, its sealed record to 2 MiB, and preflight reserves
4 MiB for that record and atomic replacement. Generation capacity and actual
free-disk checks still need coordination by the native transaction owner.
A full source cache no longer requires deleting scopes merely to stage a target.

`finish_scope` verifies the actual imported SDK data before marking that scope
complete. It replaces the prepared note body with metadata, removing the extra
copy after durable import. Ready generations cannot use the preparation-discard
operation. Pending copies expire at their original note deadline or a shortened
retention limit. Existing native retention housekeeping and explicit Forget saved
data include these generations, even while CIGAR is off. Explicit deletion can
repair corrupt records or a missing local key, while private-path, native cache
and surviving SQLite-owner checks still protect live or unrelated files.

## Current proof and remaining work

[Evidence](evidence/receipts.json) covers final
CIGAR 0.14.1 on local macOS arm64, moving notes from CPython 3.14.7 to 3.14.10,
durable reload, source-content refusal, interrupted native acknowledgement and
recovery without replay. A new reviewed replacement is then prepared back to
the prior Python producer; the removed earlier note is not resurrected. The
original SDK continues answering and its checkpoint/manifest remain unchanged.
This is a semantic data round trip on one real SDK release, not a claimed
newer-SDK upgrade or a committed runtime rollback.

Still required: integrate this layer with bounded lifecycle jobs and P6's
serialized settings/selection journal, final source/settings preconditions,
safe actor quiescence, fresh scope authorization and last-good recovery.
Coordinate cancellation, data removal and ready-generation pruning with that
owner. Cover per-scope deletion across retained generations before exposing the
complete workflow. Preserve unmapped/inactive legacy data and its required SDK
files; a global inventory never authorizes combining notes from other scopes.

An enrolled legacy producer can now be constructed from an active, actually
verified v1 runtime. Its identity binds the shipped profile, exact SDK/dependency
tree, worker, external Python executable and measured interpreter facts. The
record says `verified_enrolled_candidate`; it infers no public build ID, release
manifest or upstream source revision from the version string. Persistence
transfer still requires the measured persistence check. Catalog-bound records
retain their previous wire shape and producer fingerprint.

The additional actual fixture enrolls final 0.14.1 bytes through the legacy v1
path, then performs catalog migration, restart recovery and reverse preparation
after an edit. It proves that path without claiming those bytes are the original
b47380 candidate. Original b47380 bytes remain unavailable and unsupported
formats refuse. Public CLI/HTTP/UI controls,
installed/frozen and other-platform qualification, full parent-process crash
injection, production catalog trust/hosting and real newer-release evidence
remain unfinished. No user enablement, selected runtime, Guard execution
approval, live hook or running preview is changed by this data-layer work.
