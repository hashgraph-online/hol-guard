# Native command control binding

The optional `command_extensions` field extends `hol-guard-native-policy.v3`
with `guard.native-command-control-binding.v1`. Its program, catalog, and trust
digests identify the exact packaged native matcher program. Its health, local
revision, managed revision, effective digest, and complete layers reproduce the
existing Python `ExtensionControlRuntimeSnapshot` projection. Native execution
still requires the resident to admit that exact packaged program.

The production publisher requires `native-command-program-v1` and
`native-command-control-fence-v1` together with the existing snapshot/resident
capabilities. A missing capability, missing or
invalid program, catalog mismatch, invalid control binding, or failed verified
authority read closes readiness. It does not emit an unbound legacy snapshot as
a substitute. Direct snapshot builders retain their explicit legacy mode:
omitting `command_extensions` preserves the existing policy digest, signing
bytes, and canonical JSON exactly.

## Authenticated authority and freshness

The publisher worker calls
`GuardStore.read_extension_control_authority_for_registry`. This verifies the
credential-backed local authority and independently authenticated managed
activation/revision, including existing catalog migration behavior. Plain
persisted-authority readers omit managed activation and are insufficient for
this projection. The reader does not compile IR or evaluate matchers.

The immutable control runtime retains independent local and managed revision
floors. A lower protected revision, or different protected effective state at
the same pair of revisions, is rejected. Existing degraded/tampered health is
preserved, and a later unhealthy observation does not erase protected revision
floors.

Local enrollment, mutation, recovery, resumed transitions, managed activation
and removal, and semantic catalog writes invalidate registered publishers and
durably close a signed cross-process marker before changing SQL or credentials.
The retained `extension-control-authority.lock` inode supplies the OS lease:
writers acquire it exclusively; native admission, evaluation and approval
finalization acquire an overlapping shared lease without waiting.

The background publisher verifies unchanged controls under a shared lease,
allowing native decisions concurrently. A semantic-write intent raises before
effects, releases the shared lease, and triggers a complete verified read under
a new exclusive lease. It never upgrades a held shared lease. The immutable
built-in target manifest is compiled outside these leases and cached by the
exact registry, frozen extension tuple, and catalog identity. Custom registries
are not cached. Initial catalog creation can invalidate the publisher's own
candidate, so it recaptures one stable context before sending any IPC.

Publication writes the matching committed marker under the exclusive lease,
then releases it before resident push. The resident validates the signed marker
under its shared lease before accepting even an idempotent push, persists the
new snapshot and floor, and constructs the ACK. The publisher re-verifies after
ACK; its mutation token rejects an older in-flight candidate. No caller waits
for resident IPC while holding the exclusive control lease.

DB/WAL metadata remains an invalidation hint. Bounded markers cover signing
material, the local authority snapshot/latest transition, managed active/revision
state, and managed manifest context. Receipt and unrelated sync-state churn leave
these markers unchanged. Periodic reconciliation independently verifies authority;
a database marker never supplies control authority.

Polling governs how quickly another publisher rebuilds a candidate. It does not
grant stale native authority: a missing, closed, malformed, mismatched or
unverifiable marker fails the resident request. A process that dies after closing
the marker leaves it closed. Background verification can publish only the
actually committed state after that interruption, with the increased fence
revision even when SQL rolled back to unchanged controls.

`GuardStore.recover_extension_control_authority` calls
`_reset_extension_control_authority` through its explicit recovery path; the
daemon requires its existing action grant before invoking recovery. Before
resetting local revision zero, it selects the new authority key and signs a new
epoch linked to the exact MAC-verified prior native control floor. The previous
epoch, fence revision, key identity and complete floor digest must match that
retained floor. Ordinary health changes cannot reset either revision floor.
Recovery evidence is retained across later mutations, and cannot authorize a
second key change in the same epoch. A publisher whose old in-memory runtime
missed another publisher's recovery ACK verifies the current authenticated floor
and its retained predecessor link before catching up.

Missing-key recovery discards catalog manifests authenticated by the lost key
and rebuilds them from the trusted current registry. It preserves independently
authenticated managed state; unavailable managed authentication remains
fail-closed rather than silently removing managed restrictions.

## Marker and recovery wire contract

`native-runtime/command-control-authority.v1.json` is canonical JSON with exact
fields `schema`, `epoch`, `mutation_revision`, `authority_key_id`, `phase`,
`effective_digest`, `recovery`, and `mac`. Epoch and mutation revision are
positive unsigned 64-bit integers. `phase` is `closed` or `committed`;
`effective_digest` is null while closed and the exact control digest while
committed. The snapshot's `command_extensions.authority` contains exactly
`epoch`, `mutation_revision`, `authority_key_id`, and `recovery`.

The MAC is HMAC-SHA256 using the existing derived policy verifier key and
`hol-guard.native-command-control-authority.v1\0 || canonical unsigned record`.
The extension authority key identity is
`SHA256(hol-guard.native-command-control-authority-key.v1\0 || key)`; zeroes
represent the absence of an enrolled key. An explicit recovery object has schema
`guard.native-command-control-recovery.v1`, previous epoch/mutation revision/key
identity, `previous_floor_digest`, and a 32-byte random nonce encoded as hex.
The prior-floor digest is
`SHA256(hol-guard.native-command-control-floor-link.v1\0 || canonical complete floor)`.
Legacy or absent floor authority context uses zeroes. The floor itself remains
authenticated, including when its expired snapshot is absent.

Unix operations use bounded reads, owner/mode/single-link checks, no-follow
opens, retained directory descriptors, complete writes, file/directory fsync,
atomic replacement and identity read-back. Existing owned 0644 lock files are
tightened through the same open inode. Windows uses the existing verified
private-handle replacement helpers and overlapping byte-zero locking. The
reentrant Python lock state is scoped to PID and normalized path, so forked
children must acquire their own OS lease. Unwinding an inherited child context
closes its descriptor without releasing the parent's live lock.

## Managed source contracts

New managed activations capture only their configured targets' trusted source
fingerprints in an authenticated `sourceTargetManifest`. Same-bundle retries
retain that source. Catalog refreshes keep a bounded authenticated context tied
to the exact activation digest, and persist a migration intent before advancing
the protected catalog revision. Repeated reads and interrupted retries cannot
restore an old managed allow after its matcher contract changes. Existing cloud
activations and ACKs are not rewritten during projection. A legacy activation
without authenticated source context conservatively clamps enabled controls
until a newly authorized activation supplies its source; deleting a newer
context can only reconstruct the source already authenticated by the activation.

## Bounds and digest compatibility

| Boundary | Limit and behavior |
| --- | --- |
| Program artifact | At most 4 MiB, regular file, duplicate JSON keys rejected; domain-separated program digest checked before metadata is used |
| Metadata cache | Two exact captured byte strings, at most 8 MiB total; file timestamps alone cannot preserve a cache hit |
| Metadata JSON | At most 64 levels, 16,384 children per collection, and 1,000,000 visited values |
| Control layers | At most two, with distinct `local-admin`/`signed-cloud` kinds |
| Controls | At most 512 per layer; unique `(target_kind, target_id)` within each layer |
| Targets | ASCII `command.*` identifiers, at most 256 characters, with permission kind matching `.permission.` |
| Revisions | Independent unsigned 64-bit local and managed counters; booleans are rejected |
| Control marker | At most 4 KiB, exact canonical authenticated fields, positive epoch and mutation revision |
| Managed source context | At most 512 configured targets, existing 256-character target limit, 512 KiB complete authenticated record |
| Snapshot transport | Existing 256 KiB total snapshot/push envelope limit remains; oversized complete projections fail explicitly |
| Synchronous hook read | Python uses the small acknowledged binding and retains a shared mutation lease for enforcing PreToolUse; Rust checks the bounded marker. The added fence does not read the program, registry, configuration, or credential material. Ordinary review coordination still reads/writes its approval rows. |

When a binding is present, the policy digest adds
`command_extensions_digest = SHA256(canonical binding JSON)`. The generation
fingerprint and snapshot materialization receive the same captured binding.
The existing HMAC authenticates the whole body, including that binding.

Rust's combined authority record may also contain `command_control_floor` with
the highest protected local/managed revisions and effective digest. The Python
cache reader validates this optional shape and its domain-separated floor MAC.
The legacy floor MAC remains unchanged when the field is absent. Optional
`authority` and `previous_floor_digest` authenticate epoch recovery without
discarding its predecessor link. An authenticated legacy raw v3 snapshot without
command bindings has no control floor and can enter the resident's migration
path. The floor is anti-rollback evidence and is never used as a replacement for
verified policy.

## Ordinary review approval binding and finalization

The registered daemon hook path uses the existing local review queue and
resolved-allow reuse. It does not call the separate native v3/v4 approval
claim/consume API. An artifact resolution with `persist_policy=False` records
the ordinary approval row; it does not acquire one-time consumption semantics.

For a native command review, `hook_native_review_binding.py` derives a compact
`guard.native-review-policy-binding.v1` solely from the validated native edge
receipt and its matching typed result. The domain includes the policy, rule,
and runtime digests plus the receipt's complete compact command observation
binding. The policy digest covers the authenticated recovery epoch and mutation
fence even when the effective controls are unchanged. Request payload metadata
cannot supply this domain. Evidence-writer acceptance is independent: declining
an asynchronous receipt write does not remove the current review's authority.

The queued action envelope retains this domain. A resolved allow is reusable
only when the current domain matches exactly along with the existing harness,
tool, launch target, and workspace. Pending deduplication includes the domain
in its action identity, so a new policy cannot overwrite an earlier pending
review while a user is deciding it. An absent binding retains the prior legacy
contract; bound and unbound approvals cannot authorize each other. Snapshot
generation renewal alone does not invalidate a matching policy domain. Native
block decisions bypass this reuse logic.

The enforcing PreToolUse worker first prepares its acknowledged snapshot and
recording posture. A trusted presence flag in the compact acknowledged
projection then selects `native_review_fence`, which acquires the retained
shared control lease before native evaluation and retains it through review
queueing, reuse, and final response rendering. The snapshot wire envelope keeps
its existing fields; the presence flag is internal. Legacy, post-tool, and
recording-only paths perform no added fence I/O. The final allowed response
must still fit the original absolute request deadline. Fence unavailability or
an expired allow uses the existing availability delivery and exactly one
availability route counter; a completed native hard block is preserved.

This extends the native request's control linearization interval through local
approval reuse. A stricter cross-process control writer cannot commit during
that interval. The shared lease is released after the final result is chosen
and before the response is returned. The added Python operations are the secure
retained lock open, bounded regular-file/owner/mode/link/inode checks,
nonblocking shared-lock acquisition with the remaining deadline, and release.
An old owned lock may be tightened in place, and an empty new lock initialized
with its single byte. The path does not load the integrity keyring, guard
configuration, packaged program, or extension registry. No shared-to-exclusive
upgrade or resident publication is performed inside it.

`tests/test_native_review_policy_binding.py` and
`tests/test_native_review_mutation_fence.py` use typed native edge fixtures and
real approval persistence. They cover domain changes, absence-only legacy
behavior, pending-row isolation, payload forgery rejection, unchanged-domain
reuse, deadline/availability accounting, hard-block preservation, and lease
release on timeout, exception, and inherited-context fork unwind. The process
regression pauses actual worker reuse while another process calls the public
control commit API, verifies its SQL revision cannot advance, then verifies
the commit completes after reuse releases the lease. These are source-level
proofs; actual registered launchers, Rust IPC, and Windows fs2/msvcrt overlap
remain separate installed qualification requirements.

### Local component timing, 2026-09-17

The separate `native-review-fence-component-2026-09-17.json` record measures
source commit `8ad5a92d2242ab8a8e98005a89e652bd11a771f0` on a shared Linux x86_64
host with Python 3.12.14 and normal garbage collection. Each component has 200
warm-up calls and 2,000 measured calls using `perf_counter_ns`, with linear
interpolation for percentiles. The retained private lock is initialized before
measurement. The host was coordinated through the shared performance lock;
CPU affinity and other host scheduling were not controlled.

| Component | p50, microseconds | p95, microseconds | p99, microseconds | Maximum, microseconds |
| --- | ---: | ---: | ---: | ---: |
| Unbound context, no added lock I/O | 1.475 | 1.570 | 3.674 | 192.950 |
| Warm shared fence | 22.102 | 88.681 | 225.913 | 3,767.072 |
| Verified review receipt binding | 142.590 | 410.897 | 1,900.077 | 34,818.926 |
| Fence containing binding validation | 253.746 | 792.303 | 17,994.552 | 134,120.467 |

The full tails are retained: the combined p99 was 17.99 ms and maximum was
134.12 ms. This run cannot attribute those pauses to a particular cause. It
measures only the added fence and typed-fixture binding components, with no
resident IPC, approval database, launcher startup, full hook execution, or tool
execution. It is a local diagnostic, not an installed latency/SLO result; the
component percentiles must not be added or subtracted as a full-hook estimate.

`scripts/ci/measure_native_review_fence.py` reproduces the procedure from a
source checkout. Use its `--coordination-lock` and `--source-commit` arguments
after reserving a quiet host interval. It emits bounded aggregate JSON, keeps
all measured samples in the percentiles, and makes no pass/fail SLO judgment.

## Evidence

`tests/test_native_command_control_binding.py` covers existing effective-digest
parity, complete 512+512 control projections, malformed/unknown fields, mutable
caller isolation, absent-field byte compatibility, control-only generation
changes, exact-content metadata caching, malformed/oversized artifacts,
independent revision floors, and optional authority-floor authentication.

`tests/test_native_command_control_binding_publisher.py` covers capability
incomparability, missing-program failure, pre-commit invalidation and ordered
ACK, control changes during ACK without a local callback, local opt-in together
with managed restrictions, managed removal/rollback, WAL tampering, and the
in-memory hook binding boundary.

`tests/test_native_command_control_authority.py` covers exact cross-language
signed vectors, malformed/oversized fields, private short-write/link faults,
shared-reader exclusion of mutations, retained-inode replacement, lexical
reentrancy and fork isolation. `tests/test_native_command_control_authority_publisher.py`
covers closure-sync failure before SQL effects, a real subprocess exit during
an uncommitted mutation, exact retained-floor recovery, tampered floors, missing
keys, stale-publisher recovery catch-up, same-epoch key immutability and
unchanged shared reconciliation. `tests/test_managed_control_manifest_context.py`
covers catalog refresh, crash retries, context deletion/tampering, legacy source
absence and stable source provenance on same-bundle delivery.

Native socket and Windows interoperability qualification must use the compiled
release runtime in CI; Python fixture ACKs alone are not that evidence.

This establishes the Python publication portion of RSP-115. Installed native
matcher admission, complete catalog outcome parity, and end-to-end performance
qualification are separate evidence owned by the native interpreter workstream.
