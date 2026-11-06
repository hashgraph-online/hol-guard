# Catalog discovery preparation

Discovery is a rebuildable integrity-checked metadata cache, not policy or
activation authority. The existing verified installed/remote factories remain
the only inputs. Rust owns traversal, scheduling, completeness, ownership,
proofs, CAS publication and handle validation. Python performs requested IO.
No policy programs, inactive whole-library JSON or metadata IR are retained by
the resident, and preparation is not called by a hook decision.

## Control-plane readiness

An installed catalog HTTP read starts one background preparation worker and
returns 503 while preparing. The worker performs release verification and
preparation outside the request and lease. Subsequent ordinary UI requests use
the completed handle. Failure automatically retries after a one-second backoff;
there is no user preparation command. There is one background slot, not an
unbounded thread queue. A rejected handle invalidates the readiness and
preparation caches, so the next request initiates proof reconstruction.

Explicit `prepare_discovery` remains a synchronous control-plane API. It
captures a validated executable identity once, checks full file stat identity
at each RPC, and revalidates the runtime at completion. Resident restart loses
the registered handle; preparation rechecks the cached objects before issuing
a new token. A handle is never recovered merely because files exist.

## Additive batching and resources

`catalog-prepare-batch-v1` adds `begin_batched` and `advance_batch` to
`catalog_prepare_v1`. Existing begin/advance/resume/abort/validate operations,
discovery CAS schemas and public read representations remain compatible.
New Python preparation explicitly rejects runtimes lacking the batch feature;
it has no Python algorithm or whole-library fallback.

Rust requests at most 64 independent missing objects per batch. A batch
contains at most 4 MiB decoded object bytes (less than 5.6 MiB base64), within
the existing resident wire budget. Existing 65,536-byte object, 8 MiB assembled
blob, 64-work-step, 64-entry page, four-session and 100,000-extension bounds
remain unchanged. Concat traversal, signed-root completeness and ownership
checks are unchanged. Only compact extension identity/reference rows are kept
until discovery pages are published; each metadata payload is dropped after
processing.

Transient authenticated input retains at most 64 objects (4 MiB). Completed job
roots are discarded. Only overflow is spilled to the existing transport CAS,
so ordinary small records do not each require a filesystem publication. Large
concatenations still progress at fixed memory through verified spill reads.
The public discovery CAS and legacy preparation operations are unchanged.
Resident restart or a fresh batched session may refetch transient input from
the verified source; it never promotes existing display metadata into proof
authority. In-process handle reuse still performs no source fetches. Persisted
cache reads use an operation-local pinned directory descriptor: leaf opens
reject symlinks, check private ownership and stable file identity, enforce the
object byte bound and verify SHA. The three private directory identities and
permissions are checked before and after each read, and full lexical ancestry
is checked at operation boundaries. Canonical JSON and reference length checks
remain in the existing native proof/read layers. Windows retains the existing
secure filesystem reader. No handle survives resident restart.

Output writes share a pinned private directory for each bounded step. On Unix,
temporary creation, atomic publication/repair and cleanup use descriptor-relative
operations, so a renamed parent cannot redirect writes. The descriptor's privacy
is checked for every write, and full namespace identity is rechecked before the
step can publish a handle. Existing-object reads retain all read checks. This
writer rejects every path outside the discovery objects suffix and does not
apply to activation, control or security storage. Other platforms retain the
existing discovery write path.

Global permission ownership uses one private sparse scratch file per session,
not an inode per permission. Open addressing stores an occupied byte plus the
32-byte SHA256 identity. Capacity is the next power of two above twice the
existing extension-count times 512 permission bound. At the maximum it is
2^27 slots, 4.125 GiB logical scratch space per session (16.5 GiB across four
sessions); actual blocks are allocated only for touched slots. A claim uses a
33-byte stack buffer and bounded probing. Duplicate hashes fail closed.
No ownership strings or whole-library permission array are retained. POSIX
unlinks the open scratch file immediately, including cleanup after a crash;
normal completion/abort/error closes it. Windows opens it with delete-on-close
so process termination also reclaims it; normal cleanup closes then removes it.

The installed IO adapter retains only the last bounded ZIP container during a
preparation (the existing 8 MiB metadata-container limit), and checks each requested
member's length and SHA. It drops the container when preparation returns.
The cache is local to preparation; ordinary public `fetch` semantics are
unchanged.

## Publication, corruption and crashes

Only discovery-cache per-object fsyncs are omitted. Temporary private files are
fully written before atomic hard-link publication; repair of a private corrupt
object uses atomic replacement after expected bytes are integrity checked.
Activation, control and security durable storage are untouched.

Power loss may discard cache objects or directory entries. Reads continue to
check SHA, reference length/expansion, canonical JSON and private paths; incomplete
or corrupt content returns unavailable, never a trusted result. Missing or
SHA-corrupt or empty transport objects are fetched again; derived corrupt objects are
rebuilt. Invalid path ownership, symlinks and permissions fail closed. Resident
restart discards all sessions and registered handles. Rebuild requires the
same verified factory boundary and all global proofs again, not trust in the
presence of an on-disk root. Unpublished temporary cache files can be abandoned
by a killed process; they are never addressed by digest or treated as handles.
