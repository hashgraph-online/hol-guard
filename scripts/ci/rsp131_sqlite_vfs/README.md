# RSP-131 SQLite and queue observation prerequisite

This is an opt-in diagnostic observation layer. It is not an installed-platform
qualification or a change to Guard's persistence, cache, policy, or hook deadlines.
The original RSP-128/129/131 dependencies and every earlier failed installed run
remain unresolved by this component.

The existing mixed witness counts Python journal writes and file fsync calls.
Those counters cannot see SQLite's C I/O. This extension is loaded by an actual
Python `sqlite3.Connection`, receives that engine's SQLite extension API table,
and registers a unique VFS with `makeDflt=0`. The default VFS is checked unchanged.
The diagnostic store's existing connection factory chooses the name through a URI;
all original connection timeout, transaction, row-factory and PRAGMA logic remains
in the original GuardStore methods.

## Measurements and limits

| Observation | Meaning | It does not establish |
| --- | --- | --- |
| Queue observation | Monotonic enqueue to batch dequeue, by record kind and admission/retry/recovery origin | Journal durability, SQLite commit age, or original age of preexisting/recovered data |
| `vfs_x_write_requested_bytes` | Sum of byte amounts supplied to the original xWrite | Actual kernel or physical bytes |
| `vfs_x_write_success_bytes` | Sum of requested amounts whose original xWrite returned SQLITE_OK | Unique changed bytes, durable bytes, device write amplification |
| `vfs_x_write_error_requested_bytes` | Requested amounts for failed xWrite calls | The unknown prefix possibly written before an error |
| `vfs_x_sync_calls` and error/flag counts | Calls and returns at the original VFS xSync boundary | Kernel fsync/fdatasync counts or directory-sync effects |
| Separate writer/readback/other cells | Connection scope at open; writer is the existing writer Thread object | Per-request tracing, other factories, other processes, or all daemon work |
| Separate main/WAL/rollback/other cells | SQLite's original xOpen file role and associated owned database filename | Kernel descriptor/inode attribution |

SQLite shared-memory callbacks, mmap fetch/unfetch, locking, file controls,
deletion and all other supported methods forward to the original VFS. Mapped
bytes consumed and directory sync effects are not measured. Readback may itself
perform SQLite work; its counters remain separate. Unknown method versions,
cross-thread connection use, foreign database filenames, failed attestation and
counter saturation prevent complete scope attribution.

The report is fixed at 12 cells and 23 integer metrics per cell. Counter overflow
saturates with an explicit flag. It contains no SQL, receipt payload, hook text,
buffers or per-event trace. The C context privately retains the one admitted
database path solely to check associated main/WAL/journal names. The report
contains a digest of that path, runtime image hashes and the actual SQLite API
image name; these are diagnostic metadata.

The extension and each successfully registered callback context stay resident
until process exit. This prevents freeing a callback after the last xClose but
before SQLite finishes its enclosing connection teardown. At most 16 registration
contexts are admitted per loaded extension image. The Python adapter retains at
most 16 verified loader-image descriptors, each for an image at most 8 MiB, per process. This retained diagnostic memory
and the fixed counter/connection-attestation overhead must be included in any
future resource measurement. Every named VFS unregisters after its observed files
close; the module-local proxy restores first. Ending observation with live files
returns a refusal and keeps the callbacks alive. The ordinary process-wide default
VFS is never replaced.

## Host admission and use

The first implementation requires Linux, Python 3.12 or newer with SQLite
extension loading enabled, SQLite 3.31 or newer with mutex support, a POSIX C
compiler, SQLite development headers, and the descriptor loader at
`/proc/self/fd`. macOS, Windows, signing and installed-artifact qualification are
separate future gates. No loader privilege, ptrace grammar or kernel setting is
changed.

The caller compiles the exact reviewed C sources against the selected host SDK,
records the compiler/header/source/binary identities, and supplies the binary
SHA256 explicitly. The adapter verifies the owned regular binary through a held
descriptor and loads that descriptor through the actual Python SQLite connection.
It hashes Python, `_sqlite3`, and the image containing the actual SQLite API-table
function. The actual observer and SQLite API callback mappings must match the
hashed files' device/inode identities. A resident extension without prior
admission, or a changed previously admitted image, is refused. Each verified
image uses one distinct, close-on-exec loader descriptor until process exit;
repeated loads of the same unchanged image reuse that descriptor. This keeps
`/proc/self/fd` loader aliases unique while SQLite retains code permanently.
An attempted load can retain code even if admission later fails, so its loader
descriptor remains quarantined within the same bound. Only images that pass
complete callback and engine attestation enter the admitted-image registry.
The report separates these retained loader descriptors from the named VFS and
database connection closure. The observer-scoped descriptor still rechecks the
image digest and metadata at teardown, then closes.
The extension build hides internal symbols and exports only its load entrypoint. Each observed connection must attest its real database filename,
engine source ID, and exactly one new main-file VFS open.

Example wiring inside an already owned diagnostic fixture (no remote path input):

```python
queue = EvidenceQueueObservation()
vfs = SQLiteVFSObservation(
    database=session.store.path,
    extension=reviewed_binary,
    extension_sha256=reviewed_binary_sha256,
)
mixed = MixedScenarioFixture(session, queue_observation=queue, sqlite_observer=vfs)
```

Alternatively pass the same optional objects to `ReceiptWitness`. They are absent
by default, preserving compatibility with older installed artifacts. Queue
observation and VFS observation can be used independently. After the original
mixed finish/drain/readback, the witness closes the observation and exports its
final aggregates. Inclusive native-finish-to-SQL-readback age is retained
separately; it is never relabeled queue residence.

## Source controls

`tests/test_native_slo_sqlite_vfs.py` contains 10 compiled callback-fixture cases
and 14 Python cases. The C fixture supplies
explicit test callbacks rather than a SQLite engine. It checks versions 1/2/3,
optional callbacks, original arguments/returns/errno, a failed write with a real
prefix side effect, short-read zero-fill preservation, sync errors, open failure
with/without methods, unsupported-version refusal, cross-thread calls and
saturation. It does not claim actual SQLite or kernel I/O.

The separate Python cases load the real extension through Python's actual SQLite
engine and exercise WAL and rollback-journal commit/rollback/busy behavior with
and without observation, concurrent writer/readback connections, cross-thread
scope refusal, name collision, descriptor admission, retained live callbacks,
restored default connections, cleanup failure followed by real admission, and
the actual Guard receipt writer/journal/store path. The receipt fixture is
explicitly a source control; it is not an actual
native authority or installed mixed workload. Original mixed-witness and writer
controls must also be retained in the fresh validation cohort.

The complete component cohort contains 71 cases across SQLite, queue observation,
writer delegation and source-gate controls. Constructor failures must release the
observer lock and detach recovered queue records without changing the original
journal or suppressing the original startup failure.

A local Linux run on Python 3.12 passed all 71 component cases and 54 existing
writer, mixed-workload and persistence-gate regression cases. The SQLite cases
used the actual Python SQLite engine; the receipt source control used Guard's
writer, journal and store. This does not establish installed native execution,
the platform matrix, kernel fsync counts or physical-device write volume.

The compile fixture retains exact compiler arguments, stdout/stderr, return codes,
source and included-header hashes, dependency files and binary hashes. Every
qualification run must bind those records and the exact tested source. Earlier
475/203 controls do not transfer to this component, and passing its source controls
does not establish installed native or platform performance qualification.

Primary interface contracts:
- https://www.sqlite.org/c3ref/io_methods.html
- https://www.sqlite.org/c3ref/vfs.html
- https://www.sqlite.org/c3ref/vfs_find.html
- https://www.sqlite.org/c3ref/uri_boolean.html
- https://www.sqlite.org/loadext.html

## Explicit installed workload

`scripts/bench_guard_native_persistence.py` connects the observers to the existing
isolated daemon's private `mixed_start` control. The request contains only a
bounded absolute extension filename, its exact SHA256 and the bounded queue
capacity. The daemon performs descriptor and ownership admission and loads the
extension through its actual Python SQLite engine before offering observed hooks.
No runtime environment override or alternative policy authority is introduced.
The ordinary mixed workload remains unchanged when this option is absent.

Run the C/SQLite control module first with a source-development Python 3.12
environment and retain its `build-receipt.json`, compiler/dependency records and
exact shared object. Then use the noneditable candidate wheel's interpreter:

```sh
"$INSTALLED_PYTHON" scripts/bench_guard_native_persistence.py \
  --extension "$OWNED_VFS_EXTENSION" --extension-sha256 "$VFS_SHA256" \
  --output persistence-summary.json --ledger persistence-ledger.jsonl \
  --seconds 30 --rate 20 --concurrency 16
```

The runner requires the installed bundled default runtime in auto mode and an
ordinary proof environment. It retains runtime/package, native diagnostic helper
source and extension identities before and after the actual mixed hooks, public
policy updates, local inventory writes and contained resident restart. It keeps
the original workload and performance checks and adds explicit VFS/queue
completeness and closure checks. Its evidence remains a separate instrumented
diagnostic: headline timing eligibility and full RSP-131 qualification stay false,
and kernel fsync counts and physical-device bytes remain unavailable.

The private-control tests use actual C/SQLite, Guard's writer and queue with
synthetic native return values. They also require an unsuccessful witness
constructor or entry to release its admitted VFS before a valid retry. Actual
installed native evidence must come from the executable runner on a host that
supports the product's local socket transport; source controls cannot replace it.
