# Settings commit lane for CIGAR switching

The native Unix settings writer now uses one protected profile lock for its
read/compute/replace operation. A concurrent writer receives `config_write_busy`
without waiting for SDK work. The same lane is available to P6's final selection
commit. CIGAR artifact acquisition, interpreter setup, SDK probes and candidate
data preparation must finish before taking it.

The lock is a pinned private, owner-held, single-link regular file. Directory
and lock identity are checked again before publication. Writes use an exclusive
private temporary file, file sync, descriptor-relative atomic rename and parent
directory sync. Existing read-only modes and ACL write refusals remain effective;
an atomic rename cannot bypass them. Expected previous bytes are checked under
the lock immediately before replacement; stale protected config refuses. All native settings/channel/
reset writes share the lane. Invalid channel input still creates no profile.
Ordinary settings readers and CIGAR status reads do not acquire this lock.

Stop revokes in-memory authority first through the existing service. Its disk
step now reads the latest preferences inside the writer lock before narrowing
only enablement. A busy write cannot silently overwrite a newer selected runtime,
source set or retention preference. Existing settings compute/parity behavior
and Guard execution approvals are unchanged.

An error after rename reports `config_commit_outcome_unknown`. The file may
already contain the intended selection, so a future switch recovery must inspect
the exact protected settings and journal; it cannot blindly replay or reverse
the operation. No error cleanup deletes the committed config. A subsequent
writer can remove only recognized private orphan staging files under its lock:
at most 32 files of at most 1 MiB each, found in a bounded 4096-entry profile
listing. Unknown names stay untouched. Links, ownership/mode changes and an
over-limit batch refuse instead of deleting ambiguous files.

The new commit implementation is Unix-specific. Other hosts retain their
existing settings writer and have no new CIGAR switching qualification from this
change. Local macOS source tests are not installed/frozen or cross-platform
qualification. Abrupt parent-loss injection remains a P9 requirement.

The [native selection owner](CIGAR_NATIVE_SELECTION.md) now uses this writer
lane for exact SDK/data pairs and a profile-bound write-ahead journal, with fresh
Service activation and compatible interrupted-commit recovery. Its shared
preparation lease is independent of installation storage, so off-state data
repair does not create an installation registry. Central live switch jobs,
final epoch/policy/source/settings coordination, cancellation, all recovery
and rollback effects and public controls remain P6–P8 work. External editors
do not participate in the writer protocol; observed changes refuse, and final
policy/settings checks remain necessary around a cutover.

See [evidence](evidence/upgrades-legacy-producer-config-20261027.json) for the
enrolled/catalog data tests and settings commit regressions, and
[prepared evidence](CIGAR_PREPARED_EVIDENCE.md) for the data contract.

The later [ordinary settings opt-in checkpoint](CIGAR_SETTINGS_OPT_IN.md) moves verification outside this short writer lane while retaining the shared lifecycle lease through exact-byte CAS. It fixes recursive catalog-lock acquisition after authenticated import. Concurrent edits and home replacement refuse; every explicit Stop advances a native intent fence, including while already off. Final real SDK tests cover ordinary enablement and the existing live switch/rollback flow. This checkpoint does not complete P7 off-state SDK/data selection or the remaining P6/P9 qualification.
