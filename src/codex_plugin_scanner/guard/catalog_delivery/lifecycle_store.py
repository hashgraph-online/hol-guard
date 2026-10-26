"""Existing protected secret-store IO; Rust authenticates and advances records."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time

from ..native_command_control_authority_io import require_exclusive_command_control_mutation_lease
from ..native_command_control_authority_store import _key
from . import lifecycle

PREFIX = "guard-command-pack-lifecycle"
STAMP = "guard-command-pack-lifecycle-enrolled"
# A native request carries a bounded payload. Control history grows without
# bound, so hand the native walk a file once the chain outgrows the request.
LEGACY_HISTORY_INLINE_BYTES = 1024 * 1024
SPILL_PREFIX = "legacy-history-"
SPILL_SUFFIX = ".jsonl"
# A spill lives for one native call. Anything older than this outlived the
# process that wrote it, so no live migration can still be reading it.
SPILL_ORPHAN_SECONDS = 60 * 60


def _stamp(store):
    return store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(STAMP))


def _mark(store, stamp):
    backend = store._policy_integrity_secret_store
    backend.set_secret(store._build_scoped_secret_ref(STAMP), stamp)
    if _stamp(store) != stamp:
        raise ValueError("pack_lifecycle_protected_write_mismatch")


def read(store):
    backend = store._policy_integrity_secret_store
    if backend is None or store._should_skip_policy_integrity_keychain_access(backend):
        raise ValueError("pack_lifecycle_protected_store_unavailable")
    return store._get_policy_integrity_secret_from_store(store._build_scoped_secret_ref(PREFIX))


def inspect(store):
    record = read(store)
    return record, lifecycle.invoke("read", key=_key(store).hex(), floor=record)


def write(store, record):
    require_exclusive_command_control_mutation_lease(store.guard_home)
    lifecycle.invoke("read", key=_key(store).hex(), floor=record)
    backend = store._policy_integrity_secret_store
    if backend is None or store._should_skip_policy_integrity_keychain_access(backend):
        raise ValueError("pack_lifecycle_protected_store_unavailable")
    backend.set_secret(store._build_scoped_secret_ref(PREFIX), record)
    if read(store) != record:
        raise ValueError("pack_lifecycle_protected_write_mismatch")


def floor_enrolled(store):
    """True when a floor and its enrollment stamp are both already present."""
    return read(store) is not None and _stamp(store) is not None


def enroll_installed(store, authority):
    """Installation enrollment only; never invoked by activation/recovery.

    A missing record in any later API activation is an explicit failure. This
    helper does not recover a lost floor and cannot overwrite a retained one.
    """
    require_exclusive_command_control_mutation_lease(store.guard_home)
    if read(store) is not None or _stamp(store) is not None:
        raise ValueError("pack_lifecycle_already_enrolled")
    result = lifecycle.invoke("enroll", key=_key(store).hex(), **lifecycle.release_evidence(authority))
    _mark(store, result["stamp"])
    write(store, result["record"])


def migrate_installed(store, authority):
    """Startup/installation only, under EX; never a preview repair path.

    Stamp first: an interrupted protected write fails closed on next startup.
    Older native-phase floors may predate the stamp; authenticate and retain
    them exactly. Missing/corrupt stamped floors are never reconstructed.
    """
    require_exclusive_command_control_mutation_lease(store.guard_home)
    with legacy_transport(store) as evidence:
        result = lifecycle.invoke(
            "migrate",
            key=_key(store).hex(),
            floor=read(store),
            stamp=_stamp(store),
            **evidence,
            **lifecycle.release_evidence(authority),
        )
    if result["record"] is not None:
        _mark(store, result["stamp"])
        write(store, result["record"])


@contextlib.contextmanager
def legacy_transport(store, connection=None):
    """Keep the legacy evidence request within the native payload bound.

    An install accumulates one authority transition per policy save and the
    native walk reads them in order, so a long-lived install eventually cannot
    state its own history in a single request. Spill the chain to a private
    file beside the request instead; the native side authenticates every
    record exactly as it does inline, and the file never outlives the call.
    """
    evidence = legacy_evidence(store, connection)
    history = evidence["legacy_history"]
    if sum(len(item["record"]) for item in history if item) <= LEGACY_HISTORY_INLINE_BYTES:
        yield evidence
        return
    from ..native_policy_snapshot_windows_support import _runtime_state_directory

    # The runtime state directory is private state: provision it the way every
    # other writer does, so a default umask cannot leave it world-readable and
    # fail the authority reads this migration exists to restore.
    directory = _runtime_state_directory(store.guard_home)
    _discard_orphaned_spills(directory)
    handle, spilled = tempfile.mkstemp(prefix=SPILL_PREFIX, suffix=SPILL_SUFFIX, dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            for item in history:
                stream.write(json.dumps(item, separators=(",", ":")) + "\n")
        yield {**evidence, "legacy_history": [], "legacy_history_path": spilled}
    finally:
        with contextlib.suppress(OSError):
            os.unlink(spilled)


def _discard_orphaned_spills(directory):
    """Drop chains a terminated process left behind.

    The ordinary exit removes its own file, but a crash during migration
    strands a full history, and interrupted retries accumulate copies of it.
    Only files older than a call could possibly be are removed, so a migration
    running in another process keeps the chain it is still streaming.
    """
    stale = time.time() - SPILL_ORPHAN_SECONDS
    with contextlib.suppress(OSError):
        for entry in os.scandir(directory):
            if not entry.name.startswith(SPILL_PREFIX) or not entry.name.endswith(SPILL_SUFFIX):
                continue
            with contextlib.suppress(OSError):
                if entry.is_file(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_mtime < stale:
                    os.unlink(entry.path)


def legacy_evidence(store, connection=None):
    """Transport retained credential/SQL envelopes; native code binds them."""
    from . import activation_baseline, activation_store

    if connection is None:
        with store._connect() as opened:
            return legacy_evidence(store, opened)
    key = store._authority_key(required=False)
    anchor = store._secret_store().get_secret(store._anchor_ref())
    # This untrusted revision only selects SQL evidence. Rust authenticates the
    # original protected envelope before giving any selected row authority.
    observed_revision = None if anchor is None else json.loads(json.loads(anchor)["record"])["revision"]
    row = connection.execute("select * from extension_control_authority_snapshot where singleton=1").fetchone()

    def envelope(row, prefix):
        return (
            None
            if row is None
            else dict(record=row[prefix + "_json"], digest=row[prefix + "_digest"], mac=row[prefix + "_mac"])
        )

    active = activation_store._row(connection)
    if active is not None and activation_baseline.is_baseline(active["record_json"]):
        activation_baseline.verify(active, _key(store))
        active = None
    pending = transition = None
    if (
        observed_revision is not None
        and connection.execute(
            "select 1 from sqlite_master where type='table' and name='extension_command_pack_pending'"
        ).fetchone()
    ):
        pending = connection.execute(
            "select * from extension_command_pack_pending where control_revision=?", (observed_revision,)
        ).fetchone()
        if pending is not None:
            transition = connection.execute(
                "select * from extension_control_authority_transition where revision=?", (observed_revision,)
            ).fetchone()
    history = (
        []
        if row is None
        else connection.execute(
            "select * from extension_control_authority_transition where revision < ? order by revision desc",
            (row["revision"],),
        ).fetchall()
    )
    return dict(
        legacy_key=None if key is None else key.hex(),
        legacy_anchor=None if anchor is None else json.loads(anchor),
        legacy_snapshot=envelope(row, "snapshot"),
        legacy_activation=envelope(active, "record"),
        legacy_history=[envelope(item, "snapshot") for item in history],
        legacy_transition=envelope(transition, "transition"),
        legacy_next_snapshot=envelope(transition, "snapshot"),
        legacy_pending=None
        if pending is None
        else dict(activation=envelope(pending, "record"), link=envelope(pending, "link")),
    )


def migration_retained(store):
    """Authenticate a no-op startup under SH without creating keys or secrets."""
    floor = read(store)
    if floor is None:
        return False
    stamp = _stamp(store)
    result = lifecycle.invoke("migrate", key=_key(store, create=False).hex(), floor=floor, stamp=stamp)
    return result == {"record": floor, "stamp": stamp}


def check(store, captured, next_record):
    require_exclusive_command_control_mutation_lease(store.guard_home)
    observed, _ = inspect(store)
    if observed != captured and observed != next_record:
        raise ValueError("pack_lifecycle_prepared_floor_conflict")


def commit(store, captured, next_record):
    check(store, captured, next_record)
    write(store, next_record)
