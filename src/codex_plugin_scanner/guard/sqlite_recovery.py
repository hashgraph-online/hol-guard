"""Bounded proof helpers for recovering an unusable Guard SQLite store."""

from __future__ import annotations

import sqlite3
from contextlib import suppress
from pathlib import Path
from typing import Literal
from uuid import uuid4

FATAL_SQLITE_ERROR_MARKERS = (
    "database disk image is malformed",
    "database corruption",
    "file is not a database",
)
SQLITE_IO_ERROR_MARKER = "disk i/o error"
SQLiteStoreProbe = Literal["fatal", "healthy", "io", "unknown"]
SQLiteFileIdentity = tuple[int, int, int, int, int]
SQLiteStoreIdentity = tuple[SQLiteFileIdentity | None, SQLiteFileIdentity | None, SQLiteFileIdentity | None]


def _sqlite_readonly_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro"


def _probe_sqlite_store(path: Path) -> SQLiteStoreProbe:
    try:
        with sqlite3.connect(_sqlite_readonly_uri(path), uri=True, timeout=1.0) as connection:
            result = connection.execute("pragma quick_check").fetchone()
    except sqlite3.DatabaseError as error:
        message = str(error).lower()
        if any(marker in message for marker in FATAL_SQLITE_ERROR_MARKERS):
            return "fatal"
        if SQLITE_IO_ERROR_MARKER in message:
            return "io"
        return "unknown"
    return "healthy" if result == ("ok",) else "fatal"


def _guard_home_accepts_sqlite_write(guard_home: Path) -> bool:
    probe_path = guard_home / f"storage-probe-{uuid4().hex}.db"
    try:
        with sqlite3.connect(probe_path, timeout=0.1) as probe:
            probe.execute("create table probe (value integer)")
            probe.execute("insert into probe values (1)")
        return probe_path.is_file()
    except sqlite3.DatabaseError:
        return False
    finally:
        with suppress(OSError):
            probe_path.unlink()


def _sqlite_store_identity(path: Path) -> SQLiteStoreIdentity:
    identities: list[SQLiteFileIdentity | None] = []
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            metadata = candidate.stat()
        except OSError:
            identities.append(None)
            continue
        identities.append(
            (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        )
    return identities[0], identities[1], identities[2]


def sqlite_store_is_proven_unusable(
    *,
    path: Path,
    guard_home: Path,
    error: BaseException,
    fatal_error: bool,
) -> bool:
    """Revalidate the current path before permitting destructive recovery."""

    io_error = SQLITE_IO_ERROR_MARKER in str(error).lower()
    if not fatal_error and not io_error:
        return False
    initial_identity = _sqlite_store_identity(path)
    first_state = _probe_sqlite_store(path)
    confirmed_identity = _sqlite_store_identity(path)
    if initial_identity != confirmed_identity or first_state == "healthy":
        return False
    if first_state != "fatal" or not _guard_home_accepts_sqlite_write(guard_home):
        return False
    second_state = _probe_sqlite_store(path)
    final_identity = _sqlite_store_identity(path)
    return second_state == "fatal" and confirmed_identity == final_identity


def _quarantine_event_sort_key(base: str, fallback_mtime: float) -> tuple[str, str, float]:
    """Order quarantine events by the timestamp encoded in their id.

    ``Path.replace`` preserves the moved file's mtime, which is the source
    database's last write — not the moment of quarantine — so a newly
    quarantined long-idle database must not sort as older than an earlier
    event. The ``...-<stamp>Z-<uuid>`` suffix encodes the event time; names
    without a parseable stamp fall back to mtime and sort oldest.
    """

    name = base
    stamp = ""
    if name.startswith("guard.db.corrupt-"):
        stamp = name[len("guard.db.corrupt-") :]
    # Only the exact `%Y%m%dT%H%M%S%fZ` quarantine shape ranks as stamped;
    # a digit-led but malformed name must not outrank real event ids.
    if (
        len(stamp) >= 21
        and stamp[:8].isdigit()
        and stamp[8] == "T"
        and stamp[9:15].isdigit()
        and stamp[15:21].isdigit()
        and stamp[21] == "Z"
    ):
        return ("1", stamp, fallback_mtime)
    return ("0", "", fallback_mtime)


def prune_quarantined_store_snapshots(guard_home: Path, *, keep: int = 2) -> int:
    """Delete the oldest quarantined store snapshots beyond ``keep`` events.

    Every quarantine preserves a full copy of an unusable database, which on
    long-lived installs reaches multiple gigabytes per event. Without this
    sweep the Guard home grows without bound and every later start pays for
    it. The newest ``keep`` events stay available for support diagnostics.
    """

    keep = max(0, int(keep))
    groups: dict[str, tuple[str, str, float]] = {}
    with suppress(OSError):
        for entry in guard_home.glob("guard.db.corrupt-*"):
            if entry.is_symlink() or not entry.is_file():
                continue
            # Group the base database with its -wal/-shm sidecars by the
            # shared quarantine id prefix.
            name = entry.name
            base = name
            for ending in ("-wal", "-shm"):
                if name.endswith(ending):
                    base = name[: -len(ending)]
                    break
            try:
                modified = entry.stat().st_mtime
            except OSError:
                continue
            key = _quarantine_event_sort_key(base, modified)
            previous = groups.get(base)
            groups[base] = key if previous is None else max(previous, key)
    if keep >= len(groups):
        return 0
    stale_prefixes = sorted(groups, key=groups.__getitem__, reverse=True)[keep:]
    removed = 0
    for base in stale_prefixes:
        for ending in ("", "-wal", "-shm"):
            candidate = guard_home / f"{base}{ending}"
            with suppress(OSError):
                # Recheck before unlinking: a sidecar may have been swapped
                # for a symlink since the grouping pass, and a dangling link
                # must never be followed or counted as a removed snapshot.
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                candidate.unlink()
                removed += 1
    return removed


def restore_readable_sqlite_store(*, destination: Path, quarantined: Path) -> bool:
    """Move a quarantined store back when it still opens and passes integrity."""

    if destination.exists() or destination.is_symlink():
        return False
    if _probe_sqlite_store(quarantined) != "healthy":
        return False
    extras = [
        (Path(f"{quarantined}{suffix}"), Path(f"{destination}{suffix}"))
        for suffix in ("-wal", "-shm")
        if Path(f"{quarantined}{suffix}").exists() and not Path(f"{quarantined}{suffix}").is_symlink()
    ]
    try:
        quarantined.replace(destination)
    except OSError:
        return False
    moved: list[tuple[Path, Path]] = []
    try:
        for source, target in extras:
            source.replace(target)
            moved.append((source, target))
        return True
    except OSError:
        for source, target in reversed(moved):
            with suppress(OSError):
                target.replace(source)
        with suppress(OSError):
            destination.replace(quarantined)
        return False
