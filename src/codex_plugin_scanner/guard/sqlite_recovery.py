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
SQLiteFileIdentity = tuple[int, int, int, int]
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
        identities.append((metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns))
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
