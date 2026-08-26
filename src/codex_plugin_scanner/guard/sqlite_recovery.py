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


def _probe_sqlite_store(path: Path) -> SQLiteStoreProbe:
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.0) as connection:
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
    state = _probe_sqlite_store(path)
    if state == "healthy":
        return False
    if state == "fatal":
        return True
    if state != "io" or not _guard_home_accepts_sqlite_write(guard_home):
        return False
    return _probe_sqlite_store(path) in {"fatal", "io"}


def restore_readable_sqlite_store(*, destination: Path, quarantined: Path) -> bool:
    """Move a quarantined store back when it still opens and passes integrity."""

    if destination.exists() or destination.is_symlink():
        return False
    if _probe_sqlite_store(quarantined) != "healthy":
        return False
    try:
        quarantined.replace(destination)
        for suffix in ("-wal", "-shm"):
            extra = Path(f"{quarantined}{suffix}")
            if extra.exists() and not extra.is_symlink():
                extra.replace(Path(f"{destination}{suffix}"))
        return True
    except OSError:
        return False
