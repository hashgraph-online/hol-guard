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
        with sqlite3.connect(path, timeout=0.1) as connection:
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
