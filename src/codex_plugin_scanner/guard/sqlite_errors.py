"""SQLite failure routing with authoritative primary and extended codes."""

from __future__ import annotations

import sqlite3
from typing import Final, Literal

SQLiteFailureKind = Literal["busy", "locked", "io", "full", "corrupt", "other"]
FATAL_SQLITE_ERROR_MARKERS = (
    "database disk image is malformed",
    "database corruption",
    "file is not a database",
)
SQLITE_IO_ERROR_MARKER = "disk i/o error"
# SQLite's stable primary result codes; named sqlite3 exports require Python
# 3.11, while Guard also supports 3.10 and its text-only exceptions.
_SQLITE_BUSY: Final = 5
_SQLITE_LOCKED: Final = 6
_SQLITE_IOERR: Final = 10
_SQLITE_CORRUPT: Final = 11
_SQLITE_FULL: Final = 13
_SQLITE_NOTADB: Final = 26


def sqlite_failure_kind(error: BaseException) -> SQLiteFailureKind:
    if not isinstance(error, sqlite3.DatabaseError):
        return "other"
    code = getattr(error, "sqlite_errorcode", None)
    if isinstance(code, int) and not isinstance(code, bool):
        # Extended codes retain the primary code in their low byte. Keep the
        # original error intact for diagnostics; routing alone uses that byte.
        primary = code & 0xFF
        if primary == _SQLITE_BUSY:
            return "busy"
        if primary == _SQLITE_LOCKED:
            return "locked"
        if primary == _SQLITE_IOERR:
            return "io"
        if primary == _SQLITE_FULL:
            return "full"
        if primary in {_SQLITE_CORRUPT, _SQLITE_NOTADB}:
            return "corrupt"
        return "other"
    # Legacy/injected errors may lack numeric metadata. Never let text
    # override a numeric code supplied by SQLite.
    message = str(error).lower()
    if any(marker in message for marker in FATAL_SQLITE_ERROR_MARKERS):
        return "corrupt"
    if SQLITE_IO_ERROR_MARKER in message:
        return "io"
    if isinstance(error, sqlite3.OperationalError):
        if "locked" in message:
            return "locked"
        if "busy" in message:
            return "busy"
    return "other"


def sqlite_error_is_busy_locked(error: BaseException) -> bool:
    return sqlite_failure_kind(error) in {"busy", "locked"}


def sqlite_error_is_fatal(error: BaseException) -> bool:
    return sqlite_failure_kind(error) == "corrupt"


def sqlite_error_is_io(error: BaseException) -> bool:
    return sqlite_failure_kind(error) == "io"
