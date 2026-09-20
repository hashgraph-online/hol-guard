"""Bounded public failure codes for asynchronous evidence persistence."""

from __future__ import annotations

import errno
import sqlite3
from typing import Final, Literal, cast

EvidenceFailurePhase = Literal[
    "journal_append",
    "receipt_persistence",
    "command_activity_persistence",
    "journal_checkpoint",
    "journal_recovery",
    "journal_rewrite",
]

_PHASES: Final = (
    "journal_append",
    "receipt_persistence",
    "command_activity_persistence",
    "journal_checkpoint",
    "journal_recovery",
    "journal_rewrite",
)
_SQLITE_TYPES: Final = (
    sqlite3.Error,
    sqlite3.Warning,
    sqlite3.InterfaceError,
    sqlite3.DatabaseError,
    sqlite3.DataError,
    sqlite3.OperationalError,
    sqlite3.IntegrityError,
    sqlite3.InternalError,
    sqlite3.ProgrammingError,
    sqlite3.NotSupportedError,
)
_OS_TYPES: Final = (
    OSError,
    PermissionError,
    FileNotFoundError,
    FileExistsError,
    IsADirectoryError,
    NotADirectoryError,
    InterruptedError,
    BlockingIOError,
    BrokenPipeError,
    ConnectionError,
    ConnectionAbortedError,
    ConnectionRefusedError,
    ConnectionResetError,
    TimeoutError,
    ProcessLookupError,
    ChildProcessError,
)
# SQLite's public primary result codes are stable. Literal values keep this
# module importable on supported Python 3.10, which does not export constants
# or attach sqlite_errorcode to driver exceptions. Missing codes stay explicit.
_SQLITE_CODES: Final[dict[int, str]] = {
    5: "sqlite_busy",
    6: "sqlite_locked",
    11: "sqlite_corrupt",
    26: "sqlite_not_a_database",
    8: "sqlite_read_only",
    13: "sqlite_full",
    10: "sqlite_io",
    14: "sqlite_cannot_open",
    19: "sqlite_constraint",
}
_OS_CODES: Final = {
    errno.EACCES: "os_permission",
    errno.EPERM: "os_permission",
    errno.ENOENT: "os_missing",
    errno.ENOSPC: "os_no_space",
    errno.EROFS: "os_read_only",
}
_CODES: Final = frozenset(
    (
        *_SQLITE_CODES.values(),
        *_OS_CODES.values(),
        "sqlite_other",
        "sqlite_code_unavailable",
        "os_other",
        "os_code_unavailable",
        "os_timeout",
        "value_error",
        "type_error",
        "runtime_error",
        "other_exception",
        "unacknowledged",
        "invalid_record",
        "recovery_capacity",
        "recovery_duplicate",
    )
)
_DIAGNOSTIC_KEYS: Final = frozenset(f"{phase}/{code}" for phase in _PHASES for code in _CODES)


def evidence_failure_code(error: BaseException) -> str:
    """Classify exact built-in exceptions without exporting arbitrary details.

    Identity comparisons deliberately exclude user-defined exception subclasses
    and their metaclass, attribute, string, or representation callbacks. Numeric
    codes are read only after an exact built-in type match, then reduced to a
    fixed label. Exception messages and paths are never inspected or retained.
    """

    error_type = type(error)
    if any(error_type is candidate for candidate in _SQLITE_TYPES):
        code = getattr(error, "sqlite_errorcode", None)
        return _SQLITE_CODES.get(code & 0xFF, "sqlite_other") if type(code) is int else "sqlite_code_unavailable"
    if error_type is TimeoutError:
        return "os_timeout"
    if any(error_type is candidate for candidate in _OS_TYPES):
        code = cast(OSError, error).errno
        return _OS_CODES.get(code, "os_other") if type(code) is int else "os_code_unavailable"
    if error_type is ValueError:
        return "value_error"
    if error_type is TypeError:
        return "type_error"
    if error_type is RuntimeError:
        return "runtime_error"
    return "other_exception"


def evidence_failure_snapshot(value: object) -> dict[str, int] | None:
    """Copy only the bounded public counter shape; absent data is unavailable."""

    if type(value) is not dict:
        return None
    fields = cast(dict[object, object], value)
    if len(fields) > len(_DIAGNOSTIC_KEYS):
        return None
    result: dict[str, int] = {}
    for key, count in fields.items():
        if type(key) is not str or key not in _DIAGNOSTIC_KEYS or type(count) is not int or count < 0:
            return None
        result[key] = count
    return result
