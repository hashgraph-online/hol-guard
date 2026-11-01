"""Forensic records for quarantined Guard SQLite stores.

Each quarantine event writes a small owner-only JSON record before the store
files move, then updates it with the recovery outcome afterwards. Records carry
no absolute paths so they are safe to retain indefinitely. The native runtime
(`store-quarantine-forensics --stdin`) diagnoses the store header and writes
the records; without it, nothing is recorded.
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sqlite_recovery import SQLiteStoreProbeDetail

QUARANTINE_FORENSICS_SCHEMA = "guard.store-quarantine-forensics.v1"
QUARANTINE_FORENSICS_SUFFIX = ".forensics.json"
_QUARANTINE_FILE_LABELS = (("db", ""), ("wal", "-wal"), ("shm", "-shm"))
_FORENSICS_PROCESS_PATTERN = re.compile(r"^[a-z][a-z-]{0,31}$")
_FEATURE = "native-store-quarantine-forensics-v1"
_SCHEMA = "store-quarantine-forensics.v1"
_TIMEOUT_SECONDS = 10.0


def quarantine_forensics_path(guard_home: Path, quarantine_id: str) -> Path:
    return guard_home / f"guard.db.corrupt-{quarantine_id}{QUARANTINE_FORENSICS_SUFFIX}"


def _forensics_process_name() -> str | None:
    parts = [
        basename
        for argument in sys.argv[:2]
        if _FORENSICS_PROCESS_PATTERN.fullmatch(basename := os.path.basename(argument))
    ]
    return " ".join(parts) if parts else None


def _guard_version() -> str:
    from codex_plugin_scanner.version import __version__

    return __version__


def quarantine_file_stats(path: Path) -> dict[str, dict[str, int]]:
    """File identity metadata for a store's db/-wal/-shm trio (no paths)."""

    stats: dict[str, dict[str, int]] = {}
    for label, suffix in _QUARANTINE_FILE_LABELS:
        candidate = Path(f"{path}{suffix}")
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            metadata = candidate.stat()
        except OSError:
            continue
        stats[label] = {
            "size": metadata.st_size,
            "dev": metadata.st_dev,
            "ino": metadata.st_ino,
            "mtime_ns": metadata.st_mtime_ns,
        }
    return stats


def write_quarantine_forensics(
    *,
    guard_home: Path,
    quarantine_id: str,
    quarantined_at: datetime,
    error: BaseException,
    probe: SQLiteStoreProbeDetail | None,
    files: dict[str, dict[str, int]],
    store_path: Path | None = None,
) -> Path:
    """Persist why a store was quarantined before the store files move.

    The native runtime redacts the Guard home from the message, diagnoses the
    store's first page at `store_path` and writes the owner-only record.
    """

    record: dict[str, object] = {
        "store_path": None if store_path is None else str(store_path),
        "quarantined_at": quarantined_at.isoformat(),
        "error_class": type(error).__name__,
        "error_message": str(error).encode("utf-8", "replace").decode("utf-8"),
        "probe": (
            None
            if probe is None
            else {
                "first_state": probe.first_state,
                "second_state": probe.second_state,
                "guard_home_accepts_write": probe.guard_home_accepts_write,
                "identity_stable": probe.identity_stable,
            }
        ),
        "files": files,
        "pid": os.getpid(),
        "guard_version": _guard_version(),
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_errorcode": _int_or_none(getattr(error, "sqlite_errorcode", None)),
        "sqlite_errorname": _text_or_none(getattr(error, "sqlite_errorname", None)),
        "process": _forensics_process_name(),
    }
    _record(guard_home, quarantine_id, {"op": "record", "record": record})
    return quarantine_forensics_path(guard_home, quarantine_id)


def update_quarantine_forensics_outcome(
    guard_home: Path,
    quarantine_id: str,
    *,
    outcome: str,
    salvage: dict[str, bool] | None = None,
) -> None:
    """Record the recovery outcome on the matching forensics record."""

    _record(
        guard_home,
        quarantine_id,
        {"op": "outcome", "outcome": outcome, "salvage": dict(salvage) if salvage else None},
    )


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _record(guard_home: Path, quarantine_id: str, request: dict[str, object]) -> None:
    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _FEATURE,
        "store-quarantine-forensics",
        {"schema": _SCHEMA, "guard_home": str(guard_home), "quarantine_id": quarantine_id, **request},
        output_limit=256,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    if answer is None:
        raise RuntimeError("quarantine forensics require the native runtime")
    if answer.get("written") is not True:
        error = answer.get("error")
        reason = error if isinstance(error, str) and error.isidentifier() else "unknown"
        raise RuntimeError(f"quarantine forensics were not written: {reason}")
