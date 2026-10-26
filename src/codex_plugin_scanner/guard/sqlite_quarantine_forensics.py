"""Forensic records for quarantined Guard SQLite stores.

Each quarantine event writes a small owner-only JSON record before the store
files move, then updates it with the recovery outcome afterwards. Records carry
no absolute paths so they are safe to retain indefinitely.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import uuid4

if TYPE_CHECKING:
    from .sqlite_recovery import SQLiteStoreProbeDetail

QUARANTINE_FORENSICS_SCHEMA = "guard.store-quarantine-forensics.v1"
QUARANTINE_FORENSICS_SUFFIX = ".forensics.json"
_QUARANTINE_FILE_LABELS = (("db", ""), ("wal", "-wal"), ("shm", "-shm"))
_FORENSICS_PROCESS_PATTERN = re.compile(r"^[a-z][a-z-]{0,31}$")
_FORENSICS_MESSAGE_LIMIT = 500


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


_SQLITE_MAGIC = b"SQLite format 3\x00"
_BTREE_PAGE_KINDS = {
    0x02: "interior-index",
    0x05: "interior-table",
    0x0A: "leaf-index",
    0x0D: "leaf-table",
}
# SQLite 3.7.0 through 3.51.2 can corrupt a WAL database when several
# connections write and checkpoint concurrently (the "WAL-reset" bug).
_WAL_RESET_BUG_FIXED_IN = (3, 51, 3)


def sqlite_wal_reset_bug_possible(version: tuple[int, ...] | None = None) -> bool:
    """True when the linked SQLite predates the WAL-reset corruption fix."""

    return (version if version is not None else sqlite3.sqlite_version_info) < _WAL_RESET_BUG_FIXED_IN


def sqlite_header_diagnosis(path: Path) -> dict[str, object]:
    """Classify the first database page without recording any file content.

    Distinguishes a store whose page 1 was overwritten by another page (a
    stray write or stale WAL checkpoint) from a truncated, zeroed or foreign
    file. Only magic-match, page-kind label and sizes are returned.
    """

    diagnosis: dict[str, object] = {}
    try:
        if path.is_symlink() or not path.is_file():
            return diagnosis
        size = path.stat().st_size
        with path.open("rb") as handle:
            head = handle.read(100)
    except OSError:
        return diagnosis
    diagnosis["file_size"] = size
    diagnosis["header_magic_ok"] = head[:16] == _SQLITE_MAGIC
    if head and not any(head):
        diagnosis["header_zeroed"] = True
    if len(head) >= 100 and diagnosis["header_magic_ok"]:
        raw_page_size = int.from_bytes(head[16:18], "big")
        page_size = 65536 if raw_page_size == 1 else raw_page_size
        diagnosis["page_size_field"] = page_size
        if 512 <= page_size <= 65536 and page_size & (page_size - 1) == 0:
            diagnosis["size_multiple_of_page"] = size % page_size == 0
        diagnosis["wal_mode_header"] = head[18] == 2 and head[19] == 2
    if not diagnosis["header_magic_ok"] and head:
        kind = _BTREE_PAGE_KINDS.get(head[0])
        if kind is not None:
            diagnosis["page1_looks_like_btree_page"] = kind
    return diagnosis


def _atomic_owner_only_json_write(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            handle.write(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def write_quarantine_forensics(
    *,
    guard_home: Path,
    quarantine_id: str,
    quarantined_at: datetime,
    error: BaseException,
    probe: SQLiteStoreProbeDetail | None,
    files: dict[str, dict[str, int]],
    header: dict[str, object] | None = None,
) -> Path:
    """Persist why a store was quarantined before the store files move."""

    payload: dict[str, object] = {
        "schema": QUARANTINE_FORENSICS_SCHEMA,
        "quarantine_id": quarantine_id,
        "quarantined_at": quarantined_at.isoformat(),
        "error_class": type(error).__name__,
        "error_message": str(error).replace(str(guard_home), "<guard_home>")[:_FORENSICS_MESSAGE_LIMIT],
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
        "sqlite_wal_reset_bug_possible": sqlite_wal_reset_bug_possible(),
    }
    if header:
        payload["header"] = header
    sqlite_errorcode = getattr(error, "sqlite_errorcode", None)
    sqlite_errorname = getattr(error, "sqlite_errorname", None)
    if sqlite_errorcode is not None:
        payload["sqlite_errorcode"] = sqlite_errorcode
    if sqlite_errorname is not None:
        payload["sqlite_errorname"] = sqlite_errorname
    process = _forensics_process_name()
    if process is not None:
        payload["process"] = process
    path = quarantine_forensics_path(guard_home, quarantine_id)
    _atomic_owner_only_json_write(path, payload)
    return path


def update_quarantine_forensics_outcome(
    guard_home: Path,
    quarantine_id: str,
    *,
    outcome: str,
    salvage: dict[str, bool] | None = None,
) -> None:
    """Record the recovery outcome on the matching forensics record."""

    path = quarantine_forensics_path(guard_home, quarantine_id)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        payload = loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        payload = {}
    payload.setdefault("schema", QUARANTINE_FORENSICS_SCHEMA)
    payload.setdefault("quarantine_id", quarantine_id)
    payload["outcome"] = outcome
    if salvage:
        payload["salvage"] = dict(salvage)
    _atomic_owner_only_json_write(path, payload)
