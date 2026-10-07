"""Bounded proof helpers for recovering an unusable Guard SQLite store."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing, suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .sqlite_deadline_connection import connect_sqlite_with_deadline
from .sqlite_errors import sqlite_error_is_fatal, sqlite_error_is_io
from .sqlite_quarantine_forensics import QUARANTINE_FORENSICS_SUFFIX

SQLiteStoreProbe = Literal["fatal", "healthy", "io", "unknown"]
SQLiteFileIdentity = tuple[int, int, int, int, int]
SQLiteStoreIdentity = tuple[SQLiteFileIdentity | None, SQLiteFileIdentity | None, SQLiteFileIdentity | None]


def _sqlite_readonly_uri(path: Path) -> str:
    return f"{path.resolve().as_uri()}?mode=ro"


def _probe_sqlite_store(path: Path) -> SQLiteStoreProbe:
    try:
        with closing(
            connect_sqlite_with_deadline(_sqlite_readonly_uri(path), uri=True, timeout_seconds=1.0)
        ) as connection:
            result = connection.execute("pragma quick_check").fetchone()
    except sqlite3.DatabaseError as error:
        if sqlite_error_is_fatal(error):
            return "fatal"
        if sqlite_error_is_io(error):
            return "io"
        return "unknown"
    return "healthy" if result == ("ok",) else "fatal"


def _guard_home_accepts_sqlite_write(guard_home: Path) -> bool:
    probe_path = guard_home / f"storage-probe-{uuid4().hex}.db"
    try:
        with closing(connect_sqlite_with_deadline(probe_path, timeout_seconds=0.1)) as probe, probe:
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


@dataclass(frozen=True, slots=True)
class SQLiteStoreProbeDetail:
    """Proof states observed while revalidating a failed store."""

    proven_unusable: bool
    first_state: SQLiteStoreProbe | None
    second_state: SQLiteStoreProbe | None
    guard_home_accepts_write: bool | None
    identity_stable: bool


def sqlite_store_probe_detail(
    *,
    path: Path,
    guard_home: Path,
    error: BaseException,
    fatal_error: bool,
) -> SQLiteStoreProbeDetail:
    """Revalidate the current path before permitting destructive recovery."""

    io_error = sqlite_error_is_io(error)
    if not fatal_error and not io_error:
        return SQLiteStoreProbeDetail(
            proven_unusable=False,
            first_state=None,
            second_state=None,
            guard_home_accepts_write=None,
            identity_stable=True,
        )
    initial_identity = _sqlite_store_identity(path)
    first_state = _probe_sqlite_store(path)
    confirmed_identity = _sqlite_store_identity(path)
    identity_stable = initial_identity == confirmed_identity
    if not identity_stable or first_state == "healthy":
        return SQLiteStoreProbeDetail(
            proven_unusable=False,
            first_state=first_state,
            second_state=None,
            guard_home_accepts_write=None,
            identity_stable=identity_stable,
        )
    if first_state != "fatal":
        return SQLiteStoreProbeDetail(
            proven_unusable=False,
            first_state=first_state,
            second_state=None,
            guard_home_accepts_write=None,
            identity_stable=True,
        )
    guard_home_accepts_write = _guard_home_accepts_sqlite_write(guard_home)
    if not guard_home_accepts_write:
        return SQLiteStoreProbeDetail(
            proven_unusable=False,
            first_state=first_state,
            second_state=None,
            guard_home_accepts_write=False,
            identity_stable=True,
        )
    second_state = _probe_sqlite_store(path)
    final_identity = _sqlite_store_identity(path)
    final_stable = confirmed_identity == final_identity
    return SQLiteStoreProbeDetail(
        proven_unusable=second_state == "fatal" and final_stable,
        first_state=first_state,
        second_state=second_state,
        guard_home_accepts_write=guard_home_accepts_write,
        identity_stable=identity_stable and final_stable,
    )


def sqlite_store_is_proven_unusable(
    *,
    path: Path,
    guard_home: Path,
    error: BaseException,
    fatal_error: bool,
) -> bool:
    """Revalidate the current path before permitting destructive recovery."""

    return sqlite_store_probe_detail(
        path=path,
        guard_home=guard_home,
        error=error,
        fatal_error=fatal_error,
    ).proven_unusable


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
        len(stamp) >= 22
        and stamp[:8].isdigit()
        and stamp[8] == "T"
        and stamp[9:15].isdigit()
        and stamp[15:21].isdigit()
        and stamp[21] == "Z"
    ):
        return ("1", stamp, fallback_mtime)
    return ("0", "", fallback_mtime)


def _quarantine_event_base(name: str) -> str:
    """Map a quarantine artifact name to the base database name of its event."""

    for ending in ("-wal", "-shm", QUARANTINE_FORENSICS_SUFFIX):
        if name.endswith(ending):
            return name[: -len(ending)]
    return name


def _quarantine_event_epoch_seconds(base: str, fallback_mtime: float) -> float:
    """Event time from the encoded stamp, or file mtime for legacy names."""

    rank, stamp, _mtime = _quarantine_event_sort_key(base, fallback_mtime)
    if rank != "1":
        return fallback_mtime
    with suppress(ValueError):
        return datetime.strptime(stamp[:22], "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc).timestamp()
    return fallback_mtime


@dataclass(slots=True)
class _QuarantineEvent:
    sort_key: tuple[str, str, float] | None = None
    bytes: int = 0
    mtime: float = 0.0
    has_snapshot: bool = False


def prune_quarantined_store_snapshots(
    guard_home: Path,
    *,
    now: float | None = None,
    min_keep: int = 2,
    max_age: timedelta = timedelta(days=7),
    max_total_bytes: int = 2 * 1024**3,
) -> int:
    """Prune quarantined store snapshots by recency, age, and size budget.

    Every quarantine preserves a full copy of an unusable database, which on
    long-lived installs reaches multiple gigabytes per event. Events are
    ordered newest first by the encoded quarantine stamp; the newest
    ``min_keep`` events always stay, and older events stay only while they
    are within ``max_age`` and the running byte budget. The forensic record
    (``*.forensics.json``) belongs to its event but is never deleted — it is
    tiny and is the only record of why the store was quarantined.
    """

    min_keep = max(0, int(min_keep))
    now_epoch = time.time() if now is None else float(now)
    max_age_seconds = max_age.total_seconds()
    events: dict[str, _QuarantineEvent] = {}
    with suppress(OSError):
        for entry in guard_home.glob("guard.db.corrupt-*"):
            if entry.is_symlink() or not entry.is_file():
                continue
            base = _quarantine_event_base(entry.name)
            try:
                metadata = entry.stat()
            except OSError:
                continue
            event = events.setdefault(base, _QuarantineEvent())
            key = _quarantine_event_sort_key(base, metadata.st_mtime)
            if event.sort_key is None or key > event.sort_key:
                event.sort_key = key
            if not entry.name.endswith(QUARANTINE_FORENSICS_SUFFIX):
                event.bytes += metadata.st_size
                event.has_snapshot = True
            event.mtime = max(event.mtime, metadata.st_mtime)
    ordered = sorted(
        ((base, event) for base, event in events.items() if event.has_snapshot),
        key=lambda item: item[1].sort_key or ("0", "", 0.0),
        reverse=True,
    )
    removed = 0
    kept_bytes = 0
    for index, (base, event) in enumerate(ordered):
        if index < min_keep:
            keep_event = True
        else:
            age_seconds = now_epoch - _quarantine_event_epoch_seconds(base, event.mtime)
            keep_event = age_seconds <= max_age_seconds and kept_bytes + event.bytes <= max_total_bytes
        if keep_event:
            kept_bytes += event.bytes
            continue
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


def quarantined_store_summary(guard_home: Path) -> dict[str, object]:
    """Compact summary of quarantined store snapshots for diagnostics."""

    count = 0
    total_bytes = 0
    forensic_record_count = 0
    newest_epoch: float | None = None
    events: dict[str, float] = {}
    with suppress(OSError):
        for entry in guard_home.glob("guard.db.corrupt-*"):
            if entry.is_symlink() or not entry.is_file():
                continue
            try:
                metadata = entry.stat()
            except OSError:
                continue
            total_bytes += metadata.st_size
            if entry.name.endswith(QUARANTINE_FORENSICS_SUFFIX):
                forensic_record_count += 1
            if not entry.name.endswith(QUARANTINE_FORENSICS_SUFFIX):
                base = _quarantine_event_base(entry.name)
                epoch = _quarantine_event_epoch_seconds(base, metadata.st_mtime)
                previous = events.get(base)
                events[base] = epoch if previous is None else max(previous, epoch)
    count = len(events)
    if events:
        newest_epoch = max(events.values())
    return {
        "count": count,
        "total_bytes": total_bytes,
        "newest_quarantined_at": (
            datetime.fromtimestamp(newest_epoch, tz=timezone.utc).isoformat() if newest_epoch is not None else None
        ),
        "forensic_record_count": forensic_record_count,
    }


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


_LOCAL_CLI_SALVAGE_TABLES = (
    "local_cli_authority",
    "local_cli_observation",
    "local_cli_grant",
    "local_cli_command",
    "local_cli_command_grant",
)
_REQUIRED_LOCAL_CLI_SALVAGE_TABLES = (
    "local_cli_grant",
    "local_cli_command",
    "local_cli_command_grant",
)
_PARTIAL_COPY_OK_TABLES = frozenset(
    {
        "local_cli_authority",
        "local_cli_observation",
        "local_cli_grant",
    }
)


def salvage_local_cli_state(*, source: Path, destination: Path) -> bool:
    """Copy readable custom-extension tables from a quarantined store.

    Full ``quick_check`` can fail after an interrupted update while
    ``local_cli_*`` tables still SELECT. Empty reinit would drop those grants.
    Grant, command catalog, and command-grant copies must all succeed
    (empty tables still count) so an allowed grant cannot restore without
    its scoped catalog.
    """

    if source.is_symlink() or destination.is_symlink() or not destination.is_file():
        return False
    try:
        source_uri = f"{source.resolve().as_uri()}?mode=ro"
        with (
            closing(connect_sqlite_with_deadline(source_uri, uri=True, timeout_seconds=1.0)) as src,
            closing(connect_sqlite_with_deadline(destination, timeout_seconds=1.0)) as dst,
            dst,
        ):
            from .store_local_cli_schema import ensure_local_cli_schema

            ensure_local_cli_schema(dst)
            copied: dict[str, bool] = {}
            for table in _LOCAL_CLI_SALVAGE_TABLES:
                copied[table] = _copy_allowlisted_table(src, dst, table)
            if not all(copied.get(table) for table in _REQUIRED_LOCAL_CLI_SALVAGE_TABLES):
                dst.rollback()
                return False
            dst.commit()
            return True
    except sqlite3.Error:
        return False


def _copy_allowlisted_table(src: sqlite3.Connection, dst: sqlite3.Connection, table: str) -> bool:
    if table not in _LOCAL_CLI_SALVAGE_TABLES:
        return False
    try:
        source_columns = _table_columns(src, table)
        dest_columns = _table_columns(dst, table)
    except sqlite3.Error:
        return False
    shared = [column for column in dest_columns if column in source_columns]
    if not shared:
        return False
    quoted = ",".join(f'"{column}"' for column in shared)
    placeholders = ",".join("?" for _ in shared)
    try:
        cursor = src.execute(f'select {quoted} from "{table}"')
    except sqlite3.Error:
        return False
    inserted = False
    saw_rows = False
    statement = f'insert or replace into "{table}" ({quoted}) values ({placeholders})'
    try:
        for row in cursor:
            saw_rows = True
            try:
                _ = dst.execute(statement, row)
                inserted = True
            except sqlite3.Error:
                if table not in _PARTIAL_COPY_OK_TABLES:
                    return False
                continue
    except sqlite3.Error:
        # Partial command or command-grant copies can drop block rows and
        # widen an allowed grant. Fail those tables closed.
        return inserted if table in _PARTIAL_COPY_OK_TABLES else False
    return inserted or not saw_rows


def _table_columns(connection: sqlite3.Connection, table: str) -> list[str]:
    if table not in _LOCAL_CLI_SALVAGE_TABLES:
        return []
    names: list[str] = []
    for row in connection.execute(f'pragma table_info("{table}")'):
        name = row[1] if isinstance(row, tuple) else row["name"]
        if isinstance(name, str) and name:
            names.append(name)
    return names
