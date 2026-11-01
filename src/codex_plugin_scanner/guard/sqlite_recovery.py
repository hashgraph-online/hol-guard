"""Bounded proof helpers for recovering an unusable Guard SQLite store."""

from __future__ import annotations

import sqlite3
from contextlib import closing, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .sqlite_deadline_connection import connect_sqlite_with_deadline
from .sqlite_errors import sqlite_error_is_fatal, sqlite_error_is_io

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
    "local_cli_grant_capability",
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
        # Losing a capability row only narrows an allowed grant.
        "local_cli_grant_capability",
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
            # A capability row rides along only with an allowed grant and a
            # restored cli-surface observation, the same two facts the apply
            # required to write it. An observation that failed to copy leaves
            # the row an orphan, so it goes.
            _ = dst.execute(
                "delete from local_cli_grant_capability where cli_id not in "
                "(select grant_row.cli_id from local_cli_grant as grant_row "
                "join local_cli_observation as observed on observed.cli_id = grant_row.cli_id "
                "where grant_row.state = 'allowed' and observed.surface = 'cli')"
            )
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
