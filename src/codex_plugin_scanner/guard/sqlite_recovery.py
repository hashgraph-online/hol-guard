"""Bounded proof helpers for recovering an unusable Guard SQLite store."""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from .sqlite_deadline_connection import connect_sqlite_with_deadline
from .sqlite_errors import sqlite_error_is_fatal, sqlite_error_is_io
from .sqlite_tuning import sqlite_operation_deadline_monotonic

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


_SALVAGE_TIMEOUT_SECONDS = 15.0


def salvage_quarantined_state(*, source: Path, destination: Path) -> tuple[bool, bool]:
    """Carry Cloud Review and custom-extension state into the new store.

    ``sqlite_store_salvage.rs`` restores each atomically within its own
    authority boundary and answers ``(cloud_review, local_cli)``. A runtime
    that cannot answer salvages nothing, which leaves the fresh store as an
    empty reinitialization. Normal OAuth, DPoP, capability-signature,
    revocation and request-binding checks still apply afterwards.
    """

    if source.is_symlink() or destination.is_symlink() or not destination.is_file():
        return False, False
    from .mdm.runtime_request import runtime_answer
    from .review_event_wake import review_event_wake_signal
    from .store_local_cli_schema import ensure_local_cli_schema

    # The native copy fills tables this store owns the schema of; a store
    # that cannot take them leaves the local CLI copy to fail on its own.
    with suppress(sqlite3.Error), closing(connect_sqlite_with_deadline(destination, timeout_seconds=1.0)) as dst, dst:
        ensure_local_cli_schema(dst)
    restorable = not _holds_cloud_credentials(destination)
    deadline = time.monotonic() + _SALVAGE_TIMEOUT_SECONDS
    operation_deadline = sqlite_operation_deadline_monotonic()
    answer = runtime_answer(
        "native-sqlite-store-salvage-v1",
        "sqlite-store-salvage",
        {
            "schema": "sqlite-store-salvage.v1",
            "source": str(source.absolute()),
            "destination": str(destination.absolute()),
        },
        output_limit=4096,
        deadline=deadline if operation_deadline is None else min(deadline, operation_deadline),
    )
    if answer is None:
        # The native command commits Cloud Review before it copies
        # custom-extension state and answers, so a lost answer can follow a
        # completed restore. The fresh store holds credentials only then.
        cloud_review = restorable and _holds_cloud_credentials(destination)
        local_cli = False
    else:
        cloud_review = answer.get("cloud_review") is True
        local_cli = answer.get("local_cli") is True
    if cloud_review:
        review_event_wake_signal(destination).notify()
    return cloud_review, local_cli


def _holds_cloud_credentials(destination: Path) -> bool:
    with suppress(sqlite3.Error), closing(connect_sqlite_with_deadline(destination, timeout_seconds=1.0)) as dst:
        found = dst.execute("select 1 from sync_state where state_key = 'oauth_local_credentials'").fetchone()
        return found is not None
    return False
