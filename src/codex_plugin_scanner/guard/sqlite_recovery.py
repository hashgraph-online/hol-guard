"""Bounded proof helpers for recovering an unusable Guard SQLite store."""

from __future__ import annotations

import os
import sqlite3
import time
from collections.abc import Callable
from contextlib import closing, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .sqlite_deadline_connection import connect_sqlite_with_deadline
from .sqlite_errors import sqlite_error_is_io
from .sqlite_tuning import sqlite_connect_timeout_seconds, sqlite_operation_deadline_monotonic

SQLiteStoreProbe = Literal["fatal", "healthy", "io", "unknown"]
_PROBE_FEATURE = "native-sqlite-store-probe-v1"
_PROBE_TIMEOUT_SECONDS = 10.0
_PROBE_STATES: dict[object, SQLiteStoreProbe] = {state: state for state in ("fatal", "healthy", "io", "unknown")}


@dataclass(frozen=True, slots=True)
class SQLiteStoreProbeDetail:
    """Proof states observed while revalidating a failed store."""

    proven_unusable: bool
    first_state: SQLiteStoreProbe | None
    second_state: SQLiteStoreProbe | None
    guard_home_accepts_write: bool | None
    identity_stable: bool


_UNPROVEN = SQLiteStoreProbeDetail(
    proven_unusable=False,
    first_state=None,
    second_state=None,
    guard_home_accepts_write=None,
    identity_stable=True,
)


def sqlite_store_probe_detail(
    *,
    path: Path,
    guard_home: Path,
    error: BaseException,
    fatal_error: bool,
) -> SQLiteStoreProbeDetail:
    """Revalidate the current path before permitting destructive recovery.

    ``sqlite_store_probe.rs`` proves the store unusable only after two stable
    corrupt probes around a successful write to the Guard home. Without its
    answer nothing is proven, so the store stays in place.
    """

    if not fatal_error and not sqlite_error_is_io(error):
        return _UNPROVEN
    answer = _probe_answer({"op": "detail", "path": str(path.absolute()), "guard_home": str(guard_home.absolute())})
    if answer is None:
        return _UNPROVEN
    accepts_write = answer.get("guard_home_accepts_write")
    return SQLiteStoreProbeDetail(
        proven_unusable=answer.get("proven_unusable") is True,
        first_state=_PROBE_STATES.get(answer.get("first_state")),
        second_state=_PROBE_STATES.get(answer.get("second_state")),
        guard_home_accepts_write=accepts_write if isinstance(accepts_write, bool) else None,
        identity_stable=answer.get("identity_stable") is not False,
    )


def restore_readable_sqlite_store(*, destination: Path, quarantined: Path) -> bool:
    """Move a quarantined store back when it still opens and passes integrity.

    A lost answer counts as a restore only when the store and both sidecars
    already left quarantine.
    """

    answer = _probe_answer(
        {"op": "restore", "path": str(destination.absolute()), "quarantined": str(quarantined.absolute())}
    )
    if answer is not None:
        return answer.get("restored") is True
    return (
        destination.is_file()
        and not destination.is_symlink()
        and not any(os.path.lexists(f"{quarantined}{suffix}") for suffix in ("", "-wal", "-shm"))
    )


def _probe_answer(request: dict[str, object]) -> dict[str, object] | None:
    wait = sqlite_connect_timeout_seconds()
    if wait <= 0:
        raise TimeoutError("Guard storage operation deadline expired.")
    from .mdm.runtime_request import runtime_answer

    deadline = time.monotonic() + _PROBE_TIMEOUT_SECONDS
    operation_deadline = sqlite_operation_deadline_monotonic()
    return runtime_answer(
        _PROBE_FEATURE,
        "sqlite-store-probe",
        {"schema": "sqlite-store-probe.v1", **request, "wait_seconds": wait},
        output_limit=4096,
        deadline=deadline if operation_deadline is None else min(deadline, operation_deadline),
    )


_SALVAGE_TIMEOUT_SECONDS = 15.0


def salvage_quarantined_state(*, source: Path, destination: Path) -> tuple[bool, bool]:
    """Carry Cloud Review and custom-extension state into the new store.

    ``sqlite_store_salvage.rs`` restores each atomically within its own
    authority boundary and answers ``(cloud_review, local_cli)``. When the
    answer is lost, each half is read back from the destination: the fresh
    store holds no credentials or custom-extension grants until a restore
    commits them. Normal OAuth, DPoP, capability-signature, revocation and
    request-binding checks still apply afterwards.
    """

    if source.is_symlink() or destination.is_symlink() or not destination.is_file():
        return False, False
    from .mdm.runtime_request import runtime_answer
    from .review_event_wake import review_event_wake_signal
    from .store_local_cli_schema import ensure_local_cli_schema

    # The native copy fills tables this store owns the schema of; a store
    # that cannot take them leaves the local CLI copy to fail on its own.
    restorable = True
    cli_restorable = True
    with suppress(sqlite3.Error), closing(connect_sqlite_with_deadline(destination, timeout_seconds=1.0)) as dst, dst:
        with suppress(sqlite3.Error):
            restorable = not _holds_cloud_credentials(dst)
        ensure_local_cli_schema(dst)
        with suppress(sqlite3.Error):
            cli_restorable = not _holds_local_cli_grants(dst)
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
        # The native command commits Cloud Review, then custom-extension
        # state, before it answers, so a lost answer can follow a completed
        # restore of either. The fresh store holds their rows only then.
        cloud_review = restorable and _restored(destination, _holds_cloud_credentials)
        local_cli = cli_restorable and _restored(destination, _holds_local_cli_grants)
    else:
        cloud_review = answer.get("cloud_review") is True
        local_cli = answer.get("local_cli") is True
    if cloud_review:
        review_event_wake_signal(destination).notify()
    return cloud_review, local_cli


def _restored(destination: Path, holds: Callable[[sqlite3.Connection], bool]) -> bool:
    with suppress(sqlite3.Error), closing(connect_sqlite_with_deadline(destination, timeout_seconds=1.0)) as dst:
        return holds(dst)
    return False


def _holds_local_cli_grants(connection: sqlite3.Connection) -> bool:
    return connection.execute("select 1 from local_cli_grant limit 1").fetchone() is not None


def _holds_cloud_credentials(connection: sqlite3.Connection) -> bool:
    found = connection.execute("select 1 from sync_state where state_key = 'oauth_local_credentials'").fetchone()
    return found is not None
