"""Lifecycle updates and bounded persistence health for command activity.

Replay checks, transitions and health counters run in the native resident
(``guard_store`` op). Python validates inputs, serializes the activity, and
shapes the persisted row back into its frozen DTO.
"""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Protocol, cast

from .native_guard_store import NativeGuardStoreUnavailable

_ERROR_CODE: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")


_MAX_COUNTER: Final = 2**63 - 1
_ERROR_ACTIVE_COLUMN: Final = {
    "maintenance_failed": "maintenance_error_active",
    "shadow_evaluation_failed": "shadow_error_active",
}
# These fail before `_resident_request`. Any other unavailable reason may mean
# the resident already counted the event, so a local increment would double it.
_PRE_SEND_REASONS: Final = frozenset(
    {
        "native_guard_store_prerequisite_unavailable",
        "native_guard_store_request_invalid",
    }
)


def _count_failure_locally(owner: _ConnectionOwner, error_code: str, occurred_at: datetime) -> None:
    """Outage-only counter write: bounded health bookkeeping, never a verdict."""

    column = _ERROR_ACTIVE_COLUMN.get(error_code, "command_error_active")
    with owner._connect() as connection:
        connection.execute("begin immediate")
        connection.execute(
            "update command_activity_health "
            "set dropped_event_count = min(dropped_event_count + 1, ?), "
            "persistence_error_count = min(persistence_error_count + 1, ?), "
            "last_error_code = ?, last_error_at = ? where singleton = 1",
            (_MAX_COUNTER, _MAX_COUNTER, error_code, occurred_at.isoformat()),
        )
        connection.execute(f"update command_activity_health_active set {column} = 1 where singleton = 1")


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


@dataclass(frozen=True, slots=True)
class CommandActivityPersistenceHealth:
    dropped_event_count: int
    persistence_error_count: int
    active_error_count: int
    last_error_code: str | None
    last_error_at: datetime | None
    schema_version: str


class StoreCommandActivityLifecycleMixin:
    def record_command_activity_persistence_failure(
        self: _ConnectionOwner,
        *,
        error_code: str,
        occurred_at: datetime,
    ) -> None:
        """Count one dropped event and persistence error without unbounded details."""

        _require_error_code(error_code)
        _require_utc_datetime(occurred_at)
        try:
            self._native_store_call(
                "record_command_activity_persistence_failure",
                {"error_code": error_code, "occurred_at": occurred_at.isoformat()},
            )
        except NativeGuardStoreUnavailable as error:
            if error.reason.partition(":")[0] not in _PRE_SEND_REASONS:
                raise
            _count_failure_locally(self, error_code, occurred_at)

    def get_command_activity_persistence_health(
        self: _ConnectionOwner,
    ) -> CommandActivityPersistenceHealth:
        with self._connect() as connection:
            row = cast(
                sqlite3.Row | None,
                connection.execute("select * from command_activity_health where singleton = 1").fetchone(),
            )
            active = cast(
                sqlite3.Row | None,
                connection.execute("select * from command_activity_health_active where singleton = 1").fetchone(),
            )
        if row is None or active is None:
            raise RuntimeError("command activity persistence health is unavailable")
        last_error_at = str(row["last_error_at"]) if row["last_error_at"] is not None else None
        return CommandActivityPersistenceHealth(
            dropped_event_count=int(row["dropped_event_count"]),
            persistence_error_count=int(row["persistence_error_count"]),
            active_error_count=sum(
                int(active[column])
                for column in (
                    "command_error_active",
                    "shadow_error_active",
                    "maintenance_error_active",
                )
            ),
            last_error_code=str(row["last_error_code"]) if row["last_error_code"] is not None else None,
            last_error_at=datetime.fromisoformat(last_error_at) if last_error_at is not None else None,
            schema_version=str(row["schema_version"]),
        )


def _require_error_code(value: str) -> None:
    if not isinstance(cast(object, value), str) or len(value) > 64 or _ERROR_CODE.fullmatch(value) is None:
        raise ValueError("error_code must be a bounded stable identifier")


def _require_utc_datetime(value: datetime) -> None:
    if not isinstance(cast(object, value), datetime) or value.tzinfo is None:
        raise ValueError("occurred_at must be timezone-aware")
    offset = value.utcoffset()
    if offset is None:
        raise ValueError("occurred_at must be timezone-aware")
    if offset.total_seconds() != 0:
        raise ValueError("occurred_at must be UTC")


__all__ = [
    "CommandActivityPersistenceHealth",
    "StoreCommandActivityLifecycleMixin",
]
