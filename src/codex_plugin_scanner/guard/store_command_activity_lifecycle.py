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

from .runtime.command_activity_contract import (
    CommandActivity,
    CommandActivityEvidence,
    CorrelationHandle,
    CorrelationKind,
)
from .store_command_activity_wire import activity_from_wire, activity_wire, evidence_wire, handle_wire

_ERROR_CODE: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")


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
    def is_exact_command_activity_pre_replay(
        self: _ConnectionOwner,
        evidence: CommandActivityEvidence,
    ) -> bool:
        """Return true for one existing logical pre delivery; reject fact conflicts."""

        correlation = evidence.activity.request_correlation
        if correlation is None:
            return False
        _require_request_correlation(correlation)
        return bool(
            self._native_store_call("is_exact_command_activity_pre_replay", {"evidence": evidence_wire(evidence)})
        )

    def get_command_activity_by_request_correlation(
        self: _ConnectionOwner,
        correlation: CorrelationHandle,
    ) -> CommandActivity | None:
        """Resolve one logical command by an exact, strong request handle."""

        _require_request_correlation(correlation)
        row = self._native_store_call(
            "command_activity_by_request_correlation",
            {"correlation": handle_wire(correlation)},
        )
        return activity_from_wire(cast(Mapping[str, object], row)) if row is not None else None

    def transition_command_activity(self: _ConnectionOwner, current: CommandActivity) -> bool:
        """Atomically advance one correlated activity; return false for an exact replay."""

        if not isinstance(cast(object, current), CommandActivity):
            raise ValueError("current must be a CommandActivity")
        correlation = current.request_correlation
        if correlation is None:
            raise ValueError("lifecycle transitions require request correlation")
        _require_request_correlation(correlation)
        return bool(self._native_store_call("transition_command_activity", {"current": activity_wire(current)}))

    def record_command_activity_persistence_failure(
        self: _ConnectionOwner,
        *,
        error_code: str,
        occurred_at: datetime,
    ) -> None:
        """Count one dropped event and persistence error without unbounded details."""

        _require_error_code(error_code)
        _require_utc_datetime(occurred_at)
        self._native_store_call(
            "record_command_activity_persistence_failure",
            {"error_code": error_code, "occurred_at": occurred_at.isoformat()},
        )

    def record_command_activity_observation_conflict(
        self: _ConnectionOwner,
        *,
        occurred_at: datetime,
    ) -> None:
        """Retain one conflicting terminal observation without claiming a persistence outage."""

        _require_utc_datetime(occurred_at)
        self._native_store_call(
            "record_command_activity_observation_conflict",
            {"occurred_at": occurred_at.isoformat()},
        )

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


def _require_request_correlation(correlation: CorrelationHandle) -> None:
    if not isinstance(cast(object, correlation), CorrelationHandle) or correlation.kind is not CorrelationKind.REQUEST:
        raise ValueError("correlation must be an exact request CorrelationHandle")


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
