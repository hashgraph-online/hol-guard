"""Bounded rollup reconciliation and retention for command activity.

Backfill, retention and rebuild run in the native resident (``guard_store``
op). Python validates inputs and supplies the wall-clock instant plus the
calendar boundaries derived from it.
"""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Final, Protocol, cast

COMMAND_ACTIVITY_AGGREGATE_MONTHS: Final = 13
DEFAULT_COMMAND_ACTIVITY_MAINTENANCE_BATCH_SIZE: Final = 1_000
_MAX_BATCH_SIZE: Final = 10_000
_MAX_RETENTION_DAYS: Final = 3_650


class _NativeOwner(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


@dataclass(frozen=True, slots=True)
class CommandActivityMaintenanceResult:
    ran: bool
    completed: bool
    backfilled_rows: int
    detail_rows_deleted: int
    correlation_rows_deleted: int
    aggregate_rows_deleted: int


class StoreCommandActivityMaintenanceMixin:
    def maintain_command_activity(
        self: _NativeOwner,
        *,
        now: datetime,
        detail_retain_days: int,
        batch_size: int = DEFAULT_COMMAND_ACTIVITY_MAINTENANCE_BATCH_SIZE,
    ) -> CommandActivityMaintenanceResult:
        """Run at most one crash-safe batch until today's work is complete."""

        _validate_maintenance_inputs(now, detail_retain_days, batch_size)
        outcome = cast(
            list[Any],
            self._native_store_call(
                "maintain_command_activity",
                {
                    "now": now.isoformat(),
                    "today": now.date().isoformat(),
                    "detail_cutoff": (now - timedelta(days=detail_retain_days)).isoformat(),
                    "aggregate_cutoff": _aggregate_cutoff(now).isoformat(),
                    "batch_size": batch_size,
                },
            ),
        )
        return CommandActivityMaintenanceResult(
            bool(outcome[0]),
            bool(outcome[1]),
            int(outcome[2]),
            int(outcome[3]),
            int(outcome[4]),
            int(outcome[5]),
        )

    def rebuild_command_activity_rollups(
        self: _NativeOwner,
        *,
        now: datetime,
    ) -> None:
        """Rebuild all retained-detail aggregates atomically for reconciliation."""

        _require_utc(now)
        self._native_store_call("rebuild_command_activity_rollups", {"now": now.isoformat()})

    def command_activity_rollups_are_reconciled(self: _NativeOwner) -> bool:
        return bool(self._native_store_call("command_activity_rollups_are_reconciled", {}))


def _aggregate_cutoff(now: datetime) -> date:
    month_index = now.year * 12 + now.month - 1 - (COMMAND_ACTIVITY_AGGREGATE_MONTHS - 1)
    return date(month_index // 12, month_index % 12 + 1, 1)


def _validate_maintenance_inputs(now: datetime, detail_retain_days: int, batch_size: int) -> None:
    _require_utc(now)
    if isinstance(detail_retain_days, bool) or not 1 <= detail_retain_days <= _MAX_RETENTION_DAYS:
        raise ValueError(f"detail_retain_days must be between 1 and {_MAX_RETENTION_DAYS}")
    if isinstance(batch_size, bool) or not 1 <= batch_size <= _MAX_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {_MAX_BATCH_SIZE}")


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")


__all__ = [
    "COMMAND_ACTIVITY_AGGREGATE_MONTHS",
    "DEFAULT_COMMAND_ACTIVITY_MAINTENANCE_BATCH_SIZE",
    "CommandActivityMaintenanceResult",
    "StoreCommandActivityMaintenanceMixin",
]
