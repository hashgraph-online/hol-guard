"""Bounded lifecycle maintenance for high-volume Guard evidence.

The SQL batches run in the native resident (``guard_store`` op, method
``maintain_storage``). Python validates the inputs, computes the two cutoff
timestamps, and runs the file-level sweeps once a pass completes."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final, Protocol

from .sqlite_recovery import prune_quarantined_store_snapshots
from .update_staging import prune_stale_update_staging

STORAGE_MAINTENANCE_MIGRATION_VERSION: Final = 20
STORAGE_QUERY_INDEX_MIGRATION_VERSION: Final = 21
DEFAULT_STORAGE_MAINTENANCE_BATCH_SIZE: Final = 500
DEFAULT_RECEIPT_DETAIL_LIMIT: Final = 250_000
DEFAULT_GUARD_EVENT_LIMIT: Final = 250_000
DEFAULT_UPLOADED_CLOUD_EVENT_LIMIT: Final = 10_000
UPLOADED_CLOUD_EVENT_RETAIN_DAYS: Final = 7
STORAGE_MAINTENANCE_BUSY_TIMEOUT_MS: Final = 25
_MAX_BATCH_SIZE: Final = 10_000


@dataclass(frozen=True, slots=True)
class StorageMaintenanceResult:
    ran: bool
    completed: bool
    receipts_archived: int
    native_decision_receipts_deleted: int
    guard_events_deleted: int
    cloud_events_deleted: int
    pages_reclaimed: int


def storage_maintenance_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists guard_storage_maintenance (
          singleton integer primary key check (singleton = 1),
          archived_receipts integer not null default 0,
          last_run_at text,
          last_receipts_archived integer not null default 0,
          last_guard_events_deleted integer not null default 0,
          last_cloud_events_deleted integer not null default 0,
          last_pages_reclaimed integer not null default 0
        )
        """,
        """
        insert or ignore into guard_storage_maintenance (singleton)
        values (1)
        """,
    )


class _StoreOwner(Protocol):
    guard_home: Path

    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


class StoreStorageMaintenanceMixin:
    def maintain_storage(
        self: _StoreOwner,
        *,
        now: datetime,
        detail_retain_days: int,
        batch_size: int = DEFAULT_STORAGE_MAINTENANCE_BATCH_SIZE,
        receipt_detail_limit: int = DEFAULT_RECEIPT_DETAIL_LIMIT,
        guard_event_limit: int = DEFAULT_GUARD_EVENT_LIMIT,
        uploaded_cloud_event_limit: int = DEFAULT_UPLOADED_CLOUD_EVENT_LIMIT,
    ) -> StorageMaintenanceResult:
        _validate_inputs(
            now=now,
            detail_retain_days=detail_retain_days,
            batch_size=batch_size,
            receipt_detail_limit=receipt_detail_limit,
            guard_event_limit=guard_event_limit,
            uploaded_cloud_event_limit=uploaded_cloud_event_limit,
        )
        payload = self._native_store_call(
            "maintain_storage",
            {
                "now": now.isoformat(),
                "cutoff": (now - timedelta(days=detail_retain_days)).isoformat(),
                "cloud_cutoff": (now - timedelta(days=UPLOADED_CLOUD_EVENT_RETAIN_DAYS)).isoformat(),
                "batch_size": batch_size,
                "receipt_detail_limit": receipt_detail_limit,
                "guard_event_limit": guard_event_limit,
                "uploaded_cloud_event_limit": uploaded_cloud_event_limit,
            },
            busy_timeout_seconds=STORAGE_MAINTENANCE_BUSY_TIMEOUT_MS / 1000,
        )
        result = _result_from_payload(payload)
        if result.completed:
            # Maintenance never delays or fails an enforcement request.
            with suppress(sqlite3.Error, TimeoutError):
                self._native_store_call("run_storage_housekeeping", {}, busy_timeout_seconds=0.001)
            # File-level sweeps (not SQL): keep quarantined store snapshots
            # and stale updater staging from accumulating for the whole life
            # of the install.
            with suppress(OSError):
                prune_quarantined_store_snapshots(self.guard_home)
            with suppress(OSError):
                prune_stale_update_staging(self.guard_home)
        return result


def _result_from_payload(payload: object) -> StorageMaintenanceResult:
    if not isinstance(payload, dict):
        raise ValueError("native_storage_maintenance_payload_invalid")
    counts = (
        "receipts_archived",
        "native_decision_receipts_deleted",
        "guard_events_deleted",
        "cloud_events_deleted",
        "pages_reclaimed",
    )
    if type(payload.get("completed")) is not bool or any(
        type(payload.get(name)) is not int or payload[name] < 0 for name in counts
    ):
        raise ValueError("native_storage_maintenance_payload_invalid")
    return StorageMaintenanceResult(
        ran=True,
        completed=payload["completed"],
        receipts_archived=payload["receipts_archived"],
        native_decision_receipts_deleted=payload["native_decision_receipts_deleted"],
        guard_events_deleted=payload["guard_events_deleted"],
        cloud_events_deleted=payload["cloud_events_deleted"],
        pages_reclaimed=payload["pages_reclaimed"],
    )


def _validate_inputs(
    *,
    now: datetime,
    detail_retain_days: int,
    batch_size: int,
    receipt_detail_limit: int,
    guard_event_limit: int,
    uploaded_cloud_event_limit: int,
) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if detail_retain_days < 1:
        raise ValueError("detail_retain_days must be positive")
    if not 1 <= batch_size <= _MAX_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {_MAX_BATCH_SIZE}")
    for name, value in (
        ("receipt_detail_limit", receipt_detail_limit),
        ("guard_event_limit", guard_event_limit),
        ("uploaded_cloud_event_limit", uploaded_cloud_event_limit),
    ):
        if value < 1:
            raise ValueError(f"{name} must be positive")


__all__ = [
    "DEFAULT_GUARD_EVENT_LIMIT",
    "DEFAULT_RECEIPT_DETAIL_LIMIT",
    "DEFAULT_STORAGE_MAINTENANCE_BATCH_SIZE",
    "DEFAULT_UPLOADED_CLOUD_EVENT_LIMIT",
    "STORAGE_MAINTENANCE_BUSY_TIMEOUT_MS",
    "STORAGE_MAINTENANCE_MIGRATION_VERSION",
    "STORAGE_QUERY_INDEX_MIGRATION_VERSION",
    "StorageMaintenanceResult",
    "StoreStorageMaintenanceMixin",
    "storage_maintenance_schema_statements",
]
