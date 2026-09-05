"""Bounded lifecycle maintenance for high-volume Guard evidence."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from contextlib import AbstractContextManager, suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol, cast

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


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


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


class StoreStorageMaintenanceMixin:
    def maintain_storage(
        self: _ConnectionOwner,
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
        with self._connect() as connection:
            connection.execute(f"pragma busy_timeout={STORAGE_MAINTENANCE_BUSY_TIMEOUT_MS}")
            connection.execute("begin immediate")
            receipts_archived = _archive_receipt_batch(
                connection,
                cutoff=now - timedelta(days=detail_retain_days),
                detail_limit=receipt_detail_limit,
                batch_size=batch_size,
            )
            native_decision_receipts_deleted = _delete_native_decision_receipt_batch(
                connection,
                cutoff=now - timedelta(days=detail_retain_days),
                detail_limit=receipt_detail_limit,
                batch_size=batch_size,
            )
            guard_events_deleted = _delete_guard_event_batch(
                connection,
                cutoff=now - timedelta(days=detail_retain_days),
                detail_limit=guard_event_limit,
                batch_size=batch_size,
            )
            cloud_events_deleted = _delete_uploaded_cloud_event_batch(
                connection,
                cutoff=now - timedelta(days=UPLOADED_CLOUD_EVENT_RETAIN_DAYS),
                detail_limit=uploaded_cloud_event_limit,
                batch_size=batch_size,
            )
            pages_reclaimed = _reclaim_free_pages(connection, batch_size=batch_size)
            completed = all(
                count < batch_size
                for count in (
                    receipts_archived,
                    native_decision_receipts_deleted,
                    guard_events_deleted,
                    cloud_events_deleted,
                )
            )
            connection.execute(
                """
                update guard_storage_maintenance
                set archived_receipts = archived_receipts + ?,
                    last_run_at = ?,
                    last_receipts_archived = ?,
                    last_guard_events_deleted = ?,
                    last_cloud_events_deleted = ?,
                    last_pages_reclaimed = ?
                where singleton = 1
                """,
                (
                    receipts_archived,
                    now.isoformat(),
                    receipts_archived,
                    guard_events_deleted,
                    cloud_events_deleted,
                    pages_reclaimed,
                ),
            )
        if completed:
            _run_passive_housekeeping(self)
            # File-level sweeps (not SQL): keep quarantined store snapshots
            # and stale updater staging from accumulating for the whole life
            # of the install.
            with suppress(OSError):
                prune_quarantined_store_snapshots(self.guard_home)
            with suppress(OSError):
                prune_stale_update_staging(self.guard_home)
        return StorageMaintenanceResult(
            ran=True,
            completed=completed,
            receipts_archived=receipts_archived,
            native_decision_receipts_deleted=native_decision_receipts_deleted,
            guard_events_deleted=guard_events_deleted,
            cloud_events_deleted=cloud_events_deleted,
            pages_reclaimed=pages_reclaimed,
        )


def _archive_receipt_batch(
    connection: sqlite3.Connection,
    *,
    cutoff: datetime,
    detail_limit: int,
    batch_size: int,
) -> int:
    boundary = _rowid_boundary(connection, table="runtime_receipts", detail_limit=detail_limit)
    rows = cast(
        Sequence[sqlite3.Row],
        connection.execute(
            """
            select r.receipt_id
            from runtime_receipts as r
            where (r.timestamp < ? or (? is not null and r.rowid <= ?))
              and not exists (
                select 1 from guard_cloud_events as cloud
                where cloud.idempotency_key = 'receipt.created:' || r.receipt_id
                  and cloud.uploaded_at is null
              )
              and not exists (
                select 1 from approval_requests as approval
                where approval.request_id = r.approval_request_id
                  and approval.status = 'pending'
              )
            order by r.timestamp
            limit ?
            """,
            (cutoff.isoformat(), boundary, boundary, batch_size),
        ).fetchall(),
    )
    receipt_ids = tuple(str(row["receipt_id"]) for row in rows)
    if not receipt_ids:
        return 0
    placeholders = ", ".join("?" for _ in receipt_ids)
    connection.execute(
        f"delete from runtime_receipt_envelopes where receipt_id in ({placeholders})",
        receipt_ids,
    )
    connection.execute(
        f"delete from receipt_rollup_actions where receipt_id in ({placeholders})",
        receipt_ids,
    )
    cloud_event_keys = tuple(f"receipt.created:{receipt_id}" for receipt_id in receipt_ids)
    connection.execute(
        f"""
        delete from guard_cloud_events
        where uploaded_at is not null
          and idempotency_key in ({placeholders})
        """,
        cloud_event_keys,
    )
    result = connection.execute(
        f"delete from runtime_receipts where receipt_id in ({placeholders})",
        receipt_ids,
    )
    return max(result.rowcount, 0)


def _delete_guard_event_batch(
    connection: sqlite3.Connection,
    *,
    cutoff: datetime,
    detail_limit: int,
    batch_size: int,
) -> int:
    boundary = _rowid_boundary(connection, table="guard_events", detail_limit=detail_limit)
    result = connection.execute(
        """
        delete from guard_events
        where event_id in (
          select event.event_id
          from guard_events as event
          where (event.occurred_at < ? or (? is not null and event.rowid <= ?))
            and not exists (
              select 1 from guard_workflow_capability_receipts as receipt
              where receipt.event_id = event.event_id
            )
            and not exists (
              select 1 from guard_workflow_capability_authority_transitions as transition
              where transition.event_id = event.event_id
            )
          order by event.occurred_at
          limit ?
        )
        """,
        (cutoff.isoformat(), boundary, boundary, batch_size),
    )
    return max(result.rowcount, 0)


def _delete_native_decision_receipt_batch(
    connection: sqlite3.Connection,
    *,
    cutoff: datetime,
    detail_limit: int,
    batch_size: int,
) -> int:
    boundary = _rowid_boundary(
        connection,
        table="native_hook_decision_receipts",
        detail_limit=detail_limit,
    )
    result = connection.execute(
        """
        delete from native_hook_decision_receipts
        where rowid in (
          select rowid
          from native_hook_decision_receipts
          where recorded_at < ? or (? is not null and rowid <= ?)
          order by recorded_at, rowid
          limit ?
        )
        """,
        (cutoff.isoformat(), boundary, boundary, batch_size),
    )
    return max(result.rowcount, 0)


def _delete_uploaded_cloud_event_batch(
    connection: sqlite3.Connection,
    *,
    cutoff: datetime,
    detail_limit: int,
    batch_size: int,
) -> int:
    boundary = _rowid_boundary(
        connection,
        table="guard_cloud_events",
        detail_limit=detail_limit,
        where="uploaded_at is not null",
    )
    result = connection.execute(
        """
        delete from guard_cloud_events
        where event_id in (
          select event_id
          from guard_cloud_events
          where uploaded_at is not null
            and (uploaded_at < ? or (? is not null and rowid <= ?))
          order by uploaded_at, occurred_at
          limit ?
        )
        """,
        (cutoff.isoformat(), boundary, boundary, batch_size),
    )
    return max(result.rowcount, 0)


def _rowid_boundary(
    connection: sqlite3.Connection,
    *,
    table: str,
    detail_limit: int,
    where: str | None = None,
) -> int | None:
    where_clause = f"where {where}" if where is not None else ""
    row = connection.execute(
        f"select max(rowid) from {table} {where_clause}",
    ).fetchone()
    if row is None or row[0] is None:
        return None
    boundary = int(row[0]) - detail_limit
    return boundary if boundary > 0 else None


def _reclaim_free_pages(connection: sqlite3.Connection, *, batch_size: int) -> int:
    mode_row = connection.execute("pragma auto_vacuum").fetchone()
    if mode_row is None or int(mode_row[0]) != 2:
        return 0
    before_row = connection.execute("pragma freelist_count").fetchone()
    before = int(before_row[0]) if before_row is not None else 0
    if before <= 0:
        return 0
    connection.execute(f"pragma incremental_vacuum({min(before, batch_size)})")
    after_row = connection.execute("pragma freelist_count").fetchone()
    after = int(after_row[0]) if after_row is not None else before
    return max(before - after, 0)


def _run_passive_housekeeping(owner: _ConnectionOwner) -> None:
    try:
        with owner._connect() as connection:
            connection.execute("pragma busy_timeout=0")
            connection.execute("pragma optimize")
            connection.execute("pragma wal_checkpoint(passive)")
    except sqlite3.Error:
        # Maintenance never delays or fails an enforcement request.
        return


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
