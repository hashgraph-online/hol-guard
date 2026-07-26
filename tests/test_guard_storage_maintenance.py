from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_receipt_rollups import (
    backfill_receipt_rollups,
    receipt_rollups_need_backfill,
)


def _insert_receipt(
    connection: sqlite3.Connection,
    *,
    receipt_id: str,
    timestamp: str,
    cloud_uploaded_at: str | None = None,
) -> None:
    connection.execute(
        """
        insert into runtime_receipts (
          receipt_id, harness, artifact_id, artifact_hash, policy_decision,
          changed_capabilities_json, provenance_summary, timestamp
        ) values (?, 'pi', ?, ?, 'allow', '[]', '', ?)
        """,
        (receipt_id, f"artifact-{receipt_id}", f"hash-{receipt_id}", timestamp),
    )
    connection.execute(
        """
        insert into runtime_receipt_envelopes (
          receipt_id, envelope_full_json, envelope_redacted_json
        ) values (?, '{"action":"allow"}', '{"action":"allow"}')
        """,
        (receipt_id,),
    )
    connection.execute(
        """
        insert into receipt_rollup_actions (receipt_id, policy_decision, dirty)
        values (?, 'allow', 0)
        on conflict(receipt_id) do update set policy_decision = 'allow', dirty = 0
        """,
        (receipt_id,),
    )
    if cloud_uploaded_at is not None:
        connection.execute(
            """
            insert into guard_cloud_events (
              event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
            ) values (?, ?, 'receipt.created', '{}', ?, ?)
            """,
            (
                f"cloud-{receipt_id}",
                f"receipt.created:{receipt_id}",
                timestamp,
                cloud_uploaded_at,
            ),
        )


def test_storage_maintenance_bounds_detail_and_preserves_rollups(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    now = datetime(2026, 7, 25, tzinfo=timezone.utc)
    old = (now - timedelta(days=120)).isoformat()
    recent = now.isoformat()
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        for index in range(6):
            _insert_receipt(
                connection,
                receipt_id=f"receipt-{index}",
                timestamp=old if index < 4 else recent,
                cloud_uploaded_at=old,
            )
        connection.execute(
            """
            insert into guard_cloud_events (
              event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
            ) values ('pending', 'receipt.created:receipt-0', 'receipt.created', '{}', ?, null)
            on conflict(idempotency_key) do update set uploaded_at = null
            """,
            (old,),
        )
        connection.execute(
            """
            update receipt_aggregate_totals
            set total = 6, allowed = 6, blocked = 0, reviewed = 0,
                first_activity_at = ?, last_activity_at = ?
            where totals_key = 'global'
            """,
            (old, recent),
        )
        for _index in range(5):
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values ('test', '{}', ?)",
                (old,),
            )
        for index in range(4):
            connection.execute(
                """
                insert into guard_cloud_events (
                  event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at
                ) values (?, ?, 'test', '{}', ?, ?)
                """,
                (f"uploaded-{index}", f"uploaded:{index}", old, old),
            )

    result = store.maintain_storage(
        now=now,
        detail_retain_days=30,
        batch_size=10,
        receipt_detail_limit=2,
        guard_event_limit=2,
        uploaded_cloud_event_limit=1,
    )

    assert result.completed is True
    assert result.receipts_archived == 3
    assert result.guard_events_deleted == 5
    assert result.cloud_events_deleted >= 3
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        receipt_ids = {str(row[0]) for row in connection.execute("select receipt_id from runtime_receipts").fetchall()}
        assert receipt_ids == {"receipt-0", "receipt-4", "receipt-5"}
        assert (
            connection.execute("select count(*) from guard_cloud_events where uploaded_at is null").fetchone()[0] == 1
        )
        assert (
            connection.execute(
                "select archived_receipts from guard_storage_maintenance where singleton = 1"
            ).fetchone()[0]
            == 3
        )
        assert receipt_rollups_need_backfill(connection) is False
        assert (
            connection.execute("select total from receipt_aggregate_totals where totals_key = 'global'").fetchone()[0]
            == 6
        )

        connection.execute(
            """
            update guard_cloud_events
            set payload_json = '{"payload":{"policyDecision":"allow"}}'
            where idempotency_key = 'receipt.created:receipt-0'
            """
        )
        connection.execute("delete from receipt_rollup_actions where receipt_id = 'receipt-4'")
        assert receipt_rollups_need_backfill(connection) is True
        backfill_receipt_rollups(connection)
        assert receipt_rollups_need_backfill(connection) is False
        totals = connection.execute(
            """
            select total, allowed, blocked, reviewed
            from receipt_aggregate_totals
            where totals_key = 'global'
            """
        ).fetchone()
        assert tuple(totals) == (6, 6, 0, 0)

        connection.execute("delete from receipt_aggregate_totals where totals_key = 'global'")
        assert receipt_rollups_need_backfill(connection) is True
        backfill_receipt_rollups(connection)
        assert receipt_rollups_need_backfill(connection) is False
        assert (
            connection.execute("select total from receipt_aggregate_totals where totals_key = 'global'").fetchone()[0]
            == 6
        )


def test_storage_maintenance_uses_bounded_batches(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    now = datetime(2026, 7, 25, tzinfo=timezone.utc)
    old = (now - timedelta(days=120)).isoformat()
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        for _index in range(5):
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values ('test', '{}', ?)",
                (old,),
            )

    first = store.maintain_storage(
        now=now,
        detail_retain_days=30,
        batch_size=2,
        guard_event_limit=1,
    )
    second = store.maintain_storage(
        now=now,
        detail_retain_days=30,
        batch_size=2,
        guard_event_limit=1,
    )

    assert first.guard_events_deleted == 2
    assert first.completed is False
    assert second.guard_events_deleted == 2
    assert second.completed is False


def test_fresh_store_uses_incremental_auto_vacuum(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma auto_vacuum").fetchone()[0] == 2


def test_current_schema_store_opens_during_concurrent_writer(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    writer = sqlite3.connect(store.path, timeout=0.1)
    writer.execute("pragma journal_mode=wal")
    writer.execute("begin immediate")
    try:
        reopened = GuardStore(
            guard_home,
            prime_policy_integrity=False,
            daemon_managed_schema=True,
        )
        assert reopened.path == store.path
    finally:
        writer.rollback()
        writer.close()


def test_current_schema_probe_treats_lock_contention_as_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)

    def locked_connect(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store_connection_schema.sqlite3, "connect", locked_connect)

    assert store._schema_is_current() is False  # pyright: ignore[reportPrivateUsage]


def test_schema_upgrade_is_serialized_across_store_processes(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        connection.execute("delete from schema_migrations where version = 20")
        connection.execute("drop table guard_storage_maintenance")

    def reopen_store(_index: int) -> GuardStore:
        return GuardStore(guard_home, prime_policy_integrity=False)

    with ThreadPoolExecutor(max_workers=2) as executor:
        stores = list(
            executor.map(
                reopen_store,
                range(2),
            )
        )

    assert all(reopened.path == store.path for reopened in stores)
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        assert connection.execute("select count(*) from schema_migrations where version = 20").fetchone()[0] == 1
