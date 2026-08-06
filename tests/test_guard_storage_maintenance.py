from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
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


def test_storage_maintenance_queries_use_time_and_reference_indexes(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        old = "2025-01-01T00:00:00+00:00"
        connection.executemany(
            "insert into guard_events (event_name, payload_json, occurred_at) values ('plan', '{}', ?)",
            [(old,)] * 100,
        )
        connection.execute(
            """
            insert into guard_workflow_capabilities (
              capability_id, approval_provenance_id, nonce, signed_claim_json, key_id,
              issued_at, not_before, expires_at, max_uses
            ) values ('plan-capability', 'approval', 'plan-nonce', '{}', 'key', ?, ?, ?, 50)
            """,
            (old, old, "2027-01-01T00:00:00+00:00"),
        )
        event_ids = [int(row["event_id"]) for row in connection.execute("select event_id from guard_events limit 50")]
        connection.executemany(
            """
            insert into guard_workflow_capability_receipts (
              receipt_id, capability_id, task_id, invocation_id, approval_provenance_id,
              signed_receipt_json, claimed_at, use_number, event_id
            ) values (?, 'plan-capability', 'task', ?, 'approval', '{}', ?, ?, ?)
            """,
            [
                (f"receipt-{index}", f"invocation-{index}", old, index + 1, event_id)
                for index, event_id in enumerate(event_ids)
            ],
        )
        connection.execute("analyze")
        receipt_plan = connection.execute(
            """
            explain query plan
            select receipt_id from runtime_receipts
            where timestamp < ?
            order by timestamp
            limit 500
            """,
            ("2026-01-01T00:00:00+00:00",),
        ).fetchall()
        event_plan = connection.execute(
            """
            explain query plan
            select event.event_id
            from guard_events as event
            where event.occurred_at < ?
              and not exists (
                select 1 from guard_workflow_capability_receipts as receipt
                where receipt.event_id = event.event_id
              )
            order by event.occurred_at
            limit 500
            """,
            ("2026-01-01T00:00:00+00:00",),
        ).fetchall()
        cloud_plan = connection.execute(
            """
            explain query plan
            select event_id from guard_cloud_events
            where uploaded_at is not null and uploaded_at < ?
            order by uploaded_at, occurred_at
            limit 500
            """,
            ("2026-01-01T00:00:00+00:00",),
        ).fetchall()

    assert "idx_receipts_timestamp_desc" in " ".join(str(row["detail"]) for row in receipt_plan)
    assert "idx_guard_workflow_receipt_event" in " ".join(str(row["detail"]) for row in event_plan)
    assert "idx_guard_cloud_events_sync" in " ".join(str(row["detail"]) for row in cloud_plan)


def test_storage_maintenance_yields_quickly_to_hook_writer(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    writer = sqlite3.connect(store.path, timeout=0.1, isolation_level=None)
    writer.execute("pragma journal_mode=wal")
    writer.execute("begin immediate")
    started = time.monotonic()
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            store.maintain_storage(
                now=datetime(2026, 7, 25, tzinfo=timezone.utc),
                detail_retain_days=30,
            )
    finally:
        elapsed = time.monotonic() - started
        writer.rollback()
        writer.close()

    assert elapsed < 0.25


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


def test_schema_initialization_does_not_poll_while_holding_migration_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    schema_checks = 0
    initializes = 0

    def schema_is_current() -> bool:
        nonlocal schema_checks
        schema_checks += 1
        return False

    def initialize() -> None:
        nonlocal initializes
        initializes += 1

    store._daemon_managed_schema = True  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(store, "_schema_is_current", schema_is_current)
    monkeypatch.setattr(store, "_initialize_schema", initialize)
    monkeypatch.setattr(store, "_hold_advisory_file_lock", lambda **_kwargs: nullcontext())

    store._initialize_serialized()  # pyright: ignore[reportPrivateUsage]

    assert schema_checks == 2
    assert initializes == 1


def test_schema_initialization_releases_process_lock_before_policy_priming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    schema_initialized = False

    def initialize_schema() -> None:
        nonlocal schema_initialized
        schema_initialized = True

    def initialize_policy_integrity() -> None:
        assert schema_initialized is True
        path_key = str(store.path.absolute())
        assert path_key not in store._schema_initialization_states  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(store, "_initialize_schema", initialize_schema)
    monkeypatch.setattr(store, "_initialize_policy_integrity", initialize_policy_integrity)

    store._initialize_serialized()  # pyright: ignore[reportPrivateUsage]


def test_schema_initialization_wait_is_bounded_and_preserves_leader_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    path_key = str(store.path.absolute())
    leader_lock = threading.Lock()
    leader_lock.acquire()
    leader_state = store_connection_schema._SchemaInitializationState(  # pyright: ignore[reportPrivateUsage]
        lock=leader_lock,
        references=1,
    )
    with store._schema_initialization_locks_guard:  # pyright: ignore[reportPrivateUsage]
        store._schema_initialization_states[path_key] = leader_state  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(store_connection_schema, "sqlite_connect_timeout_seconds", lambda: 0.01)

    try:
        with pytest.raises(TimeoutError, match="schema migration lock"):
            store._initialize_serialized()  # pyright: ignore[reportPrivateUsage]
        assert leader_state.references == 1
    finally:
        leader_lock.release()
        with store._schema_initialization_locks_guard:  # pyright: ignore[reportPrivateUsage]
            del store._schema_initialization_states[path_key]  # pyright: ignore[reportPrivateUsage]


def test_schema_initialization_waiter_retries_after_leader_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    leader_started = threading.Event()
    release_leader = threading.Event()
    call_count = 0

    def initialize_schema() -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            leader_started.set()
            assert release_leader.wait(timeout=1.0)
            raise RuntimeError("leader failed")

    monkeypatch.setattr(store, "_initialize_schema", initialize_schema)
    with ThreadPoolExecutor(max_workers=2) as executor:
        leader = executor.submit(store._initialize_serialized)  # pyright: ignore[reportPrivateUsage]
        assert leader_started.wait(timeout=1.0)
        waiter = executor.submit(store._initialize_serialized)  # pyright: ignore[reportPrivateUsage]
        release_leader.set()
        with pytest.raises(RuntimeError, match="leader failed"):
            leader.result()
        waiter.result()

    assert call_count == 2
    assert store._schema_initialization_states == {}  # pyright: ignore[reportPrivateUsage]


def test_version_21_upgrade_adds_workflow_event_index(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        connection.execute("drop index idx_guard_workflow_receipt_event")
        connection.execute("delete from schema_migrations where version = 21")

    GuardStore(guard_home, prime_policy_integrity=False)

    with sqlite3.connect(store.path) as connection:
        index = connection.execute(
            """
            select 1 from sqlite_master
            where type = 'index' and name = 'idx_guard_workflow_receipt_event'
            """
        ).fetchone()
        migration = connection.execute("select 1 from schema_migrations where version = 21").fetchone()
    assert index is not None
    assert migration is not None


def test_schema_upgrade_is_serialized_across_store_processes(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        connection.execute("delete from schema_migrations where version = 21")
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
        assert connection.execute("select count(*) from schema_migrations where version = 21").fetchone()[0] == 1
