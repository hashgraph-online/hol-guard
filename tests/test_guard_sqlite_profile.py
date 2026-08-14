from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.sqlite_profile import SQLiteProfiler
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override
from codex_plugin_scanner.guard.store import GuardStore


def test_profiler_is_bounded_and_reports_retain_sqlite_conclusion() -> None:
    profiler = SQLiteProfiler(max_samples=2)
    for duration in (1.0, 2.0, 2.0):
        profiler.record_connect(duration)
        profiler.record_transaction(duration)
        profiler.record_commit(duration)

    snapshot = profiler.snapshot()
    assert snapshot["connects"] == 3
    assert snapshot["connect_ms"]["max"] == 2.0
    assert profiler.migration_gate_report(end_to_end_p95_ms=20.0) == {
        "store_p95_percent": 10.0,
        "busy_locked_percent": 0.0,
        "store_wait_gate_tripped": False,
        "busy_locked_gate_tripped": False,
        "conclusion": "retain_sqlite_wal",
    }


def test_profiler_trips_measured_migration_gates() -> None:
    profiler = SQLiteProfiler()
    profiler.record_transaction(25.0)
    profiler.record_busy_locked()

    report = profiler.migration_gate_report(end_to_end_p95_ms=100.0)
    assert report["store_wait_gate_tripped"] is True
    assert report["busy_locked_gate_tripped"] is True
    assert report["conclusion"] == "sqlite_migration_evaluation_required"


def test_store_profiles_connect_transaction_commit_and_lock(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with store._connect() as connection:
        connection.execute("select 1")

    lock = sqlite3.connect(store.path)
    lock.execute("begin exclusive")
    try:
        with (
            sqlite_connect_timeout_override(0.01),
            pytest.raises(sqlite3.OperationalError),
            store._connect() as connection,
        ):
            connection.execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values ('x', '{}', 'now')"
            )
    finally:
        lock.rollback()
        lock.close()

    snapshot = store.sqlite_profile()
    assert snapshot["connects"] >= 2
    assert snapshot["transactions"] >= 2
    assert snapshot["commits"] >= 1
    assert snapshot["busy_locked"] >= 1
    assert set(snapshot["transaction_ms"]) == {"p50", "p95", "p99", "max"}
