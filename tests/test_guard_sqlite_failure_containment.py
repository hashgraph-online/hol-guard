from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.store import GuardStore


def _corrupt_store(path: Path) -> bytes:
    corrupt_bytes = b"not-a-sqlite-database\x00guard-recovery-fixture"
    path.write_bytes(corrupt_bytes)
    return corrupt_bytes


def _quarantined_databases(guard_home: Path) -> list[Path]:
    return sorted(guard_home.glob("guard.db.corrupt-*"))


def test_store_startup_quarantines_corruption_and_recovers(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    corrupt_bytes = _corrupt_store(guard_home / "guard.db")

    store = GuardStore(guard_home, prime_policy_integrity=False)

    quarantined = _quarantined_databases(guard_home)
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == corrupt_bytes
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma quick_check").fetchone() == ("ok",)


def test_daemon_managed_startup_quarantines_corruption(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    _corrupt_store(guard_home / "guard.db")

    store = GuardStore(
        guard_home,
        prime_policy_integrity=False,
        daemon_managed_schema=True,
    )

    assert len(_quarantined_databases(guard_home)) == 1
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma quick_check").fetchone() == ("ok",)


def test_live_store_recovers_after_fatal_sqlite_error(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    corrupt_bytes = _corrupt_store(store.path)

    with pytest.raises(sqlite3.DatabaseError, match="file is not a database"):
        store.get_runtime_state()

    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma quick_check").fetchone() == ("ok",)
    quarantined = _quarantined_databases(guard_home)
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == corrupt_bytes


def test_concurrent_startup_performs_one_recovery(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    _corrupt_store(guard_home / "guard.db")

    def open_store(_index: int) -> bool:
        store = GuardStore(guard_home, prime_policy_integrity=False)
        with sqlite3.connect(store.path) as connection:
            return connection.execute("pragma quick_check").fetchone() == ("ok",)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(open_store, range(16)))

    assert all(results)
    assert len(_quarantined_databases(guard_home)) == 1


def test_lock_contention_does_not_quarantine_healthy_store(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    writer = sqlite3.connect(store.path, timeout=0.1)
    writer.execute("begin exclusive")
    try:
        assert store._is_fatal_sqlite_error(sqlite3.OperationalError("database is locked")) is False
    finally:
        writer.rollback()
        writer.close()

    assert _quarantined_databases(guard_home) == []


@pytest.mark.parametrize(
    "message",
    [
        "database disk image is malformed",
        "database corruption at line 1",
        "file is not a database",
    ],
)
def test_fatal_storage_errors_are_recognized(message: str) -> None:
    assert GuardStore._is_fatal_sqlite_error(sqlite3.DatabaseError(message)) is True


def test_transient_io_error_does_not_quarantine_healthy_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    real_connect = store_connection_schema.sqlite3.connect
    attempts = 0

    def fail_once(database: str | Path, timeout: float = 5.0) -> sqlite3.Connection:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("disk I/O error")
        return real_connect(database, timeout=timeout)

    monkeypatch.setattr(store_connection_schema.sqlite3, "connect", fail_once)

    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        store.get_runtime_state()

    assert _quarantined_databases(store.guard_home) == []
    assert store.get_runtime_state() is None


def test_recovery_waits_for_in_flight_connection(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    entered = threading.Event()
    release = threading.Event()

    def hold_connection() -> None:
        with store._connect():  # pyright: ignore[reportPrivateUsage]
            entered.set()
            assert release.wait(timeout=2)

    holder = threading.Thread(target=hold_connection)
    holder.start()
    assert entered.wait(timeout=1)
    corrupt_bytes = _corrupt_store(store.path)
    recovered: list[bool] = []
    recovery = threading.Thread(
        target=lambda: recovered.append(
            store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
                sqlite3.DatabaseError("database disk image is malformed")
            )
        )
    )
    recovery.start()
    time.sleep(0.05)
    assert recovery.is_alive()

    release.set()
    holder.join(timeout=2)
    recovery.join(timeout=2)

    assert recovered == [True]
    assert _quarantined_databases(store.guard_home)[0].read_bytes() == corrupt_bytes


def test_unrelated_sql_error_does_not_enter_recovery(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)

    with (
        pytest.raises(sqlite3.OperationalError, match="no such table"),
        store._connect() as connection,  # pyright: ignore[reportPrivateUsage]
    ):
        connection.execute("select * from intentionally_missing_table")

    assert _quarantined_databases(store.guard_home) == []


def test_storage_gate_allows_nested_reads_on_one_thread(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)

    with store._connect() as outer:  # pyright: ignore[reportPrivateUsage]
        assert outer.execute("pragma schema_version").fetchone() is not None
        with store._connect() as inner:  # pyright: ignore[reportPrivateUsage]
            assert inner.execute("pragma schema_version").fetchone() is not None


def test_replacement_remains_exclusive_until_schema_is_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    _corrupt_store(store.path)
    initializing = threading.Event()
    release = threading.Event()
    original_initialize = store._initialize_schema  # pyright: ignore[reportPrivateUsage]

    def delayed_initialize() -> None:
        initializing.set()
        assert release.wait(timeout=2)
        original_initialize()

    monkeypatch.setattr(store, "_initialize_schema", delayed_initialize)
    recovery = threading.Thread(
        target=lambda: store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
            sqlite3.DatabaseError("database disk image is malformed")
        )
    )
    recovery.start()
    assert initializing.wait(timeout=1)
    reader_finished = threading.Event()

    def read_store() -> None:
        with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
            _ = connection.execute("select count(*) from schema_migrations").fetchone()
            reader_finished.set()

    reader = threading.Thread(target=read_store)
    reader.start()
    time.sleep(0.05)
    assert reader_finished.is_set() is False

    release.set()
    recovery.join(timeout=2)
    reader.join(timeout=2)

    assert reader_finished.is_set() is True
