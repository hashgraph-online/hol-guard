from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore


def _corrupt_store(path: Path) -> bytes:
    corrupt_bytes = b"not-a-sqlite-database\x00guard-recovery-fixture"
    path.write_bytes(corrupt_bytes)
    return corrupt_bytes


def _quarantined_databases(guard_home: Path) -> list[Path]:
    return sorted(guard_home.glob("guard.db.corrupt-*"))


def _connects_store(database: str | Path, path: Path) -> bool:
    raw = str(database)
    if raw.startswith("file:"):
        raw = raw.removeprefix("file:").split("?", 1)[0]
    return Path(raw) == path


def _main_quarantined_databases(guard_home: Path) -> list[Path]:
    return [
        path
        for path in _quarantined_databases(guard_home)
        if not path.name.endswith("-wal") and not path.name.endswith("-shm")
    ]


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

    def fail_once(database: str | Path, timeout: float = 5.0, **kwargs: object) -> sqlite3.Connection:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("disk I/O error")
        return real_connect(database, timeout=timeout, **kwargs)

    monkeypatch.setattr(store_connection_schema.sqlite3, "connect", fail_once)

    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        store.get_runtime_state()

    assert _quarantined_databases(store.guard_home) == []
    assert store.get_runtime_state() is None


def test_io_error_that_clears_after_directory_probe_does_not_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    real_connect = store_connection_schema.sqlite3.connect
    active_attempts = 0

    def fail_first_active_probe(database: str | Path, timeout: float = 5.0, **kwargs: object) -> sqlite3.Connection:
        nonlocal active_attempts
        if _connects_store(database, store.path):
            active_attempts += 1
            if active_attempts == 1:
                raise sqlite3.OperationalError("disk I/O error")
        return real_connect(database, timeout=timeout, **kwargs)

    monkeypatch.setattr("codex_plugin_scanner.guard.sqlite_recovery.sqlite3.connect", fail_first_active_probe)

    assert (
        store._store_is_proven_unusable(  # pyright: ignore[reportPrivateUsage]
            sqlite3.OperationalError("disk I/O error")
        )
        is False
    )
    assert active_attempts == 2
    assert _quarantined_databases(store.guard_home) == []


def test_fatal_error_recovers_when_rechecks_report_persistent_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    real_connect = store_connection_schema.sqlite3.connect
    active_attempts = 0

    def fail_active_probes(database: str | Path, timeout: float = 5.0, **kwargs: object) -> sqlite3.Connection:
        nonlocal active_attempts
        if _connects_store(database, store.path):
            active_attempts += 1
            raise sqlite3.OperationalError("disk I/O error")
        return real_connect(database, timeout=timeout, **kwargs)

    monkeypatch.setattr("codex_plugin_scanner.guard.sqlite_recovery.sqlite3.connect", fail_active_probes)

    assert (
        store._store_is_proven_unusable(  # pyright: ignore[reportPrivateUsage]
            sqlite3.DatabaseError("database disk image is malformed")
        )
        is True
    )
    assert active_attempts == 2


def test_recovery_restores_readable_quarantined_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    identity = UnlistedCliIdentity(
        cli_id="local-cli.ship-12345678",
        name="ship",
        kind="executable",
        identity_hash="a" * 64,
        example_label="ship",
    )
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
    )
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)

    recovered = store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
        sqlite3.DatabaseError("database disk image is malformed")
    )

    assert recovered is True
    assert getattr(store, "_last_sqlite_recovery", None) == "restored"
    assert _main_quarantined_databases(store.guard_home) == []
    granted = store.read_local_cli_grant(identity.cli_id)
    assert granted is not None
    assert granted["state"] == "allowed"


def test_connect_retries_after_restored_readable_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    identity = UnlistedCliIdentity(
        cli_id="local-cli.ship-12345678",
        name="ship",
        kind="executable",
        identity_hash="a" * 64,
        example_label="ship",
    )
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
    )
    original_connect_once = store._connect_once  # pyright: ignore[reportPrivateUsage]
    calls = {"count": 0}

    @contextmanager
    def fail_first_open() -> Iterator[sqlite3.Connection]:
        calls["count"] += 1
        if calls["count"] == 1:
            raise sqlite3.DatabaseError("database disk image is malformed")
        with original_connect_once() as connection:
            yield connection

    monkeypatch.setattr(store, "_connect_once", fail_first_open)
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)

    assert store.get_runtime_state() is None
    granted = store.read_local_cli_grant(identity.cli_id)
    assert granted is not None
    assert granted["state"] == "allowed"
    assert calls["count"] >= 2
    assert _main_quarantined_databases(store.guard_home) == []


def test_connect_retries_busy_lock_without_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    original_connect_once = store._connect_once  # pyright: ignore[reportPrivateUsage]
    calls = {"count": 0}

    @contextmanager
    def fail_first_busy() -> Iterator[sqlite3.Connection]:
        calls["count"] += 1
        if calls["count"] == 1:
            raise sqlite3.OperationalError("database is locked")
        with original_connect_once() as connection:
            yield connection

    monkeypatch.setattr(store, "_connect_once", fail_first_busy)

    assert store.get_runtime_state() is None
    assert _quarantined_databases(store.guard_home) == []
    assert calls["count"] >= 2


def test_stale_fatal_error_does_not_quarantine_healthy_store(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)

    recovered = store._recover_fatal_sqlite_store(  # pyright: ignore[reportPrivateUsage]
        sqlite3.DatabaseError("database disk image is malformed")
    )

    assert recovered is False
    assert _quarantined_databases(store.guard_home) == []
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma quick_check").fetchone() == ("ok",)


def test_connect_does_not_quarantine_replacement_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    corrupt_bytes = _corrupt_store(store.path)
    failed_stat = store.path.stat()
    failed_identity = failed_stat.st_dev, failed_stat.st_ino
    original_path = guard_home / "failed.db"
    observed_identity: tuple[int, int] | None = None
    original_recover = store._recover_fatal_sqlite_store  # pyright: ignore[reportPrivateUsage]

    def replace_before_recovery(
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        nonlocal observed_identity
        observed_identity = failed_identity
        store.path.replace(original_path)
        with sqlite3.connect(store.path) as connection:
            connection.execute("create table replacement (value integer)")
        return original_recover(error, failed_identity=failed_identity)

    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", replace_before_recovery)

    with pytest.raises(sqlite3.DatabaseError, match="file is not a database"):
        store.get_runtime_state()

    assert observed_identity == failed_identity
    assert original_path.read_bytes() == corrupt_bytes
    assert _quarantined_databases(store.guard_home) == []
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("pragma quick_check").fetchone() == ("ok",)


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
