"""Ordinary connections share the recovery gate on every supported platform."""

from __future__ import annotations

import threading
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_command_control_windows_lock as windows_lock
from codex_plugin_scanner.guard import store_connection_schema as schema
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override
from codex_plugin_scanner.guard.store import GuardStore


@contextmanager
def _held_gate(store: GuardStore, *, exclusive: bool, connection: bool = False) -> Iterator[None]:
    entered, release = threading.Event(), threading.Event()
    failures = []

    def hold() -> None:
        try:
            lease = store._connect() if connection else store._hold_storage_gate(exclusive=exclusive)
            with lease as database:
                if connection:
                    if database is None:
                        raise RuntimeError("holder did not open a SQLite connection")
                    if database.execute("select 1").fetchone()[0] != 1:
                        raise RuntimeError("holder SQLite connection failed its query")
                entered.set()
                if not release.wait(timeout=2):
                    raise TimeoutError("holder did not receive its release signal")
        except BaseException as error:
            failures.append(error)
            entered.set()

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    try:
        assert entered.wait(timeout=1)
        assert not failures
        yield
    finally:
        release.set()
        holder.join(timeout=2)
        assert not holder.is_alive()
        assert not failures


@pytest.mark.parametrize("failure", ["missing_connection", "invalid_row", "query_error"])
def test_holder_connection_failures_reach_the_test_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    closed: list[bool] = []

    def execute(_statement: str) -> SimpleNamespace:
        if failure == "query_error":
            raise OSError("synthetic holder query failure")
        return SimpleNamespace(fetchone=lambda: (0,))

    @contextmanager
    def connection() -> Generator[SimpleNamespace | None]:
        try:
            yield None if failure == "missing_connection" else SimpleNamespace(execute=execute)
        finally:
            closed.append(True)

    monkeypatch.setattr(store, "_connect", connection)
    reached_body = False
    with pytest.raises(AssertionError), _held_gate(store, exclusive=False, connection=True):
        reached_body = True
    assert not reached_body
    assert closed == [True]


def test_two_real_sqlite_connections_share_gate_at_evidence_writer_timeout(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with (
        _held_gate(store, exclusive=False, connection=True),
        sqlite_connect_timeout_override(0.05),
        store._connect() as connection,
    ):
        assert connection.execute("select count(*) from schema_migrations").fetchone()[0] > 0


@pytest.mark.parametrize(
    ("holder_exclusive", "waiter_exclusive"), [(False, False), (False, True), (True, False), (True, True)]
)
def test_storage_gate_preserves_shared_admission_and_recovery_exclusion(
    tmp_path: Path, holder_exclusive: bool, waiter_exclusive: bool
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with _held_gate(store, exclusive=holder_exclusive), sqlite_connect_timeout_override(0.05):
        if not holder_exclusive and not waiter_exclusive:
            with store._hold_storage_gate(exclusive=False):
                pass
        else:
            with (
                pytest.raises(TimeoutError, match="Timed out waiting for Guard storage access"),
                store._hold_storage_gate(exclusive=waiter_exclusive),
            ):
                pytest.fail("conflicting storage gate was admitted")
    with sqlite_connect_timeout_override(0.05), store._hold_storage_gate(exclusive=True):
        pass


def test_nested_shared_gate_cannot_upgrade_or_release_outer_lease(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with store._hold_storage_gate(exclusive=False):
        with store._hold_storage_gate(exclusive=False):
            pass
        with pytest.raises(RuntimeError, match="Cannot upgrade"), store._hold_storage_gate(exclusive=True):
            pytest.fail("nested recovery upgrade was admitted")
        assert store._storage_gate_local.owner == id(store)
        assert store._storage_gate_local.depth == 1
    assert store._storage_gate_local.owner is None
    assert store._storage_gate_local.depth == 0


def test_gate_exception_releases_lease_for_exclusive_recovery(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    original = ValueError("synthetic failure in a normal connection")
    with pytest.raises(ValueError) as caught, store._hold_storage_gate(exclusive=False):
        raise original
    assert caught.value is original
    with sqlite_connect_timeout_override(0.05), store._hold_storage_gate(exclusive=True):
        pass


@pytest.mark.parametrize("exclusive", [False, True])
def test_windows_gate_uses_existing_nonblocking_win32_primitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exclusive: bool
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    calls = []
    monkeypatch.setattr(schema, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        windows_lock, "try_lock_authority_file", lambda fd, *, shared: calls.append(("lock", fd, shared))
    )
    monkeypatch.setattr(windows_lock, "unlock_authority_file", lambda fd: calls.append(("unlock", fd)))
    with store._hold_storage_gate(exclusive=exclusive):
        assert len(calls) == 1 and calls[0][0] == "lock"
    assert calls == [("lock", calls[0][1], not exclusive), ("unlock", calls[0][1])]


def test_failed_windows_lock_preserves_deadline_polling_and_never_unlocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    clock = [0.0]
    waits = []
    unlocks = []

    def fail(_fd: int, *, shared: bool) -> None:
        assert shared
        raise PermissionError("synthetic lock contention")

    def sleep(seconds: float) -> None:
        waits.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(schema, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(schema, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep))
    monkeypatch.setattr(windows_lock, "try_lock_authority_file", fail)
    monkeypatch.setattr(windows_lock, "unlock_authority_file", lambda fd: unlocks.append(fd))
    with (
        sqlite_connect_timeout_override(0.05),
        pytest.raises(TimeoutError),
        store._hold_storage_gate(exclusive=False),
    ):
        pytest.fail("failed Windows lock was admitted")
    assert waits == [0.01] * 5
    assert unlocks == []
    assert getattr(store._storage_gate_local, "owner", None) is None
