"""SQLite recovery when a fatal error surfaces after a connection was handed out."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cloud_control import server_control_cloud_sync as _ctl_cloud_sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_sqlite_recovery_support import quarantined_databases, read_runtime_row


def test_connect_recovers_after_yielded_fatal_select(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    original_connect_once = store._connect_once  # pyright: ignore[reportPrivateUsage]
    original_recover = store._recover_fatal_sqlite_store  # pyright: ignore[reportPrivateUsage]
    connect_calls = {"count": 0}
    recover_calls = {"count": 0}

    class _SelectFailureConnection:
        def __init__(self, connection: sqlite3.Connection, *, fail: bool) -> None:
            self._connection = connection
            self._fail = fail

        def execute(self, *args: object, **kwargs: object) -> object:
            if self._fail:
                raise sqlite3.DatabaseError("database disk image is malformed")
            return self._connection.execute(*args, **kwargs)

        def __getattr__(self, name: str) -> object:
            return getattr(self._connection, name)

    @contextmanager
    def fail_first_select() -> Iterator[object]:
        connect_calls["count"] += 1
        with original_connect_once() as connection:
            yield _SelectFailureConnection(connection, fail=connect_calls["count"] == 1)

    def recover(
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        recover_calls["count"] += 1
        return original_recover(error, failed_identity=failed_identity)

    monkeypatch.setattr(store, "_connect_once", fail_first_select)
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", recover)

    with pytest.raises(sqlite3.DatabaseError, match="malformed"):
        read_runtime_row(store)

    assert recover_calls["count"] == 1
    assert quarantined_databases(store.guard_home) == []
    assert read_runtime_row(store) is None


def test_initialize_recovers_fatal_sqlite_even_when_schema_looks_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    recover_calls: list[BaseException] = []

    def recover(
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        del failed_identity
        recover_calls.append(error)
        return True

    monkeypatch.setattr(
        store,
        "_initialize_serialized_once",
        lambda: (_ for _ in ()).throw(sqlite3.DatabaseError("database disk image is malformed")),
    )
    monkeypatch.setattr(store, "_schema_is_current", lambda: True)
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", recover)
    monkeypatch.setattr(store, "_initialize_policy_integrity", lambda: None)

    store._initialize_serialized()  # pyright: ignore[reportPrivateUsage]

    assert recover_calls
    assert isinstance(recover_calls[0], sqlite3.DatabaseError)


def test_initialize_tolerates_transient_io_when_schema_is_already_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    recover_calls: list[BaseException] = []
    integrity_calls = {"count": 0}

    def recover(
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        del failed_identity
        recover_calls.append(error)
        return False

    monkeypatch.setattr(
        store,
        "_initialize_serialized_once",
        lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error")),
    )
    monkeypatch.setattr(store, "_schema_is_current", lambda: True)
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", recover)
    monkeypatch.setattr(
        store,
        "_initialize_policy_integrity",
        lambda: integrity_calls.__setitem__("count", integrity_calls["count"] + 1),
    )

    store._initialize_serialized()  # pyright: ignore[reportPrivateUsage]

    assert recover_calls
    assert integrity_calls["count"] == 1


def test_yielded_select_recovery_keeps_triggering_sqlite_error_as_cause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    original_connect_once = store._connect_once  # pyright: ignore[reportPrivateUsage]

    class _SelectFailureConnection:
        def __init__(self, connection: sqlite3.Connection) -> None:
            self._connection = connection

        def execute(self, *args: object, **kwargs: object) -> object:
            raise sqlite3.DatabaseError("database disk image is malformed")

        def __getattr__(self, name: str) -> object:
            return getattr(self._connection, name)

    @contextmanager
    def fail_select() -> Iterator[object]:
        with original_connect_once() as connection:
            yield _SelectFailureConnection(connection)

    def recover_raises(
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        del error, failed_identity
        raise RuntimeError("recovery")

    monkeypatch.setattr(store, "_connect_once", fail_select)
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", recover_raises)

    with pytest.raises(RuntimeError, match="recovery") as raised:
        read_runtime_row(store)

    assert isinstance(raised.value.__cause__, sqlite3.DatabaseError)


def test_maybe_queue_first_cloud_sync_returns_none_when_profile_raises_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        store,
        "get_cloud_sync_profile",
        lambda: (_ for _ in ()).throw(sqlite3.DatabaseError("database disk image is malformed")),
    )

    assert _ctl_cloud_sync._maybe_queue_first_cloud_sync(store=store) is None
