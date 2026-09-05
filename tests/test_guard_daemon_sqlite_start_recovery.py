from __future__ import annotations

import sqlite3

import pytest

from codex_plugin_scanner.guard.daemon.service_lifecycle import _begin_owned_service_with_store_recovery


class _FakeStore:
    def __init__(self, *, recover: bool) -> None:
        self.recover = recover
        self.recover_calls = 0
        self.failed_identity: tuple[int, int] | None = None

    def _recover_fatal_sqlite_store(
        self,
        error: BaseException,
        *,
        failed_identity: tuple[int, int] | None = None,
    ) -> bool:
        self.recover_calls += 1
        self.failed_identity = failed_identity
        assert isinstance(error, sqlite3.DatabaseError)
        return self.recover


class _FakeInner:
    def __init__(self, store: _FakeStore) -> None:
        self.store = store


class _FakeServer:
    def __init__(self, *, recover: bool) -> None:
        self.store = _FakeStore(recover=recover)
        self._server = _FakeInner(self.store)
        self.starts = 0

    def _begin_owned_service(self, generation: int) -> None:
        self.starts += 1
        if self.starts == 1:
            error = sqlite3.DatabaseError("database disk image is malformed")
            error.guard_failed_sqlite_identity = (11, 22)
            raise error
        assert generation == 1


def test_owned_service_retries_once_after_fatal_store_recovery() -> None:
    server = _FakeServer(recover=True)
    _begin_owned_service_with_store_recovery(server, 1)
    assert server.starts == 2
    assert server.store.recover_calls == 1
    assert server.store.failed_identity == (11, 22)


def test_owned_service_does_not_retry_when_store_recovery_fails() -> None:
    server = _FakeServer(recover=False)
    with pytest.raises(sqlite3.DatabaseError, match="malformed"):
        _begin_owned_service_with_store_recovery(server, 1)
    assert server.starts == 1
    assert server.store.recover_calls == 1
