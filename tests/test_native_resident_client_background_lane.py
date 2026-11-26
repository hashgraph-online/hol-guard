"""Background resident work leaves the last parked stream to hook calls."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_resident_client_pool as pool_module
from codex_plugin_scanner.guard.native_resident_client import _PersistentNativeClientPool
from codex_plugin_scanner.guard.native_resident_client_pool import background_resident_lane


class _Running:
    def poll(self) -> None:
        return None


class _Client:
    def __init__(self, started: list[_Client], **_kwargs: object) -> None:
        self._process = _Running()
        self.served: list[bytes] = []
        started.append(self)

    def request(self, payload: bytes, *, deadline_monotonic: float, **_kwargs: object) -> bytes:
        self.served.append(payload)
        return b'{"schema":"ok"}'

    def close(self, *, deadline_monotonic: float | None = None) -> bool:
        return True


@pytest.fixture
def started(monkeypatch: pytest.MonkeyPatch) -> list[_Client]:
    clients: list[_Client] = []
    monkeypatch.setattr(pool_module, "_PersistentNativeClient", lambda **kwargs: _Client(clients, **kwargs))
    return clients


def _pool(tmp_path: Path) -> _PersistentNativeClientPool:
    return _PersistentNativeClientPool(
        executable=tmp_path / "runtime", state_dir=tmp_path / "native-runtime", environment={}
    )


def _ask(pool: _PersistentNativeClientPool, payload: bytes) -> None:
    assert pool.request(payload, deadline_monotonic=time.monotonic() + 5) is not None


def test_background_work_opens_its_own_stream_instead_of_taking_the_last_parked_one(
    tmp_path: Path, started: list[_Client]
) -> None:
    pool = _pool(tmp_path)
    _ask(pool, b"warm")
    with background_resident_lane():
        _ask(pool, b"publish")
    # The hook stream that warmed the pool stayed parked for the hook.
    assert len(started) == 2
    assert started[1].served == [b"publish"]
    _ask(pool, b"hook")
    assert pool.has_idle_client()


def test_background_work_reuses_a_parked_stream_when_one_is_left_over(tmp_path: Path, started: list[_Client]) -> None:
    pool = _pool(tmp_path)
    _ask(pool, b"warm")
    with background_resident_lane():
        _ask(pool, b"publish")
        _ask(pool, b"drain")
    assert len(started) == 2
    assert pool.has_idle_client()


def test_background_work_still_runs_when_the_pool_is_full(
    tmp_path: Path, started: list[_Client], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pool_module, "_MAX_PERSISTENT_CLIENTS", 1)
    pool = _pool(tmp_path)
    _ask(pool, b"warm")
    with background_resident_lane():
        _ask(pool, b"publish")
    assert len(started) == 1
    assert started[0].served == [b"warm", b"publish"]


def test_hook_calls_take_the_last_parked_stream(tmp_path: Path, started: list[_Client]) -> None:
    pool = _pool(tmp_path)
    _ask(pool, b"warm")
    _ask(pool, b"hook")
    assert len(started) == 1
