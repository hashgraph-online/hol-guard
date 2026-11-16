"""A closing owner must not drop the resident's lease, and idle-only callers
wait briefly for a busy stream instead of falling back to a one-shot process."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_client as clients
from codex_plugin_scanner.guard import native_resident_stream as streams
from codex_plugin_scanner.guard.native_process_stop_scope import native_process_stop_scope


def _unexpected(*_args: object, **_kwargs: object) -> None:
    pytest.fail("idle-only dispatch must not create, track, or spawn")


class _Client:
    def __init__(self) -> None:
        self._process = SimpleNamespace(poll=lambda: None)
        self.calls = 0
        self.closed = 0

    def request(self, payload, *, deadline_monotonic, allow_start):
        self.calls += 1
        return b"ok"

    def close(self, **_kwargs: object) -> bool:
        self.closed += 1
        return True


def _pool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> clients._PersistentNativeClientPool:
    pool = clients._PersistentNativeClientPool(
        executable=tmp_path / "runtime", state_dir=tmp_path / "native-runtime", environment={}
    )
    monkeypatch.setattr(clients, "_PersistentNativeClient", _unexpected)
    monkeypatch.setattr(clients, "_track_resident", _unexpected)
    monkeypatch.setattr(streams.subprocess, "Popen", _unexpected)
    return pool


@pytest.mark.parametrize("idle_only", [True, False])
def test_stopped_scope_is_refused_before_it_borrows_the_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, idle_only: bool
):
    pool = _pool(tmp_path, monkeypatch)
    client = _Client()
    pool._clients.add(client)
    pool._idle.append(client)
    stop = threading.Event()
    stop.set()
    with native_process_stop_scope(stop):
        assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 1, idle_only=idle_only) is None
    assert clients._LAST_FAILURE_CODE.get() == "native_client_timed_out"
    # The parked stream is the client lease that keeps the resident up.
    assert pool._idle == [client]
    assert pool._clients == {client}
    assert client.calls == 0
    assert client.closed == 0


def test_idle_only_waits_for_a_busy_stream_to_be_parked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pool = _pool(tmp_path, monkeypatch)
    client = _Client()
    # Tracked by the pool but not parked: another request has it in use.
    pool._clients.add(client)

    def _park() -> None:
        time.sleep(0.1)
        with pool._condition:
            pool._idle.append(client)
            pool._condition.notify_all()

    threading.Thread(target=_park, daemon=True).start()
    started = time.monotonic()
    answer = pool.request(b"{}", deadline_monotonic=time.monotonic() + 5, idle_only=True, idle_wait_seconds=2.0)
    assert answer == b"ok"
    assert time.monotonic() - started < 2.0
    assert client.calls == 1
    assert pool._idle == [client]


def test_idle_only_wait_is_bounded_while_the_stream_stays_busy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pool = _pool(tmp_path, monkeypatch)
    client = _Client()
    pool._clients.add(client)
    started = time.monotonic()
    assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 5, idle_only=True, idle_wait_seconds=0.2) is None
    assert 0.15 <= time.monotonic() - started < 2.0
    assert client.calls == 0


@pytest.mark.parametrize("state", ["empty", "dead", "retiring"])
def test_idle_only_never_waits_without_a_live_busy_stream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str):
    pool = _pool(tmp_path, monkeypatch)
    if state != "empty":
        client = _Client()
        pool._clients.add(client)
        if state == "dead":
            client._process = SimpleNamespace(poll=lambda: 1)
        else:
            pool._retiring.add(client)
    monkeypatch.setattr(pool._condition, "wait", _unexpected)
    assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 5, idle_only=True, idle_wait_seconds=5.0) is None
