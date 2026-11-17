"""A closing owner must not drop the resident's lease, and idle-only callers
wait briefly for a busy stream instead of falling back to a one-shot process."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_client as clients
from codex_plugin_scanner.guard import native_resident_client_pool as pool_module
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
    monkeypatch.setattr(pool_module, "_PersistentNativeClient", _unexpected)
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


def test_stop_during_idle_wait_keeps_parked_lease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A canceled waiter must not remove the only lease keeping the resident alive."""
    pool = _pool(tmp_path, monkeypatch)
    client = _Client()
    pool._clients.add(client)  # Busy until another request returns it.
    stop = threading.Event()
    waiting = threading.Event()
    original_wait = pool._condition.wait

    def noticed_wait(timeout=None):
        waiting.set()
        return original_wait(timeout=timeout)

    monkeypatch.setattr(pool._condition, "wait", noticed_wait)

    def stop_and_park() -> None:
        if not waiting.wait(timeout=2.0):
            return
        stop.set()
        with pool._condition:
            pool._idle.append(client)
            pool._condition.notify_all()

    worker = threading.Thread(target=stop_and_park, daemon=True)
    worker.start()
    with native_process_stop_scope(stop):
        answer = pool.request(
            b"{}",
            deadline_monotonic=time.monotonic() + 3,
            idle_only=True,
            idle_wait_seconds=2.0,
        )
    worker.join(timeout=2.0)
    assert not worker.is_alive()
    assert waiting.is_set()
    assert answer is None
    assert clients._LAST_FAILURE_CODE.get() == "native_client_timed_out"
    assert pool._idle == [client]
    assert pool._clients == {client}
    assert client.calls == 0
    assert client.closed == 0


def test_idle_wait_does_not_take_lease_after_request_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A late parked stream must survive a caller whose request has expired."""
    pool = _pool(tmp_path, monkeypatch)
    client = _Client()
    pool._clients.add(client)

    def parked_after_deadline(timeout=None):
        time.sleep(0.05)
        pool._idle.append(client)

    monkeypatch.setattr(pool._condition, "wait", parked_after_deadline)
    answer = pool.request(
        b"{}",
        deadline_monotonic=time.monotonic() + 0.015,
        idle_only=True,
        idle_wait_seconds=0.2,
    )
    assert answer is None
    assert pool._idle == [client]
    assert pool._clients == {client}
    assert client.calls == 0
    assert client.closed == 0


def test_stop_without_pool_notification_interrupts_idle_wait_promptly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A stopped publisher cannot wait its entire idle grace for a pool wake."""
    pool = _pool(tmp_path, monkeypatch)
    client = _Client()
    pool._clients.add(client)
    stop = threading.Event()
    waiting = threading.Event()
    original_wait = pool._condition.wait

    def noticed_wait(timeout=None):
        waiting.set()
        return original_wait(timeout=timeout)

    monkeypatch.setattr(pool._condition, "wait", noticed_wait)

    def stop_without_notifying_pool():
        if waiting.wait(timeout=1.0):
            time.sleep(0.02)
            stop.set()

    worker = threading.Thread(target=stop_without_notifying_pool, daemon=True)
    worker.start()
    started = time.monotonic()
    with native_process_stop_scope(stop):
        answer = pool.request(
            b"{}",
            deadline_monotonic=time.monotonic() + 2,
            idle_only=True,
            idle_wait_seconds=0.8,
        )
    elapsed = time.monotonic() - started
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert waiting.is_set()
    assert answer is None
    assert elapsed < 0.4
    assert pool._clients == {client}
    assert client.closed == 0
    assert client.calls == 0


def test_idle_only_zero_wait_borrows_parked_stream_immediately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    pool = _pool(tmp_path, monkeypatch)
    client = _Client()
    pool._clients.add(client)
    pool._idle.append(client)
    monkeypatch.setattr(pool._condition, "wait", _unexpected)
    assert (
        pool.request(
            b"{}",
            deadline_monotonic=time.monotonic() + 2,
            idle_only=True,
            idle_wait_seconds=0.0,
        )
        == b"ok"
    )
    assert pool._idle == [client]
    assert client.calls == 1
