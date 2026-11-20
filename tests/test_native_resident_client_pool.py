from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module
from codex_plugin_scanner.guard import native_resident_client_pool as pool_module
from codex_plugin_scanner.guard import native_resident_revival as revival
from codex_plugin_scanner.guard.native_resident_client import (
    _PersistentNativeClient,
    _PersistentNativeClientPool,
)


def _pool(tmp_path: Path) -> _PersistentNativeClientPool:
    return _PersistentNativeClientPool(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )


def test_pool_recovers_retired_capacity_only_after_containment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clients = []

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            self.contained = False
            self.deadlines: list[float] = []
            clients.append(self)

        def request(self, _payload: bytes, *, deadline_monotonic: float) -> bytes | None:
            return None if self is clients[0] else b"recovered"

        def close(self, *, deadline_monotonic: float) -> bool:
            self.deadlines.append(deadline_monotonic)
            return self.contained

    monkeypatch.setattr(pool_module, "_PersistentNativeClient", Client)
    monkeypatch.setattr(pool_module, "_MAX_PERSISTENT_CLIENTS", 1)
    pool = _pool(tmp_path)
    assert pool.request(b"timed-out", deadline_monotonic=time.monotonic() - 1) is None
    failed = clients[0]
    assert failed in pool._clients
    assert failed in pool._retiring
    assert pool.request(b"still-contained", deadline_monotonic=time.monotonic() + 0.01) is None
    assert len(clients) == 1, "uncontained client must still occupy its slot"
    failed.contained = True
    assert pool.request(b"next", deadline_monotonic=time.monotonic() + 1) == b"recovered"
    assert len(clients) == 2
    assert failed not in pool._clients
    assert failed not in pool._retiring
    assert len(pool._clients) == 1


def test_pool_does_not_reuse_a_client_bound_to_a_failed_resident_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = b'{"error":"native_resident_state_dir_create_failed","retryable":false}'
    clients: list[object] = []

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            self.closed = False
            clients.append(self)

        def request(self, _payload: bytes, *, deadline_monotonic: float) -> bytes | None:
            # The first stream's lease failed at startup, so it frames that failure forever.
            return failure if self is clients[0] else b'{"schema":"ok"}'

        def close(self, *, deadline_monotonic: float) -> bool:
            self.closed = True
            return True

    monkeypatch.setattr(pool_module, "_PersistentNativeClient", Client)
    pool = _pool(tmp_path)
    deadline = time.monotonic() + 5
    assert pool.request(b"first", deadline_monotonic=deadline) == failure
    stale = clients[0]
    assert stale.closed
    assert stale not in pool._idle
    assert stale not in pool._clients
    assert pool.request(b"second", deadline_monotonic=deadline) == b'{"schema":"ok"}'
    assert len(clients) == 2


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (b'{"error":"native_resident_state_dir_create_failed","retryable":false}', True),
        (b'{"error":"native_resident_lease_busy","retryable":true}', True),
        (b'{"error":"native_request_invalid_json","retryable":false}', False),
        (b'{"error":"native_resident_x","retryable":false,"extra":1}', False),
        (b'{"schema":"guard-daemon-route-result.v1","error":"native_resident_x"}', False),
        (b'{"error":"native_resident_x"', False),
        (b'{"error":"native_resident_x","retryable":false}garbage', False),
        (b"", False),
    ],
)
def test_startup_error_frame_detection_is_exact(response: bytes, expected: bool) -> None:
    assert pool_module._is_resident_startup_error(response) is expected


def test_pool_dispatches_requests_across_persistent_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _pool(tmp_path)
    active = 0
    maximum_active = 0
    active_lock = threading.Lock()
    entered = threading.Barrier(4)

    def fake_request(
        _client: _PersistentNativeClient,
        payload: bytes,
        *,
        deadline_monotonic: float,
    ) -> bytes:
        del deadline_monotonic
        nonlocal active, maximum_active
        with active_lock:
            active += 1
            maximum_active = max(maximum_active, active)
        try:
            entered.wait(timeout=1)
            return payload
        finally:
            with active_lock:
                active -= 1

    closed: list[_PersistentNativeClient] = []
    monkeypatch.setattr(_PersistentNativeClient, "request", fake_request)
    monkeypatch.setattr(_PersistentNativeClient, "close", lambda client, **kwargs: closed.append(client))
    assert not pool._clients  # pyright: ignore[reportPrivateUsage]

    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(
                    pool.request,
                    f"request-{index}".encode(),
                    deadline_monotonic=time.monotonic() + 2,
                )
                for index in range(4)
            ]
            assert [future.result(timeout=2) for future in futures] == [
                f"request-{index}".encode() for index in range(4)
            ]
        assert maximum_active == 4
        assert len(pool._clients) == 4  # pyright: ignore[reportPrivateUsage]
        assert len(pool._idle) == 4  # pyright: ignore[reportPrivateUsage]
    finally:
        pool.close()
    assert len(closed) == 4


def test_pool_bounds_admission_and_waits_for_an_idle_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pool_module, "_MAX_PERSISTENT_CLIENTS", 2)
    pool = _pool(tmp_path)
    active = 0
    maximum_active = 0
    active_lock = threading.Lock()
    started = threading.Event()
    release = threading.Event()

    def fake_request(
        _client: _PersistentNativeClient,
        payload: bytes,
        *,
        deadline_monotonic: float,
    ) -> bytes:
        del deadline_monotonic
        nonlocal active, maximum_active
        with active_lock:
            active += 1
            maximum_active = max(maximum_active, active)
            started.set()
        try:
            assert release.wait(timeout=2)
            return payload
        finally:
            with active_lock:
                active -= 1

    monkeypatch.setattr(_PersistentNativeClient, "request", fake_request)
    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(
                    pool.request,
                    f"request-{index}".encode(),
                    deadline_monotonic=time.monotonic() + 2,
                )
                for index in range(4)
            ]
            assert started.wait(timeout=1)
            time.sleep(0.05)
            assert maximum_active == 2
            assert len(pool._clients) == 2  # pyright: ignore[reportPrivateUsage]
            release.set()
            assert all(future.result(timeout=2) is not None for future in futures)
    finally:
        pool.close()


def test_pool_evicts_failed_stream_before_next_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pool = _pool(tmp_path)
    calls = 0
    closed: list[_PersistentNativeClient] = []

    def fake_request(
        _client: _PersistentNativeClient,
        payload: bytes,
        *,
        deadline_monotonic: float,
    ) -> bytes | None:
        del deadline_monotonic
        nonlocal calls
        calls += 1
        return None if calls == 1 else payload

    monkeypatch.setattr(_PersistentNativeClient, "request", fake_request)
    monkeypatch.setattr(_PersistentNativeClient, "close", lambda client, **kwargs: closed.append(client))
    try:
        assert pool.request(b"failed", deadline_monotonic=time.monotonic() + 1) is None
        assert not pool._clients  # pyright: ignore[reportPrivateUsage]
        assert pool.request(b"recovered", deadline_monotonic=time.monotonic() + 1) == b"recovered"
        assert len(pool._clients) == 1  # pyright: ignore[reportPrivateUsage]
    finally:
        pool.close()
    assert len(closed) == 2


def test_pool_registry_cleanup_is_scoped_and_closes_idle_clients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_module.close_native_resident_clients()
    runtime = tmp_path / "runtime"
    home_a = tmp_path / "home-a"
    home_b = tmp_path / "home-b"
    pool_a = client_module._client_pool_for(runtime, home_a / "native-runtime", {})
    assert client_module._client_pool_for(runtime, home_a / "nested" / ".." / "native-runtime", {}) is pool_a
    pool_b = client_module._client_pool_for(runtime, home_b / "native-runtime", {})
    closed: list[_PersistentNativeClientPool] = []
    monkeypatch.setattr(_PersistentNativeClientPool, "close", lambda pool: closed.append(pool))

    try:
        client_module.close_native_resident_clients(home_a)
        assert (str(runtime), str(home_a / "native-runtime")) not in client_module._CLIENT_POOLS
        assert (str(runtime), str(home_b / "native-runtime")) in client_module._CLIENT_POOLS
        assert closed == [pool_a]
    finally:
        client_module.close_native_resident_clients()
    assert closed == [pool_a, pool_b]


def test_failed_request_log_releases_the_leased_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clients: list[object] = []

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            self.closed = False
            clients.append(self)

        def request(self, _payload: bytes, *, deadline_monotonic: float) -> bytes:
            return b'{"schema":"ok"}'

        def close(self, *, deadline_monotonic: float) -> bool:
            self.closed = True
            return True

    monkeypatch.setattr(pool_module, "_PersistentNativeClient", Client)
    monkeypatch.setattr(pool_module, "_MAX_PERSISTENT_CLIENTS", 1)
    blocker = tmp_path / "not-a-directory"
    blocker.write_bytes(b"x")
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(blocker / "resident-requests.log"))
    pool = _pool(tmp_path)
    with pytest.raises(OSError):
        pool.request(b"counted", deadline_monotonic=time.monotonic() + 1)
    leased = clients[0]
    assert leased.closed is True  # type: ignore[attr-defined]
    assert leased not in pool._clients  # pyright: ignore[reportPrivateUsage]
    log_path = tmp_path / "resident-requests.log"
    monkeypatch.setenv("HOL_GUARD_RESIDENT_REQUEST_LOG", os.fspath(log_path))
    assert pool.request(b"next", deadline_monotonic=time.monotonic() + 1) == b'{"schema":"ok"}'
    assert log_path.read_text(encoding="utf-8") == "1\n"
    assert len(pool._clients) == 1  # pyright: ignore[reportPrivateUsage]


def test_pool_reports_readiness_only_for_live_idle_clients(tmp_path: Path) -> None:
    """Readiness is what lets a caller know whether it must budget for a spawn.

    A resident that a test or an operator killed leaves a parked client whose
    process is gone; counting it as ready makes the next request pay a spawn
    inside a steady-state budget and time out.
    """

    pool = _pool(tmp_path)
    assert pool.has_idle_client() is False

    alive = SimpleNamespace(_process=SimpleNamespace(poll=lambda: None))
    pool._idle.append(alive)
    assert pool.has_idle_client() is True

    pool._idle[:] = [SimpleNamespace(_process=SimpleNamespace(poll=lambda: 1))]
    assert pool.has_idle_client() is False

    pool._idle[:] = [SimpleNamespace(_process=None)]
    assert pool.has_idle_client() is False

    pool._idle[:] = [alive]
    pool._closed = True
    assert pool.has_idle_client() is False


class _Answering:
    """A stream that answers every request with one fixed frame."""

    def __init__(self, response: bytes) -> None:
        self.response = response
        self.closed = False

    def request(self, _payload: bytes, *, deadline_monotonic: float) -> bytes:
        return self.response

    def close(self, *, deadline_monotonic: float) -> bool:
        self.closed = True
        return True


def _answering_pool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: bytes
) -> tuple[_PersistentNativeClientPool, list[_Answering]]:
    streams: list[_Answering] = []

    def build(**_kwargs: object) -> _Answering:
        stream = _Answering(response)
        streams.append(stream)
        return stream

    monkeypatch.setattr(pool_module, "_PersistentNativeClient", build)
    return _pool(tmp_path), streams


def test_a_diagnostic_does_not_arm_the_restart_hold(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Asking a crash-looping resident how it is must not open the circuit.

    The refusal frame is still returned to the caller; what it must not do is
    become the event that takes the hook path out of service.
    """
    pool, _ = _answering_pool(tmp_path, monkeypatch, revival.restart_blocked_frame())
    armed: list[object] = []
    monkeypatch.setattr(pool_module, "arm_restart_hold", armed.append)

    assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 1, diagnostic=True) is not None
    assert armed == []
    assert not revival.restart_hold_active(pool._hold_key)


def test_a_diagnostic_does_not_clear_a_held_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful answer from a warm stream is not evidence the hold is over."""
    pool, _ = _answering_pool(tmp_path, monkeypatch, b"answered")
    cleared: list[object] = []
    monkeypatch.setattr(pool_module, "clear_restart_hold", cleared.append)

    assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 1, diagnostic=True) == b"answered"
    assert cleared == []


def test_a_diagnostic_retires_the_stream_it_borrowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A question leaves no lease of its own parked in the pool."""
    pool, streams = _answering_pool(tmp_path, monkeypatch, b"answered")

    assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 1, diagnostic=True) == b"answered"
    assert len(streams) == 1
    assert streams[0].closed
    assert list(pool._idle) == []


def test_ordinary_work_still_parks_its_stream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pool, streams = _answering_pool(tmp_path, monkeypatch, b"answered")

    assert pool.request(b"{}", deadline_monotonic=time.monotonic() + 1) == b"answered"
    assert not streams[0].closed
    assert list(pool._idle) == streams


@pytest.mark.parametrize("payload", [b'{"operation":"resident_health"}', b""])
def test_a_diagnostic_restores_the_failure_the_hook_path_left_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    """A question must not overwrite the failure a hook request recorded.

    Both an answered question and a rejected one run through the same restore,
    so the caller reads back exactly what it recorded before asking.
    """

    class Pool:
        def request(
            self,
            _payload: bytes,
            *,
            deadline_monotonic: float,
            diagnostic: bool = False,
            idle_only: bool = False,
            idle_wait_seconds: float = 0.0,
        ) -> bytes:
            assert not idle_only
            assert idle_wait_seconds == 0.0
            client_module._LAST_FAILURE_CODE.set("native_client_pool_exhausted")
            return b"answered"

    monkeypatch.setattr(client_module, "_client_pool_for", lambda *_args, **_kwargs: Pool())
    client_module.record_native_resident_client_failure_code("native_resident_unavailable")
    client_module.record_native_resident_client_failure_hold_key(("runtime", "state"))

    client_module.native_resident_client_request(
        executable=tmp_path / "runtime",
        guard_home=tmp_path,
        environment={},
        payload=payload,
        timeout_seconds=1.0,
        diagnostic=True,
    )

    assert client_module.native_resident_client_failure_code() == "native_resident_unavailable"
    assert client_module.native_resident_client_failure_hold_key() == ("runtime", "state")


def test_ordinary_work_still_records_its_own_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client_module.record_native_resident_client_failure_code("native_resident_unavailable")

    client_module.native_resident_client_request(
        executable=tmp_path / "runtime",
        guard_home=tmp_path,
        environment={},
        payload=b"",
        timeout_seconds=1.0,
    )

    assert client_module.native_resident_client_failure_code() == "native_client_request_invalid"
