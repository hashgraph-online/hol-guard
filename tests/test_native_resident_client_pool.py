from __future__ import annotations

import io
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module
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


def test_client_reader_keeps_response_binding_with_the_captured_generation_queue(
    tmp_path: Path,
) -> None:
    client = _PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )
    old_queue: Queue[bytes | client_module._StreamFailure] = Queue(maxsize=1)
    active_queue: Queue[bytes | client_module._StreamFailure] = Queue(maxsize=1)
    response = b"old-generation-response"
    process = SimpleNamespace(stdout=io.BytesIO(struct.pack(">I", len(response)) + response))

    client._responses = active_queue  # pyright: ignore[reportPrivateUsage]
    client._read_responses(process, old_queue)  # pyright: ignore[reportArgumentType]

    assert old_queue.get_nowait() == response
    assert active_queue.empty()


def test_client_frame_write_skips_selector_on_windows_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_resident_transport as transport

    class PipeStdin:
        def fileno(self) -> int:
            raise AssertionError("Windows pipes must not enter the selector path")

        def write(self, frame: bytes) -> int:
            self.written = frame
            return len(frame)

        def flush(self) -> None:
            return

    stdin = PipeStdin()
    monkeypatch.setattr(transport.os, "name", "nt")
    assert transport.write_frame(stdin, b"frame", deadline_monotonic=time.monotonic() + 1)
    assert stdin.written == b"frame"


def test_client_frame_write_is_bounded_when_pipe_writer_blocks() -> None:
    class BlockingStdin:
        def __init__(self) -> None:
            self.started = threading.Event()
            self.released = threading.Event()
            self.closed = False

        def fileno(self) -> int:
            raise OSError("selector unavailable")

        def write(self, _frame: bytes) -> None:
            self.started.set()
            self.released.wait()

        def flush(self) -> None:
            return

        def close(self) -> None:
            self.closed = True
            self.released.set()

    stdin = BlockingStdin()
    started = time.monotonic()
    assert not _PersistentNativeClient._write_frame(  # pyright: ignore[reportPrivateUsage]
        stdin,
        b"frame",
        deadline_monotonic=time.monotonic() + 0.05,
    )
    assert stdin.started.is_set()
    assert stdin.closed
    assert time.monotonic() - started < 0.5


def test_client_close_can_interrupt_a_blocked_frame_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class BlockingStdin:
        def __init__(self) -> None:
            self.closed = False
            self.released = threading.Event()

        def close(self) -> None:
            self.closed = True
            self.released.set()

    class Process:
        def __init__(self) -> None:
            self.stdin = BlockingStdin()
            self.stdout = None

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            self.stdin.close()

        def wait(self, timeout: float) -> None:
            del timeout

        def kill(self) -> None:
            self.stdin.close()

    client = _PersistentNativeClient(
        executable=tmp_path / "runtime",
        state_dir=tmp_path / "native-runtime",
        environment={},
    )
    process = Process()
    started = threading.Event()
    result: list[bytes | None] = []

    def fake_start() -> bool:
        object.__setattr__(client, "_process", process)
        return True

    def blocked_write(
        _stdin: object,
        _frame: bytes,
        *,
        deadline_monotonic: float,
    ) -> bool:
        del deadline_monotonic
        started.set()
        process.stdin.released.wait(timeout=2)
        return False

    monkeypatch.setattr(client, "_start", fake_start)
    monkeypatch.setattr(client, "_write_frame", blocked_write)
    request_thread = threading.Thread(
        target=lambda: result.append(client.request(b"payload", deadline_monotonic=time.monotonic() + 5)),
        daemon=True,
    )
    request_thread.start()
    assert started.wait(timeout=1)

    started_closing = time.monotonic()
    client.close()

    assert time.monotonic() - started_closing < 0.5
    request_thread.join(timeout=1)
    assert not request_thread.is_alive()
    assert result == [None]
    assert process.stdin.closed


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
    monkeypatch.setattr(_PersistentNativeClient, "close", lambda client: closed.append(client))
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
    monkeypatch.setattr(client_module, "_MAX_PERSISTENT_CLIENTS", 2)
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
    monkeypatch.setattr(_PersistentNativeClient, "close", lambda client: closed.append(client))
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
