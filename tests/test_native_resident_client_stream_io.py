"""A resident client stream keeps response binding and bounds blocked frame writes."""

from __future__ import annotations

import io
import struct
import threading
import time
from pathlib import Path
from queue import Queue
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_resident_client as client_module
from codex_plugin_scanner.guard.native_resident_client import _PersistentNativeClient


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
    process = SimpleNamespace(
        stdout=io.BytesIO(struct.pack(">I", len(response)) + response),
        wait=lambda timeout=None: 0,
    )

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
    assert transport.write_frame(
        stdin,
        b"frame",
        deadline_monotonic=time.monotonic() + 1,
        launch_worker=lambda worker: worker.start() or True,
    )
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
    workers = []

    def launch_worker(worker: threading.Thread) -> bool:
        workers.append(worker)
        worker.start()
        return True

    started = time.monotonic()
    try:
        assert not _PersistentNativeClient._write_frame(  # pyright: ignore[reportPrivateUsage]
            stdin,
            b"frame",
            deadline_monotonic=time.monotonic() + 0.05,
            launch_worker=launch_worker,
        )
        assert stdin.started.is_set()
        assert not stdin.closed
        assert time.monotonic() - started < 0.5
    finally:
        stdin.released.set()
        for worker in workers:
            worker.join(timeout=1)
            assert not worker.is_alive()


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

    def fake_start(*, deadline_monotonic: float | None = None, allow_start: bool = True) -> bool:
        assert allow_start
        del deadline_monotonic
        object.__setattr__(client, "_process", process)
        return True

    def blocked_write(
        _stdin: object,
        _frame: bytes,
        *,
        deadline_monotonic: float,
        **kwargs: object,
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
