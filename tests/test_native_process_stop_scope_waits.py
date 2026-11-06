"""Daemon shutdown cancels native waits owned by its background threads."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Queue

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.native_process_stop_scope import native_process_stop_scope, scoped_native_stop_event
from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient, _StreamFailure


def test_command_activity_maintenance_runs_inside_the_shutdown_stop_scope() -> None:
    service = object.__new__(daemon_server.GuardDaemonServer)
    shutdown = threading.Event()
    service._shutdown_started = shutdown
    scoped: list[threading.Event | None] = []

    def maintain() -> None:
        scoped.append(scoped_native_stop_event())
        shutdown.set()

    service._maintain_command_activity_best_effort = maintain
    service._maintain_storage_best_effort = lambda: True
    service._command_activity_maintenance_loop()

    assert scoped == [shutdown]
    assert scoped_native_stop_event() is None


def test_resident_response_wait_ends_once_the_scoped_stop_event_is_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _PersistentNativeClient(executable=Path(sys.executable), state_dir=tmp_path, environment={})
    # A resident that reads requests and never answers.
    process = subprocess.Popen(
        (sys.executable, "-c", "import sys; sys.stdin.buffer.read()"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    responses: Queue[bytes | _StreamFailure] = Queue(maxsize=1)
    closes: list[float | None] = []
    monkeypatch.setattr(client, "_request_snapshot", lambda **_kwargs: (process, process.stdin, responses))
    monkeypatch.setattr(client, "_request_is_current", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(client, "close", lambda *, deadline_monotonic=None: closes.append(deadline_monotonic) or True)
    stop = threading.Event()
    outcome: dict[str, object] = {}

    def run() -> None:
        with native_process_stop_scope(stop):
            started = time.monotonic()
            outcome["response"] = client.request(b"{}", deadline_monotonic=started + 10.0)
            outcome["elapsed"] = time.monotonic() - started

    try:
        worker = threading.Thread(target=run)
        worker.start()
        time.sleep(0.3)
        stop.set()
        worker.join(timeout=15)
        assert not worker.is_alive()
        assert outcome["response"] is None
        elapsed = outcome["elapsed"]
        assert isinstance(elapsed, float)
        assert elapsed < 3.0
        assert len(closes) == 1
    finally:
        process.kill()
        _ = process.wait(timeout=10)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()
