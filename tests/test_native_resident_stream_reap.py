"""A native client that exits on its own is reaped and its exit is logged."""

from __future__ import annotations

import logging
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient, _StreamFailure


def test_exited_client_is_reaped_and_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    client = _PersistentNativeClient(executable=Path(sys.executable), state_dir=tmp_path, environment={})
    process = subprocess.Popen(
        (sys.executable, "-c", "import sys; sys.exit(3)"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    responses: queue.Queue[bytes | _StreamFailure] = queue.Queue(maxsize=1)
    reader = threading.Thread(target=client._read_responses, args=(process, responses))
    with caplog.at_level(logging.WARNING):
        reader.start()
        reader.join(timeout=10)
    assert not reader.is_alive()
    assert process.returncode == 3  # wait() already collected the exit status: no zombie
    assert isinstance(responses.get_nowait(), _StreamFailure)
    assert "native_client_exited returncode=3" in caplog.text
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            stream.close()


def _run_reader(
    client: _PersistentNativeClient, process: subprocess.Popen[bytes]
) -> queue.Queue[bytes | _StreamFailure]:
    responses: queue.Queue[bytes | _StreamFailure] = queue.Queue(maxsize=1)
    reader = threading.Thread(target=client._read_responses, args=(process, responses))
    reader.start()
    reader.join(timeout=10)
    assert not reader.is_alive()
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            stream.close()
    return responses


def test_unexpected_signal_exit_is_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    client = _PersistentNativeClient(executable=Path(sys.executable), state_dir=tmp_path, environment={})
    process = subprocess.Popen(
        (sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    with caplog.at_level(logging.WARNING):
        _run_reader(client, process)
    assert process.returncode is not None and process.returncode != 0
    assert f"native_client_exited returncode={process.returncode}" in caplog.text


def test_client_retired_by_guard_is_not_logged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    client = _PersistentNativeClient(executable=Path(sys.executable), state_dir=tmp_path, environment={})
    process = subprocess.Popen(
        (sys.executable, "-c", "import sys; sys.exit(3)"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    client._retiring = process
    with caplog.at_level(logging.WARNING):
        _run_reader(client, process)
    assert process.returncode == 3
    assert "native_client_exited" not in caplog.text


def test_crash_is_logged_when_close_starts_after_stream_closed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    client = _PersistentNativeClient(executable=Path(sys.executable), state_dir=tmp_path, environment={})
    # The child closes its stdout, then lingers so the reader is still waiting
    # when a request sees the failure and starts closing the client.
    process = subprocess.Popen(
        (sys.executable, "-c", "import os, sys, time; os.close(1); time.sleep(0.5); sys.exit(4)"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    responses: queue.Queue[bytes | _StreamFailure] = queue.Queue(maxsize=1)
    reader = threading.Thread(target=client._read_responses, args=(process, responses))
    with caplog.at_level(logging.WARNING):
        reader.start()
        assert isinstance(responses.get(timeout=10), _StreamFailure)
        client._closing = True
        reader.join(timeout=10)
    assert not reader.is_alive()
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            stream.close()
    assert "native_client_exited returncode=4" in caplog.text
