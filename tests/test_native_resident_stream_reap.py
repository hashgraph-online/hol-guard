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
