from __future__ import annotations

import os
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_resident_client as client
from codex_plugin_scanner.guard import native_resident_stream as stream

_WORKER = """
import struct
import sys

mode = sys.argv[1]
while True:
    header = sys.stdin.buffer.read(4)
    if len(header) != 4:
        break
    payload = sys.stdin.buffer.read(struct.unpack('>I', header)[0])
    if mode == 'silent' and payload != b'warm':
        continue
    if mode == 'stderr':
        sys.stderr.write('private-fixture-detail\\nnative_resident_start_timeout\\n')
        sys.stderr.flush()
    if mode in ('exit', 'stderr'):
        sys.exit(7)
    if mode == 'empty':
        break
    if mode == 'partial-header':
        sys.stdout.buffer.write(b'\\x00\\x00')
    elif mode == 'partial-response':
        sys.stdout.buffer.write(struct.pack('>I', 8) + b'no')
    elif mode == 'oversized-response':
        sys.stdout.buffer.write(struct.pack('>I', 2 * 1024 * 1024 + 1))
    elif mode == 'zero-response':
        sys.stdout.buffer.write(struct.pack('>I', 0))
    else:
        response = payload if mode == 'echo' else b'{"ok":true}\\n'
        sys.stdout.buffer.write(struct.pack('>I', len(response)) + response)
    sys.stdout.buffer.flush()
    if mode not in ('ok', 'echo', 'silent'):
        break
"""


@dataclass
class _StreamHarness:
    executable: Path
    guard_home: Path
    environment: dict[str, str]
    mode: str = "ok"
    launches: list[tuple[tuple[str, ...], dict[str, Any]]] = field(default_factory=list)
    processes: list[subprocess.Popen[bytes]] = field(default_factory=list)

    def request(self, payload: bytes = b"{}", **kwargs: Any) -> bytes | None:
        if "deadline_monotonic" not in kwargs:
            kwargs.setdefault("timeout_seconds", 2.0)
        return client.native_resident_client_request(
            executable=self.executable,
            guard_home=self.guard_home,
            environment=self.environment,
            payload=payload,
            **kwargs,
        )


@pytest.fixture
def stream_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_StreamHarness]:
    """Keep the real pool, frame transport, pipes, reader and child cleanup."""
    executable = tmp_path / "hol-guard-runtime"
    executable.write_bytes(b"test-runtime")
    worker = tmp_path / "framed_worker.py"
    worker.write_text(_WORKER, encoding="utf-8")
    environment = {**os.environ, "HOME": str(tmp_path), "PRIVATE_FIXTURE_VALUE": "private-fixture-detail"}
    harness = _StreamHarness(executable, tmp_path / "guard-home", environment)
    popen = subprocess.Popen

    def launch(command: tuple[str, ...], **kwargs: Any) -> subprocess.Popen[bytes]:
        harness.launches.append((tuple(command), dict(kwargs)))
        if harness.mode == "start-failure":
            raise OSError("private-fixture-detail")
        assert set(kwargs) == {"cwd", "env", "stdin", "stdout", "stderr", "start_new_session"}
        process = popen(
            (sys.executable, "-I", "-u", str(worker), harness.mode),
            cwd=kwargs["cwd"],
            env=kwargs["env"],
            stdin=kwargs["stdin"],
            stdout=kwargs["stdout"],
            stderr=kwargs["stderr"],
            start_new_session=kwargs["start_new_session"],
        )
        harness.processes.append(process)
        return process

    monkeypatch.setattr(stream.subprocess, "Popen", launch)
    try:
        yield harness
    finally:
        try:
            assert client.close_native_residents(harness.guard_home)
        finally:
            for process in harness.processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
        assert all(process.poll() is not None for process in harness.processes)


@pytest.mark.parametrize("raw_hook_envelope", [False, True])
def test_request_uses_package_bound_persistent_stream(stream_harness: _StreamHarness, raw_hook_envelope: bool) -> None:
    assert stream_harness.request(raw_hook_envelope=raw_hook_envelope) == b'{"ok":true}\n'
    command, options = stream_harness.launches[0]
    assert command == (
        str(stream_harness.executable),
        "resident-client-stream",
        "--stdin",
        str(stream_harness.guard_home / "native-runtime"),
    )
    assert options["cwd"] == stream_harness.executable.parent
    assert options["stdin"] == subprocess.PIPE
    assert options["stdout"] == subprocess.PIPE
    assert options["stderr"] == subprocess.DEVNULL
    assert options["start_new_session"] is True
    assert options["env"]["HOME"] == stream_harness.environment["HOME"]
    assert "PRIVATE_FIXTURE_VALUE" not in options["env"]
    assert client.native_resident_client_failure_code() is None
    assert stream_harness.request(b'{"second":true}') == b'{"ok":true}\n'
    assert len(stream_harness.launches) == 1
    assert stream_harness.processes[0].poll() is None


@pytest.mark.parametrize("raw_hook_envelope", [False, True])
def test_stop_runner_replacement_does_not_select_retired_request_route(
    stream_harness: _StreamHarness, monkeypatch: pytest.MonkeyPatch, raw_hook_envelope: bool
) -> None:
    def forbidden_one_shot(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Replacing the shutdown runner must not change request routing")

    monkeypatch.setattr(client, "run_isolated_hook_process", forbidden_one_shot)
    assert stream_harness.request(raw_hook_envelope=raw_hook_envelope) == b'{"ok":true}\n'
    assert len(stream_harness.launches) == 1


def test_request_keeps_absolute_deadline_through_real_frame_write(
    stream_harness: _StreamHarness, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_deadlines: list[float] = []
    write_frame = stream.write_frame

    def observe_write(stdin: object, frame: bytes, *, deadline_monotonic: float) -> bool:
        observed_deadlines.append(deadline_monotonic)
        assert frame == struct.pack(">I", 2) + b"{}"
        return write_frame(stdin, frame, deadline_monotonic=deadline_monotonic)

    monkeypatch.setattr(stream, "write_frame", observe_write)
    deadline = time.monotonic() + 2
    assert stream_harness.request(deadline_monotonic=deadline) == b'{"ok":true}\n'
    assert observed_deadlines == [deadline]


@pytest.mark.parametrize(
    "mode", ["exit", "empty", "partial-header", "partial-response", "oversized-response", "zero-response"]
)
def test_invalid_stream_response_fails_closed_and_reaps_child(stream_harness: _StreamHarness, mode: str) -> None:
    stream_harness.mode = mode
    assert stream_harness.request() is None
    assert client.native_resident_client_failure_code() == "native_client_stream_failed"
    assert len(stream_harness.processes) == 1
    process = stream_harness.processes[0]
    assert process.poll() is not None
    assert process.stdin is not None and process.stdin.closed
    assert process.stdout is not None and process.stdout.closed


def test_stream_failure_does_not_publish_child_stderr(stream_harness: _StreamHarness) -> None:
    stream_harness.mode = "stderr"
    assert stream_harness.request() is None
    assert client.native_resident_client_failure_code() == "native_client_stream_failed"
    assert stream_harness.launches[0][1]["stderr"] == subprocess.DEVNULL


def test_stream_start_failure_does_not_publish_exception_detail(stream_harness: _StreamHarness) -> None:
    stream_harness.mode = "start-failure"
    assert stream_harness.request() is None
    assert client.native_resident_client_failure_code() == "native_client_start_failed"
    assert stream_harness.processes == []


def test_unanswered_request_retires_child_at_original_deadline(stream_harness: _StreamHarness) -> None:
    stream_harness.mode = "silent"
    assert stream_harness.request(b"warm") == b'{"ok":true}\n'
    deadline = time.monotonic() + 0.05
    assert stream_harness.request(deadline_monotonic=deadline) is None
    assert client.native_resident_client_failure_code() == "native_client_timed_out"
    assert len(stream_harness.processes) == 1
    assert stream_harness.processes[0].poll() is not None


@pytest.mark.parametrize("payload", [b"", b"\xff", b"x" * (6 * 1024 * 1024 + 1)])
def test_invalid_request_never_starts_a_child(stream_harness: _StreamHarness, payload: bytes) -> None:
    assert stream_harness.request(payload) is None
    assert client.native_resident_client_failure_code() == "native_client_request_invalid"
    assert stream_harness.launches == []


def test_stream_accepts_exact_response_bound(stream_harness: _StreamHarness) -> None:
    stream_harness.mode = "echo"
    payload = b"x" * (2 * 1024 * 1024)
    assert stream_harness.request(payload, timeout_seconds=5) == payload
    assert client.native_resident_client_failure_code() is None
