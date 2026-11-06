"""Windows process cleanup ordering regressions."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch_runtime
from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process


def test_windows_success_closes_job_after_io_drain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class RecordingStream(io.BytesIO):
        def __init__(self, name: str, value: bytes = b"") -> None:
            super().__init__(value)
            self.name = name

        def close(self) -> None:
            events.append(f"{self.name}-close")
            super().close()

    class ExitedProcess:
        pid = 987_654

        def __init__(self) -> None:
            self.stdin = RecordingStream("stdin")
            self.stdout = RecordingStream("stdout", b"response")
            self.stderr = RecordingStream("stderr", b"diagnostic")

        def poll(self) -> int:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 0

    class RecordingJob:
        def terminate(self) -> None:
            events.append("job-terminate")

        def close(self) -> None:
            events.append("job-close")

    process = ExitedProcess()
    job = RecordingJob()
    monkeypatch.setattr(launch_runtime.os, "name", "nt")
    monkeypatch.setattr(
        launch_runtime,
        "spawn_windows_hook_process",
        lambda *_args, **_kwargs: (process, job),
    )

    result = run_isolated_hook_process(
        ["managed"],
        input_text="",
        cwd=tmp_path,
        environment={},
        timeout_seconds=1,
    )

    assert result.returncode == 0
    assert result.containment_failed is False
    assert "job-terminate" not in events
    assert events.index("job-close") < events.index("stdout-close")
    assert events.index("job-close") < events.index("stderr-close")
    assert process.stdin.closed and process.stdout.closed and process.stderr.closed


def test_windows_failure_terminates_job_before_final_stream_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class RecordingStream(io.BytesIO):
        def __init__(self, name: str) -> None:
            super().__init__()
            self.name = name

        def close(self) -> None:
            events.append(f"{self.name}-close")
            super().close()

    class FailedProcess:
        pid = 987_654

        def __init__(self) -> None:
            self.stdin = RecordingStream("stdin")
            self.stdout = RecordingStream("stdout")
            self.stderr = RecordingStream("stderr")

        def poll(self) -> int:
            return 7

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            return 7

    class RecordingJob:
        def terminate(self) -> None:
            events.append("job-terminate")

        def close(self) -> None:
            events.append("job-close")

    process = FailedProcess()
    job = RecordingJob()
    monkeypatch.setattr(launch_runtime.os, "name", "nt")
    monkeypatch.setattr(
        launch_runtime,
        "spawn_windows_hook_process",
        lambda *_args, **_kwargs: (process, job),
    )

    result = run_isolated_hook_process(
        ["managed"],
        input_text="",
        cwd=tmp_path,
        environment={},
        timeout_seconds=1,
    )

    assert result.returncode == 7
    assert result.containment_failed is False
    assert events.index("job-terminate") < events.index("stdout-close")
    assert events.index("job-terminate") < events.index("stderr-close")
    assert events.index("job-close") < events.index("stdout-close")


class _FakeJob:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def terminate(self) -> None:
        self.events.append("job-terminate")

    def close(self) -> None:
        self.events.append("job-close")


class _FailingStream(io.BytesIO):
    def read(self, size: int | None = -1) -> bytes:
        del size
        raise OSError("read failed")


class _FakeProcess:
    pid = 987_655

    def __init__(self, stdout: io.BytesIO, stderr: io.BytesIO) -> None:
        self.stdin = io.BytesIO()
        self.stdout = stdout
        self.stderr = stderr

    def poll(self) -> int:
        return 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return 0


def _use_fake_windows_process(monkeypatch: pytest.MonkeyPatch, process: _FakeProcess, job: _FakeJob) -> None:
    monkeypatch.setattr(launch_runtime.os, "name", "nt")
    monkeypatch.setattr(launch_runtime, "spawn_windows_hook_process", lambda *_args, **_kwargs: (process, job))


def test_read_failure_marks_capture_incomplete_and_keeps_raw_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_fake_windows_process(monkeypatch, _FakeProcess(_FailingStream(), io.BytesIO(b"\xff raw")), _FakeJob([]))

    result = run_isolated_hook_process(["managed"], input_text="", cwd=tmp_path, environment={}, timeout_seconds=1)

    assert result.capture_incomplete is True
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b"\xff raw"
    assert result.stderr == "� raw"


def test_interrupted_wait_terminates_the_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _use_fake_windows_process(monkeypatch, _FakeProcess(io.BytesIO(), io.BytesIO()), _FakeJob(events))

    def interrupted_wait(*_args: object, **_kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(launch_runtime, "wait_for_hook_process", interrupted_wait)

    with pytest.raises(KeyboardInterrupt):
        run_isolated_hook_process(["managed"], input_text="", cwd=tmp_path, environment={}, timeout_seconds=1)

    assert events == ["job-terminate"]
