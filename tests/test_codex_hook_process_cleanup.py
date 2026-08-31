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
