from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.native_slo_stop_diagnostics import _stop_diagnostic_from_stderr
from scripts.native_slo_stop_trace import StopTrace


class Sampler:
    def __init__(self):
        self.snapshots = iter(
            (
                ({"rss_bytes": 10}, {(1, ("start-one",)): "native_runtime"}),
                ({"rss_bytes": 20}, {(2, ("start-two",)): "native_runtime"}),
            )
        )

    def sample_with_identities(self):
        return next(self.snapshots)


def test_stop_trace_preserves_timeout_exception_deadline_and_payload_privacy(monkeypatch):
    error = subprocess.TimeoutExpired(
        ["/native", "resident-stop"],
        2,
        stderr=(
            b"native_resident_phase phase=client_response_read status=ok elapsed_ms=1\n"
            b"private-diagnostic-must-not-save\n"
        ),
    )
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        raise error

    monkeypatch.setattr(subprocess, "run", run)
    with (
        StopTrace(Path("/native"), Sampler(), case=lambda: "session_3:readiness") as trace,
        pytest.raises(subprocess.TimeoutExpired) as caught,
    ):
        subprocess.run(["/native", "resident-stop"], timeout=2, env={"PUBLIC_FLAG": "1"})
    assert caught.value is error and subprocess.run is run
    assert len(calls) == 1 and calls[0][1]["timeout"] == 2
    assert calls[0][1]["env"] == {"PUBLIC_FLAG": "1", "HOL_GUARD_NATIVE_DIAGNOSTIC": "1"}
    row = trace.events[0]
    assert row["case"] == "session_3:readiness"
    assert row["process_outcome"] == "timed_out"
    assert row["new_counts"] == row["gone_counts"] == {"native_runtime": 1}
    assert row["phases"] == [{"phase": "client_response_read", "status": "ok", "elapsed_ms": 1}]
    assert "private-diagnostic" not in str(row)


def test_unrelated_commands_and_other_binaries_keep_their_original_arguments(monkeypatch):
    calls = []
    outcome = subprocess.CompletedProcess([], 0, b"", b"")

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return outcome

    monkeypatch.setattr(subprocess, "run", run)
    with StopTrace(Path("/native"), Sampler()) as trace:
        assert subprocess.run(["/native", "capabilities"], timeout=4) is outcome
        assert subprocess.run(["/other", "resident-stop"], timeout=2) is outcome
    assert calls == [((["/native", "capabilities"],), {"timeout": 4}), ((["/other", "resident-stop"],), {"timeout": 2})]
    assert trace.events == []


def test_phase_lines_cannot_hide_the_native_stop_error_or_change_transient_retry_classification():
    observed = _stop_diagnostic_from_stderr(
        b"native_resident_phase phase=client_connect status=ok elapsed_ms=2\n"
        b"native_resident_note name=states value=0\n"
        b"native_resident_stop_unavailable\n"
    )
    assert observed["error"] == "native_resident_stop_unavailable"
    assert (
        _stop_diagnostic_from_stderr(b"native_resident_phase anything")["error"]
        == "native_resident_stop_process_failed"
    )
