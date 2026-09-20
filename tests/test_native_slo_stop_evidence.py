"""Recovery keeps its original stop failure when real session cleanup runs."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import bench_guard_native_installed_slo as bench
from scripts import native_slo_session as local
from scripts.native_slo_adapter import Observation
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_observation_failure import SloProgress


@pytest.mark.parametrize("cleanup_failed", [False, True])
def test_recovery_failure_precedes_real_session_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup_failed: bool
) -> None:
    events = []
    stop_calls = []
    sessions = []
    original_errors = []
    report = tmp_path / "native-stop-diagnostic.json"
    monkeypatch.setenv("NATIVE_STOP_DIAGNOSTIC_PATH", str(report))

    class Session:
        # Use the real lifecycle methods with a finite constructor that starts
        # no daemon, process, socket or native executable.
        __enter__ = local.AdapterSession.__enter__
        __exit__ = local.AdapterSession.__exit__
        close = local.AdapterSession.close
        stop_resident = local.AdapterSession.stop_resident

        def __init__(self, runtime: Path) -> None:
            self.label = "active" if sessions else "cold"
            sessions.append(self)
            self.runtime = runtime
            self.guard_home = tmp_path / self.label
            self.workspace = tmp_path
            self._connection = None
            self.last_stop_diagnostic = local._build_stop_diagnostic("not-run")
            self._stop_diagnostic_written = False
            self.temporary: Any = SimpleNamespace(cleanup=lambda: events.append((self.label, "temporary_cleanup")))
            self.daemon: Any = SimpleNamespace(
                stop=lambda: events.append((self.label, "daemon_stop")),
                _server=SimpleNamespace(
                    active_hook_requests=0,
                    hook_process_runner=SimpleNamespace(close_native_resident_clients=lambda: True),
                ),
            )

        def start(self) -> None:
            events.append((self.label, "start"))

        def observe(self, harness: str, event: str, size_class: str) -> Observation:
            events.append((self.label, "observe"))
            return Observation(harness, event, size_class, 1.0, "native_resident", True)

    def stop(runtime: Path, guard_home: Path, *, write_diagnostic: bool = True) -> local.NativeStopResult:
        stop_calls.append((str(runtime), guard_home.name, write_diagnostic))
        count = sum(label == "active" for _, label, _ in stop_calls)
        failed = guard_home.name == "active" and (count == 1 or (count == 2 and cleanup_failed))
        code = "native_resident_stop_unavailable" if count == 1 else "native_resident_stop_in_progress"
        diagnostic = local._build_stop_diagnostic(
            "failed" if failed else "contained",
            error=code if failed else None,
            fields={"authenticated": "verified", "owner_lock": "busy" if failed else "free"},
        )
        if write_diagnostic:
            local._write_stop_diagnostic(diagnostic)
        return local.NativeStopResult(not failed, diagnostic)

    original_require = bench._require

    def require(condition: bool, reason: object) -> None:
        try:
            original_require(condition, reason)
        except RuntimeError as error:
            original_errors.append(error)
            raise

    monkeypatch.setattr(bench, "AdapterSession", Session)
    monkeypatch.setattr(bench, "_require", require)
    monkeypatch.setattr(bench, "_run_cold", lambda *_args: [])
    monkeypatch.setattr(bench, "_run_warm", lambda *_args: [])
    monkeypatch.setattr(bench, "_run_sizes", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(local, "stop_native_resident", stop)
    with pytest.raises(FixtureFailureError, match="resident stop failed during recovery sample 0") as caught:
        bench._measure_slo(
            Path("fixed-runtime"),
            (("claude-code", "PostToolUse"),),
            warm_iterations=1,
            cold_iterations=1,
            recovery_iterations=2,
            readiness_samples=0,
            include_capacity=False,
        )
    assert stop_calls == [
        ("fixed-runtime", "cold", True),
        ("fixed-runtime", "cold", False),
        ("fixed-runtime", "active", True),
        ("fixed-runtime", "active", True),
        ("fixed-runtime", "active", False),
    ]
    assert events.count(("active", "observe")) == 1
    assert events.count(("active", "daemon_stop")) == events.count(("active", "temporary_cleanup")) == 1
    cause: BaseException = caught.value
    while cause.__cause__ is not None:
        cause = cause.__cause__
    assert cause is original_errors[0] and type(cause) is RuntimeError
    assert str(cause) == "native_installed_slo_failed: resident stop failed during recovery sample 0"
    later = json.loads(report.read_text())
    assert later["status"] == ("failed" if cleanup_failed else "contained")
    if cleanup_failed:
        assert later["error"] == "native_resident_stop_in_progress"
    detail = failure_evidence(caught.value)
    captured = detail["recovery_stop"]
    assert isinstance(captured, dict)
    assert captured["capture_boundary"] == "recovery_phase_exception_before_session_cleanup"
    assert captured["status"] == "failed" and captured["error"] == "native_resident_stop_unavailable"
    assert captured["owner_lock"] == "busy"
    assert detail["failed_phase"] == "recovery"
    completed_counts = detail["completed_sample_counts"]
    assert isinstance(completed_counts, dict) and "recovery" not in completed_counts
    assert str(tmp_path) not in json.dumps(detail)


def test_capture_failure_keeps_original_exception_and_success_never_captures() -> None:
    original = RuntimeError("original operation failure")
    calls = []

    def unavailable() -> object:
        calls.append("capture")
        raise RuntimeError("private diagnostic failure")

    with SloProgress().phase("recovery", stop_diagnostic=unavailable):
        pass
    assert calls == []
    with pytest.raises(FixtureFailureError) as caught, SloProgress().phase("recovery", stop_diagnostic=unavailable):
        raise original
    assert calls == ["capture"] and caught.value.__cause__ is original
    assert failure_evidence(caught.value)["recovery_stop"] == {"available": False, "capture_failed": True}
    assert "private diagnostic failure" not in json.dumps(failure_evidence(caught.value))


def test_capture_copies_closed_fields_without_exporting_paths_or_payloads() -> None:
    from scripts.native_slo_observation_failure import _recovery_stop_evidence

    value = local._build_stop_diagnostic("failed", error="native_resident_stop_unavailable")
    value.update(payload="PRIVATE_BODY", path="PRIVATE_PATH", owner_lock="PRIVATE_VALUE")
    observed = _recovery_stop_evidence(value)
    value["status"] = "contained"
    assert observed["status"] == "failed" and observed["error"] == "native_resident_stop_unavailable"
    assert "PRIVATE" not in json.dumps(observed)
    assert _recovery_stop_evidence(None)["available"] is False
