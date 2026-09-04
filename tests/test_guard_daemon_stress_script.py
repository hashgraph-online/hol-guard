from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import urllib.error
from dataclasses import replace
from email.message import Message
from pathlib import Path
from typing import cast

import pytest

import scripts.stress_guard_daemon as stress_script
import scripts.stress_guard_daemon_runtime as stress_runtime
from scripts.stress_guard_daemon import StressResult


class _HealthResponse:
    def __init__(self, payload: object, *, status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _HealthResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int = -1) -> bytes:
        return self._body


@pytest.mark.parametrize(
    "first_error",
    (TimeoutError("temporary timeout"), urllib.error.URLError("connection failed")),
)
def test_health_probe_retries_transient_transport_failure_then_succeeds(
    first_error: Exception,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[float] = []
    responses = iter((first_error, _HealthResponse({"ok": True})))

    def open_health(_url: str, *, timeout: float) -> object:
        calls.append(timeout)
        result = next(responses)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(stress_runtime.urllib.request, "urlopen", open_health)

    assert stress_runtime.health_is_ready("http://127.0.0.1:1") is True
    assert len(calls) == 2
    assert 0 < calls[0] <= 0.5
    assert 0 < calls[1] <= calls[0]


def test_health_probe_retries_persistent_transport_failure_only_once(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0

    def open_health(_url: str, *, timeout: float) -> object:
        del timeout
        nonlocal calls
        calls += 1
        raise TimeoutError("contains-secret-token")

    monkeypatch.setattr(stress_runtime.urllib.request, "urlopen", open_health)

    assert stress_runtime.health_probe_status("http://127.0.0.1:1") == "transient"
    assert stress_runtime.health_is_ready("http://127.0.0.1:1") is False
    assert calls == 4
    assert "contains-secret-token" not in capsys.readouterr().out


def test_health_probe_retries_overload_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[float] = []
    responses = iter(
        (
            urllib.error.HTTPError(
                "http://127.0.0.1:1/healthz",
                503,
                "Service Unavailable",
                Message(),
                io.BytesIO(b'{"error":"daemon_overloaded"}'),
            ),
            _HealthResponse({"ok": True}),
        )
    )

    def open_health(_url: str, *, timeout: float) -> object:
        calls.append(timeout)
        result = next(responses)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(stress_runtime.urllib.request, "urlopen", open_health)

    assert stress_runtime.health_is_ready("http://127.0.0.1:1") is True
    assert len(calls) == 2


def test_health_probe_does_not_retry_an_explicitly_unhealthy_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def open_health(_url: str, *, timeout: float) -> _HealthResponse:
        del timeout
        nonlocal calls
        calls += 1
        return _HealthResponse({"ok": False})

    monkeypatch.setattr(stress_runtime.urllib.request, "urlopen", open_health)

    assert stress_runtime.health_probe_status("http://127.0.0.1:1") == "unhealthy"
    assert stress_runtime.health_is_ready("http://127.0.0.1:1") is False
    assert calls == 2


def test_health_probe_stops_when_total_deadline_is_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    clock = iter((100.0, 100.0, 101.01))

    def open_health(_url: str, *, timeout: float) -> object:
        del timeout
        nonlocal calls
        calls += 1
        raise urllib.error.URLError("temporary connection failure")

    monkeypatch.setattr(stress_runtime.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(stress_runtime.urllib.request, "urlopen", open_health)

    assert stress_runtime.health_is_ready("http://127.0.0.1:1") is False
    assert calls == 1


def test_daemon_stress_gate_keeps_fresh_process_alive_with_populated_store() -> None:
    script = Path(__file__).parents[1] / "scripts" / "stress_guard_daemon.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--requests=12",
            "--receipts=2000",
            "--settle-seconds=0",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    loaded = cast(object, json.loads(completed.stdout))
    assert isinstance(loaded, dict)
    result = cast(dict[str, object], loaded)

    assert completed.returncode == 0, completed.stderr
    assert result["passed"] is True
    assert result["responses"] == 12
    assert result["errors"] == 0
    assert result["health_failures"] == 0
    assert result["pid_stable"] is True
    assert result["daemon_process_count"] == 1
    assert isinstance(result["database_bytes"], int)
    assert result["database_bytes"] > 0
    if os.name != "nt":
        rss_baseline = cast(int, result["rss_baseline_bytes"])
        rss_peak = cast(int, result["rss_peak_bytes"])
        assert rss_baseline > 0
        assert rss_peak >= rss_baseline
    lifecycle_events = result["lifecycle_events"]
    assert isinstance(lifecycle_events, list)
    assert "ready" in lifecycle_events


def test_soak_gate_requires_request_count_resources_and_rss_bound() -> None:
    result = StressResult(
        requests=100_000,
        receipts=250_000,
        responses=100_000,
        errors=0,
        p95_ms=2.0,
        max_ms=4.0,
        health_checks=1,
        health_failures=0,
        pid_stable=True,
        daemon_process_count=1,
        max_hook_latency_ms=4_500.0,
        database_bytes=1,
        lifecycle_events=("ready",),
        max_threads=32,
        max_file_descriptors=128,
        rss_baseline_bytes=100,
        rss_peak_bytes=109,
        rss_growth=0.09,
        transient_health_failures=0,
    )
    assert result.soak_passed
    assert not replace(result, rss_growth=0.11).soak_passed
    assert not replace(result, requests=99_999).soak_passed
    assert not replace(result, receipts=249_999).soak_passed
    isolated_probe_timeouts = replace(result, health_checks=18_932, transient_health_failures=30)
    assert isolated_probe_timeouts.passed
    assert isolated_probe_timeouts.soak_passed
    assert not replace(result, health_checks=18_932, transient_health_failures=200).soak_passed
    assert not replace(result, health_checks=18_932, health_failures=1).passed
    assert not replace(result, health_checks=12, transient_health_failures=1).passed


def test_enforced_soak_rejects_a_short_run_instead_of_claiming_proof() -> None:
    script = Path(__file__).parents[1] / "scripts" / "stress_guard_daemon.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--requests=12",
            "--receipts=2000",
            "--enforce-soak",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert completed.returncode == 2
    assert "requires at least 100000 requests and 250000 receipts" in completed.stderr


def test_soak_baseline_stabilizes_bounded_worker_capacity_before_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = stress_script._StressExecution(
        daemon_url="http://127.0.0.1:1",
        endpoint="http://127.0.0.1:1/v1/hooks/pi",
        auth_token="token",
        initial_pid=123,
        guard_home=Path("guard-home"),
    )
    reports = iter(
        (
            {"hook_workers": {"configured": 4, "target": 2, "workers": 2, "ready": 2, "busy": 0}},
            {"hook_workers": {"configured": 4, "target": 2, "workers": 1, "ready": 1, "busy": 1}},
            {"hook_workers": {"configured": 4, "target": 4, "workers": 4, "ready": 4, "busy": 0}},
        )
    )
    requests: list[str] = []

    monkeypatch.setattr(stress_script, "_WARMUP_CONCURRENCY", 4)
    monkeypatch.setattr(stress_script, "_healthz_details", lambda _execution: next(reports))
    monkeypatch.setattr(stress_script, "_stress_request", lambda *_args: requests.append("request") or 1.0)

    stress_script._stabilize_full_worker_capacity(execution)

    assert len(requests) == 4
    assert execution.latencies_ms == []


def test_stress_cleanup_preserves_resident_before_daemon_retirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(stress_script, "_stop_native_runtime", lambda _guard_home: events.append("resident-stop"))
    monkeypatch.setattr(
        stress_script,
        "_request_graceful_daemon_stop",
        lambda _guard_home: events.append("daemon-worker-close"),
    )
    monkeypatch.setattr(
        stress_script,
        "retire_all_guard_daemons_for_home",
        lambda _guard_home: events.append("daemon-retire") or [],
    )
    monkeypatch.setattr(stress_script, "guard_daemon_retirement_is_complete", lambda _guard_home: True)

    assert stress_script._cleanup_stress_runtime(Path("guard-home")) is True
    assert events == ["resident-stop", "daemon-worker-close", "daemon-retire"]


def test_stress_cleanup_reports_leftover_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stress_script, "_stop_native_runtime", lambda _guard_home: None)
    monkeypatch.setattr(stress_script, "_request_graceful_daemon_stop", lambda _guard_home: None)
    monkeypatch.setattr(stress_script, "retire_all_guard_daemons_for_home", lambda _guard_home: [])
    monkeypatch.setattr(stress_script, "guard_daemon_retirement_is_complete", lambda _guard_home: False)

    assert stress_script._cleanup_stress_runtime(Path("guard-home")) is False
