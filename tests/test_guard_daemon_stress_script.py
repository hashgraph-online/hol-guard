from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import urllib.error
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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


class _HookResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _HookResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int = -1) -> bytes:
        return self._body


def test_stress_request_retries_empty_hook_body(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = {"count": 0}

    def open_hook(_request: object, timeout: float | None = None) -> _HookResponse:
        del timeout
        attempts["count"] += 1
        if attempts["count"] == 1:
            return _HookResponse(b"")
        return _HookResponse(b'{"decision":"allow"}')

    monkeypatch.setattr(stress_runtime.urllib.request, "urlopen", open_hook)
    monkeypatch.setattr(stress_runtime.time, "sleep", lambda _seconds: None)

    latency = stress_runtime.stress_request("http://127.0.0.1:1/v1/hooks/pi", "token")

    assert latency >= 0
    assert attempts["count"] == 2


def test_wait_until_health_ready_retries_until_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    states = iter((False, True))

    monkeypatch.setattr(stress_runtime, "health_is_ready", lambda _url: next(states))
    monkeypatch.setattr(stress_runtime.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(stress_runtime.time, "monotonic", lambda: 0.0)

    stress_runtime.wait_until_health_ready("http://127.0.0.1:1")


def test_wait_until_daemon_lifecycle_ready_retries_until_ready(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    states = iter((False, True))

    monkeypatch.setattr(stress_script, "_daemon_lifecycle_is_ready", lambda _home: next(states))
    monkeypatch.setattr(stress_script.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(stress_script.time, "monotonic", lambda: 0.0)

    stress_script._wait_until_daemon_lifecycle_ready(tmp_path)


def test_soak_warmup_follows_lifecycle_ready_without_a_worker_floor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard-home"
    execution = stress_script._StressExecution(
        daemon_url="http://127.0.0.1:1",
        endpoint="http://127.0.0.1:1/v1/hooks/pi",
        auth_token="token",
        initial_pid=123,
        guard_home=guard_home,
    )
    store = stress_script.GuardStore(guard_home, prime_policy_integrity=False)
    order: list[str] = []
    warmup_counts: list[int] = []

    def prepare(_root: Path, _receipt_count: int) -> tuple[object, stress_script._StressExecution, Path]:
        order.append("prepare")
        return store, execution, guard_home

    def record(name: str) -> Callable[..., None]:
        def inner(*_args: object, **_kwargs: object) -> None:
            order.append(name)

        return inner

    def warmup(_endpoint: str, _auth_token: str, count: int) -> None:
        order.append("warmup")
        warmup_counts.append(count)

    monkeypatch.setattr(stress_script, "_prepare_stress_execution", prepare)
    monkeypatch.setattr(stress_script, "_sample_stress_runtime", record("sample"))
    monkeypatch.setattr(stress_script, "_wait_until_health_ready", record("health"))
    monkeypatch.setattr(stress_script, "_wait_until_daemon_lifecycle_ready", record("lifecycle"))
    monkeypatch.setattr(stress_script, "_stress_warmup", warmup)
    monkeypatch.setattr(stress_script, "_initialize_stress_resources", record("resources"))
    monkeypatch.setattr(stress_script, "_run_stress_batches", record("batches"))
    monkeypatch.setattr(stress_script, "_settle_stress_runtime", record("settle"))
    monkeypatch.setattr(stress_script, "_finalize_stress_runtime", record("finalize"))
    monkeypatch.setattr(stress_script, "_cleanup_stress_runtime", lambda _home: order.append("cleanup") or True)
    monkeypatch.setattr(stress_script, "load_daemon_lifecycle_events", lambda _home: [])

    result = stress_script.run_stress(request_count=12, receipt_count=0, settle_seconds=0)

    assert order == [
        "prepare",
        "sample",
        "health",
        "lifecycle",
        "warmup",
        "resources",
        "batches",
        "settle",
        "finalize",
        "cleanup",
    ]
    assert warmup_counts == [min(stress_script._WARMUP_CONCURRENCY, max(4, 12))]
    assert result.requests == 12
    assert not hasattr(stress_script, "_worker_capacity_is_past_deferred_startup_floor")
    assert not hasattr(stress_script, "_stabilize_full_worker_capacity")


def test_daemon_stress_gate_keeps_fresh_process_alive_with_populated_store() -> None:
    script = Path(__file__).parents[1] / "scripts" / "stress_guard_daemon.py"
    environment = dict(os.environ)
    # The spawned daemon answers route policy through the resident, which has
    # no Python fallback: hand it the same runtime the lane under test uses.
    if environment.get("HOL_GUARD_NATIVE_BINARY"):
        environment["HOL_GUARD_NATIVE"] = "force"
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
        env=environment,
        timeout=90,
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
    assert replace(result, rss_growth=0.385).soak_passed
    assert replace(result, rss_growth=0.49).soak_passed
    assert replace(result, rss_growth=0.50).soak_passed
    assert not replace(result, rss_growth=0.51).soak_passed
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


def test_measured_stress_batches_keep_health_probes_under_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = stress_runtime.StressExecution(
        daemon_url="http://127.0.0.1:1",
        endpoint="http://127.0.0.1:1/v1/hooks/pi",
        auth_token="token",
        initial_pid=123,
        guard_home=Path("guard-home"),
    )
    all_requests_started = threading.Event()
    release_requests = threading.Event()
    health_probe_observed = threading.Event()
    started_requests = 0
    started_requests_lock = threading.Lock()
    health_samples: list[int] = []

    def stress_request(*_args: object) -> float:
        nonlocal started_requests
        with started_requests_lock:
            started_requests += 1
            if started_requests == 4:
                all_requests_started.set()
        assert release_requests.wait(timeout=5)
        return 1.0

    def observe_measured_health(current: stress_runtime.StressExecution) -> None:
        health_samples.append(current.health_checks)
        current.health_checks += 1
        health_probe_observed.set()

    monkeypatch.setattr(stress_runtime, "stress_request", stress_request)
    monkeypatch.setattr(
        stress_runtime,
        "sample_stress_runtime",
        observe_measured_health,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(stress_runtime.run_stress_batches, execution, 4)
        assert all_requests_started.wait(timeout=2)
        try:
            assert health_probe_observed.wait(timeout=2)
        finally:
            release_requests.set()
        future.result(timeout=5)

    assert health_samples
    assert execution.health_checks == len(health_samples)
    assert execution.errors == []


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
