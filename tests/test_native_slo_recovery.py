from __future__ import annotations

from pathlib import Path

import pytest

import scripts.bench_guard_native_installed_slo as benchmark
from scripts.native_slo_adapter import Observation
from scripts.native_slo_capacity import CapacityMeasurements
from scripts.native_slo_contract import MAX_INSTALLED_ADAPTER_P95_MS, all_gates_pass
from scripts.native_slo_reporting import SloMeasurements, slo_gates, slo_result, summarize_measurements


class _RecoverySession:
    def __init__(self, *, allowed: bool = True, route: str = "native_resident") -> None:
        self.events: list[str] = []
        self._allowed = allowed
        self._route = route
        self._stopped = False

    def observe(self, harness: str, event: str, size_class: str) -> Observation:
        self.events.append("observe")
        return Observation(
            harness,
            event,
            size_class,
            1.0,
            self._route if self._stopped else "native_resident",
            self._allowed if self._stopped else True,
        )

    def stop_resident(self) -> bool:
        self.events.append("stop")
        self._stopped = True
        return True

    def rearm_policy_after_resident_stop(self) -> None:
        self.events.append("rearm")


def test_recovery_requires_the_first_post_stop_request_without_rearm() -> None:
    session = _RecoverySession()

    assert len(benchmark._run_recovery(session, 1)) == 1

    assert session.events == ["observe", "stop", "observe"]


def test_explicit_rearm_stays_inside_the_recovery_measurement(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [1.0]

    class TimedSession(_RecoverySession):
        def rearm_policy_after_resident_stop(self) -> None:
            super().rearm_policy_after_resident_stop()
            clock[0] += 0.080

        def observe(self, harness: str, event: str, size_class: str) -> Observation:
            if self._stopped:
                clock[0] += 0.020
            return super().observe(harness, event, size_class)

    monkeypatch.setattr(benchmark.time, "perf_counter", lambda: clock[0])
    session = TimedSession()

    assert benchmark._run_recovery(session, 1, rearm_policy=True) == pytest.approx([100.0])
    assert session.events == ["observe", "stop", "rearm", "observe"]


@pytest.mark.parametrize("rearm_policy", [False, True])
@pytest.mark.parametrize(
    ("allowed", "route"),
    [(False, "native_resident"), (False, "native_fail_safe"), (True, "native_oneshot"), (True, "python_semantic")],
)
def test_recovery_never_replaces_a_failed_first_request(rearm_policy: bool, allowed: bool, route: str) -> None:
    session = _RecoverySession(allowed=allowed, route=route)

    with pytest.raises(RuntimeError, match="recovery sample 0 failed"):
        benchmark._run_recovery(session, 3, rearm_policy=rearm_policy)

    assert session.events == ["observe", "stop", *(["rearm"] if rearm_policy else []), "observe"]


def _measurements(recovery: list[float], rearmed: list[float]) -> SloMeasurements:
    observation = Observation("codex", "PostToolUse", "1k", 1.0, "native_resident", True)
    return SloMeasurements(
        warm=[observation],
        sizes=[
            Observation("codex", "PostToolUse", size, 1.0, "native_resident", True) for size in ("250k", "1m", "5m")
        ],
        recovery=recovery,
        rearmed_recovery=rearmed,
        cold=[1.0],
        concurrent_16=[observation],
        concurrent_64=[observation],
        errors_16=0,
        errors_64=0,
        readiness=[1.0],
        rss_baseline=1,
        rss_peak=1,
    )


@pytest.mark.parametrize(
    ("recovery", "rearmed", "expected"),
    [
        ([1000.0], [1000.0], True),
        ([1000.01], [1.0], False),
        ([1.0], [1000.01], False),
        ([], [1.0], False),
        ([1.0], [], False),
    ],
)
def test_recovery_gates_require_both_cases_with_the_original_budget(
    recovery: list[float], rearmed: list[float], expected: bool
) -> None:
    measurements = _measurements(recovery, rearmed)
    summary = summarize_measurements(measurements)
    installed = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    gates = slo_gates(measurements, summary, installed, 1, include_capacity=True)

    assert MAX_INSTALLED_ADAPTER_P95_MS == 1000.0
    assert all_gates_pass(gates) is expected
    assert gates["recovery_latency"] == (bool(recovery) and max(recovery) <= 1000.0)
    assert gates["rearmed_recovery_latency"] == (bool(rearmed) and max(rearmed) <= 1000.0)


def test_report_distinguishes_autonomous_and_rearmed_recovery() -> None:
    measurements = _measurements([12.0], [34.0])
    summary = summarize_measurements(measurements)
    installed = {"routes": 1, "resident": 1, "oneshot": 0, "fail_safe": 0, "python_semantic_decisions": 0}
    gates = slo_gates(measurements, summary, installed, 1, include_capacity=True)

    report = slo_result({}, (("codex", "PostToolUse"),), installed, measurements, summary, gates)

    assert report["passed"] is True
    latency = report["latency"]
    assert isinstance(latency, dict)
    assert latency["resident_recovery"]["p95_ms"] == 12.0
    assert latency["resident_recovery_rearmed"]["p95_ms"] == 34.0


def test_benchmark_keeps_autonomous_and_rearmed_sessions_separate(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions: list[_RecoverySession] = []

    class Session(_RecoverySession):
        def __init__(self, runtime: Path) -> None:
            del runtime
            super().__init__()
            self.readiness_ms = 1.0
            sessions.append(self)

        def __enter__(self) -> Session:
            return self

        def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
            pass

    monkeypatch.setattr(benchmark, "AdapterSession", Session)
    monkeypatch.setattr(benchmark, "_run_cold", lambda *_args: [1.0])
    monkeypatch.setattr(benchmark, "_run_warm", lambda *_args: [])
    monkeypatch.setattr(benchmark, "_run_sizes", lambda *_args: [])
    monkeypatch.setattr(
        benchmark, "measure_capacity", lambda *_args, **_kwargs: CapacityMeasurements([], [], 0, 0, 1, 1)
    )
    monkeypatch.setattr(benchmark, "process_rss_bytes", lambda: 1)

    measurements = benchmark._measure_slo(
        Path("synthetic-runtime"),
        (("codex", "PostToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=True,
    )

    assert len(sessions) == 3
    assert sessions[1].events == ["observe", "stop", "observe", "observe"]
    assert sessions[2].events == ["observe", "stop", "rearm", "observe"]
    assert len(measurements.recovery) == len(measurements.rearmed_recovery) == 1
