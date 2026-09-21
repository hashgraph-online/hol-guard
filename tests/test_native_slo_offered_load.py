from __future__ import annotations

import threading
import time

from scripts.native_slo_adapter import Observation
from scripts.native_slo_offered_load import run_offered_load


def _observation() -> Observation:
    return Observation("claude-code", "PostToolUse", "1k", 1.0, "native_resident", True)


def test_offered_load_retains_failed_attempts_and_starts_on_schedule() -> None:
    def observe(index: int) -> Observation:
        if index == 2:
            raise RuntimeError("synthetic failure")
        return _observation()

    report = run_offered_load(observe, rate=20, duration_seconds=0.25, concurrency=2)
    assert report["attempted"] == 5
    assert report["completed"] == 4
    assert report["failed"] == 1
    assert report["generator_dropped"] == report["timed_out"] == 0
    assert report["latency"]["count"] == 5
    assert report["queue"]["count"] == report["service"]["count"] == 5
    assert report["accounted"] is True
    assert report["worker_shutdown_complete"] is True


def test_saturated_generator_counts_dropped_arrivals_instead_of_lowering_offered_rate() -> None:
    def observe(_index: int) -> Observation:
        time.sleep(0.06)
        return _observation()

    report = run_offered_load(observe, rate=500, duration_seconds=0.1, concurrency=1)
    assert report["attempted"] == 50
    assert report["generator_dropped"] > 0
    assert report["completed"] + report["generator_dropped"] == 50
    assert report["latency"]["count"] == 50
    assert report["queue"]["max_ms"] > 0
    assert report["accounted"] is True


def test_unresponsive_observer_is_accounted_and_cannot_block_report_shutdown() -> None:
    release = threading.Event()

    def observe(_index: int) -> Observation:
        release.wait(3)
        return _observation()

    started = time.perf_counter()
    try:
        report = run_offered_load(
            observe,
            rate=100,
            duration_seconds=0.03,
            concurrency=1,
            completion_timeout_seconds=0.02,
        )
        assert time.perf_counter() - started < 1
        assert report["timed_out"] >= 1
        assert report["worker_shutdown_complete"] is False
        assert report["accounted"] is True
        assert report["completed"] + report["failed"] + report["generator_dropped"] + report["timed_out"] == 3
    finally:
        release.set()
