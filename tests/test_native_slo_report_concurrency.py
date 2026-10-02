"""Timeout reports retain a single boundary and late request accounting."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import cast

import pytest

from scripts import native_slo_capacity as capacity
from scripts.native_slo_adapter import Observation
from scripts.native_slo_benchmark_stages import _run_serialized_warmup
from scripts.native_slo_contract import SAFE_FAILURE_STAGE_NAMES
from scripts.native_slo_progress import SloProgress, incomplete_slo_result
from scripts.native_slo_session import AdapterSession


def _progress() -> SloProgress:
    progress = SloProgress()
    progress.configure(
        (("codex", "PreToolUse"),),
        warm_iterations=1,
        cold_iterations=1,
        recovery_iterations=1,
        readiness_samples=1,
        include_capacity=True,
    )
    return progress


def test_failed_report_keeps_one_boundary_during_late_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    progress = _progress()
    progress.submit("capacity_prewarm")
    progress.attempt("capacity_prewarm")
    progress.record_failure(RuntimeError("concurrent capacity wave timed out"), stage="capacity_prewarm")
    original = SloProgress.stage_snapshot

    def finish_live_request(snapshot: SloProgress) -> dict[str, dict[str, object]]:
        stages = original(snapshot)
        progress.complete("capacity_prewarm")
        progress.record_timing("capacity_prewarm", 1.0, 2.0)
        return stages

    monkeypatch.setattr(SloProgress, "stage_snapshot", finish_live_request)
    report = incomplete_slo_result(progress, include_capacity=True)
    assert report["corpus"]["denominators"]["capacity_prewarm"]["completed"] == 0
    assert report["timing"] is None
    assert report["passed"] is False
    assert original(progress)["capacity_prewarm"]["completed"] == 1
    assert progress.timing_snapshot() is not None


def test_timed_out_prewarm_records_a_late_success_once(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()
    entered = threading.Event()
    recorded = threading.Event()
    observations: list[Observation] = []

    class Session:
        def observe(self, harness: str, event: str, size_class: str) -> Observation:
            entered.set()
            assert release.wait(timeout=2)
            return Observation(harness, event, size_class, 1.0, "native_resident", True)

    def receive(values: list[Observation]) -> None:
        observations.extend(values)
        recorded.set()

    original_wait = capacity.wait

    def wait_for_running(futures, *, timeout):
        assert entered.wait(timeout=2)
        return original_wait(futures, timeout=timeout)

    monkeypatch.setattr(capacity, "wait", wait_for_running)
    monkeypatch.setattr(capacity, "_CONCURRENT_WAVE_TIMEOUT_SECONDS", 0.01)
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        with pytest.raises(RuntimeError, match="concurrent capacity wave timed out"):
            capacity._run_concurrent(
                cast(AdapterSession, cast(object, Session())),
                (("codex", "PreToolUse"),),
                1,
                executor,
                on_transport_observations=receive,
            )
        assert entered.is_set()
        release.set()
        assert recorded.wait(timeout=2)
    finally:
        release.set()
        executor.shutdown(wait=True, cancel_futures=True)
    assert len(observations) == 1
    assert observations[0].route == "native_resident"


def test_frozen_progress_preserves_route_dependent_warm_denominators() -> None:
    progress = _progress()
    snapshot = progress.frozen_copy()
    snapshot.configure_routes((("codex", "PreToolUse"), ("pi", "PreToolUse")))

    assert snapshot.stage_snapshot()["warm"]["planned"] == 2
    assert progress.stage_snapshot()["warm"]["planned"] == 1


def test_serialized_warmup_transport_failure_counts_one_request() -> None:
    class Session:
        def observe(self, *_args: object) -> Observation:
            raise ConnectionError("fixture unavailable")

    progress = _progress()
    with pytest.raises(ConnectionError):
        _run_serialized_warmup(cast(AdapterSession, cast(object, Session())), "codex", "PreToolUse", progress=progress)
    stage = progress.stage_snapshot()["serialized_warmup"]
    assert stage["attempted"] == stage["failed"] == 1
    assert stage["completed"] == 0


def test_planned_stages_retain_their_failure_labels() -> None:
    planned = set(_progress().stage_snapshot())
    assert {"warm_precondition", "recovery_precondition", "recovery_stop"} <= planned
    assert planned <= SAFE_FAILURE_STAGE_NAMES
    for stage in planned:
        progress = SloProgress()
        progress.record_failure(RuntimeError("fixture unavailable"), stage=stage)
        assert progress.snapshot_failure()["stage"] == stage
