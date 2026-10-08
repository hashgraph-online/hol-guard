"""Concurrent SLO routes come from each worker result, never shared counters."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from codex_plugin_scanner.guard.daemon.hook_process_worker import HookProcessReview
from scripts.native_slo_route_provenance import RequestRouteTracker


class _FixtureObject:
    def __init__(self, **values: object) -> None:
        self.__dict__.update(values)


class _Runner:
    def __init__(self, barrier: threading.Barrier | None = None) -> None:
        self.barrier = barrier
        self.records: list[object] = []

    def _record_route_metric(self, route: object) -> None:
        self.records.append(route)

    def review(self, *, payload: dict[str, object]) -> HookProcessReview:
        if payload.get("retry"):
            return self.review(payload={**payload, "retry": False})
        if self.barrier is not None:
            self.barrier.wait(timeout=5)
        self._record_route_metric(payload.get("route"))
        if payload.get("empty"):
            return HookProcessReview(None, None)
        if payload.get("failed"):
            return HookProcessReview(None, "daemon_hook_process_deadline_exhausted")
        return HookProcessReview({"decision": "allow"}, None)


def test_overlapping_worker_results_preserve_individual_routes() -> None:
    runner = _Runner(threading.Barrier(4))
    tracker = RequestRouteTracker(runner)
    routes = ["native_resident", "native_fail_safe", "native_oneshot", "python_semantic"]

    def observe(route: str) -> str:
        original = {"route": route}
        request, token = tracker.begin(original)
        assert original == {"route": route}
        runner.review(payload=request)
        return tracker.finish(token)

    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            assert list(executor.map(observe, routes)) == routes
        assert sorted(runner.records) == sorted(routes)
        assert not tracker._active
    finally:
        tracker.close()


@pytest.mark.parametrize("payload", [{"route": "unrecognized"}, {"route": "native_resident", "empty": True}, {}])
def test_missing_or_invalid_route_cannot_claim_resident(payload: dict[str, object]) -> None:
    runner = _Runner()
    tracker = RequestRouteTracker(runner)
    try:
        request, token = tracker.begin(payload)
        runner.review(payload=request)
        assert tracker.finish(token) == "native_fail_safe"
    finally:
        tracker.close()


def test_terminal_failure_keeps_route_without_claiming_allowed_decision() -> None:
    runner = _Runner()
    tracker = RequestRouteTracker(runner)
    try:
        request, token = tracker.begin({"route": "native_resident", "failed": True})
        result = runner.review(payload=request)
        assert result.payload is None
        assert result.reason_code == "daemon_hook_process_deadline_exhausted"
        assert tracker.finish(token) == "native_resident"
    finally:
        tracker.close()


def test_retry_preserves_the_terminal_result_and_close_restores_runner() -> None:
    runner = _Runner()
    review, record = runner.review, runner._record_route_metric
    tracker = RequestRouteTracker(runner)
    request, token = tracker.begin({"route": "native_resident", "retry": True})
    runner.review(payload=request)
    assert tracker.finish(token) == "native_resident"
    tracker.close()
    tracker.close()
    assert runner.review == review
    assert runner._record_route_metric == record
    with pytest.raises(RuntimeError, match="route tracker is closed"):
        tracker.begin({})


def test_late_result_cannot_recreate_finished_token() -> None:
    barrier = threading.Barrier(2)
    runner = _Runner(barrier)
    tracker = RequestRouteTracker(runner)
    request, token = tracker.begin({"route": "native_resident"})
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(runner.review, payload=request)
            assert tracker.finish(token) == "native_fail_safe"
            barrier.wait(timeout=5)
            future.result(timeout=5)
        assert not tracker._active
        assert tracker.finish(token) == "native_fail_safe"
    finally:
        tracker.close()


def test_direct_http_worker_records_request_local_route_and_is_restored() -> None:
    runner = _Runner()

    class Worker:
        def __init__(self) -> None:
            self.metrics = _FixtureObject(record_route=lambda route: None)

        def review_http_payload(self, *, payload: dict[str, object]) -> dict[str, str]:
            self.metrics.record_route("native_resident")
            return {"decision": "allow"}

    worker = Worker()
    original_review, original_record = worker.review_http_payload, worker.metrics.record_route
    tracker = RequestRouteTracker(runner, worker)
    try:
        request, token = tracker.begin({})
        assert worker.review_http_payload(payload=request) == {"decision": "allow"}
        assert tracker.finish(token) == "native_resident"
    finally:
        tracker.close()
    assert worker.review_http_payload == original_review
    assert worker.metrics.record_route == original_record
