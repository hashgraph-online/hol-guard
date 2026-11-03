"""Tests for the daemon hot-path hook metrics recorder.

``HookMetricsRecorder`` keeps only bounded decision-route counts and failure
counters. These tests pin that contract: routes outside the allowed set fold
into ``native_fail_safe``, failure counters are sanitized, and the counter map
never grows past its bound or exposes session values.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.daemon.hook_metrics import HookMetricsRecorder


@pytest.fixture()
def recorder() -> HookMetricsRecorder:
    return HookMetricsRecorder()


def test_routes_are_counted_and_bounded(recorder: HookMetricsRecorder) -> None:
    recorder.record_route("native_resident")
    recorder.record_route("native_resident")
    recorder.record_route("/private/workspace/route")

    assert recorder.snapshot()["routes"] == {"native_resident": 2, "native_fail_safe": 1}


def test_failure_metrics_are_sanitized_and_bounded(recorder: HookMetricsRecorder) -> None:
    recorder.record_failure(stage="engine", exception_type="RuntimeError")
    recorder.record_failure(stage="unexpected/private/path", exception_type="not a class")

    counters = recorder.snapshot()["counters"]

    assert counters["failure:engine:RuntimeError"] == 1
    assert counters["failure:unknown:UnknownError"] == 1


def test_metric_dimensions_do_not_expose_or_multiply_session_values(recorder: HookMetricsRecorder) -> None:
    for index in range(500):
        recorder.record_failure(stage="engine", exception_type=f"SessionValue{index}")
        recorder.record_route(f"session-{index}")

    snapshot = recorder.snapshot()
    counters = snapshot["counters"]

    assert isinstance(counters, dict)
    assert len(counters) <= 256
    assert counters["metrics:overflow"] > 0
    assert all(isinstance(value, int) and not isinstance(value, bool) for value in counters.values())
    assert snapshot["routes"] == {"native_fail_safe": 500}
