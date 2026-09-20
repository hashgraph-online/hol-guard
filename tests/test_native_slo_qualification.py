from __future__ import annotations

import pytest

from scripts.native_slo_qualification import (
    compare_routes,
    confidence_summary,
    paired_order,
    paired_ratio_interval,
    sampling_gates,
    sampling_plan,
)
from scripts.native_slo_qualification_run import _native_sample_values


def test_qualification_plan_meets_minima_across_independent_runs() -> None:
    for runs in (5, 6, 9):
        plan = sampling_plan(runs=runs, qualification=True)
        assert plan["priority_per_run"] * runs >= 10_000
        assert plan["other_per_run"] * runs >= 1000
        assert plan["cold_per_run"] * runs >= 100
        assert plan["recovery_per_run"] * runs >= 100
    with pytest.raises(ValueError):
        sampling_plan(runs=4, qualification=True)
    assert [paired_order(index) for index in range(3)] == [
        ("baseline", "candidate"),
        ("candidate", "baseline"),
        ("baseline", "candidate"),
    ]


def test_confidence_intervals_use_observed_distribution_and_are_reproducible() -> None:
    values = [float(value) for value in range(1, 10_001)]
    report = confidence_summary(values)
    assert report == confidence_summary(values)
    assert report["p95_ms"] == 9500
    assert report["p99_ms"] == 9900
    assert report["p95_ci95_ms"][0] < 9500 < report["p95_ci95_ms"][1]
    assert report["p99_ci95_ms"][0] < 9900 < report["p99_ci95_ms"][1]
    constant = confidence_summary([12.5] * 100)
    assert constant["p95_ci95_ms"] == constant["p99_ci95_ms"] == [12.5, 12.5]


def test_paired_intervals_preserve_block_pairing() -> None:
    baseline = [10.0, 200.0, 50.0, 100.0, 20.0]
    candidate = [value * 0.7 for value in baseline]
    result = paired_ratio_interval(baseline, candidate)
    assert result["median_ratio"] == result["ci95_low"] == result["ci95_high"] == 0.7
    assert result["minimum_runs_met"] is True
    assert paired_ratio_interval(baseline[:2], candidate[:2])["minimum_runs_met"] is False


def test_comparison_rejects_mismatched_routes_and_insufficient_actual_samples() -> None:
    left = [{"DAEMON_INGRESS.claude-code.PostToolUse": {"count": 2, "p95_ms": 10, "p99_ms": 12}}] * 5
    right = [{"DAEMON_INGRESS.claude-code.PostToolUse": {"count": 2, "p95_ms": 7, "p99_ms": 9}}] * 5
    compared = compare_routes(left, right)
    gates = sampling_gates(compared, runs=5)
    assert gates["independent_runs"] is True
    assert gates["DAEMON_INGRESS.claude-code.PostToolUse"] is False
    with pytest.raises(ValueError, match="coverage differs"):
        compare_routes(left, [{"another.route": {"count": 2, "p95_ms": 7, "p99_ms": 9}}] * 5)


@pytest.mark.parametrize("values", [[], [True], ["2"], [float("nan")], [float("inf")], [-1], [1, 2]])
def test_native_sample_batch_rejects_malformed_or_missing_actual_observations(values: object) -> None:
    with pytest.raises(RuntimeError, match="bounded values"):
        _native_sample_values({"benign_and_block_validated": True, "values": values}, 1)


def test_native_sample_batch_requires_semantic_preflight_and_exact_observed_count() -> None:
    assert _native_sample_values({"benign_and_block_validated": True, "values": [1, 2.5]}, 2) == [1.0, 2.5]
    with pytest.raises(RuntimeError, match="preflight"):
        _native_sample_values({"benign_and_block_validated": False, "values": [1]}, 1)
