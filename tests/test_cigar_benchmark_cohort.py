"""Reject incomplete/mixed measurements and concealed cleanup failures."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.bench_guard_cigar_cohort import comparison, qualified
from scripts.bench_guard_cigar_contention import finish_cleanup


def rows():
    return [
        {
            "pair": pair,
            "mode": mode,
            "report": {
                "completed": True,
                "build_sha": "1" * 40,
                "mode": mode,
                "gates": {f"gate-{i}": True for i in range(12)},
                "direct_adapter_warm": {"p95_ms": 10 if mode == "off" else 12},
                "stages": {"1": {"latency": {"p95_ms": 100 if mode == "off" else 104}}},
            },
        }
        for pair in range(1, 6)
        for mode in ("off", "on")
    ]


def test_relative_gate_uses_both_boundaries_and_the_declared_absolute_or_percent_allowance():
    measured = comparison(rows(), 5)
    assert measured["direct"]["median_delta_ms"] == 2
    assert measured["direct"]["allowance_ms"] == 1
    assert measured["direct"]["relative_gate"] is False
    assert measured["installed_http"]["median_delta_ms"] == 4
    assert measured["installed_http"]["allowance_ms"] == 5
    assert measured["installed_http"]["relative_gate"] is True
    assert len(measured["direct"]["paired_deltas"]) == 5
    assert measured["all_relative_gates"] is False


@pytest.mark.parametrize(
    "corruption",
    [
        "missing-run",
        "duplicate-pair",
        "mixed-artifact",
        "missing-artifact",
        "failed-gate",
        "NaN",
        "bool",
    ],
)
def test_incomplete_or_invalid_cohort_cannot_receive_relative_qualification(corruption):
    measured = rows()
    if corruption == "missing-run":
        measured.pop()
    elif corruption == "duplicate-pair":
        measured[-1]["pair"] = 1
    elif corruption == "mixed-artifact":
        measured[-1]["report"]["build_sha"] = "2" * 40
    elif corruption == "missing-artifact":
        for row in measured:
            del row["report"]["build_sha"]
    elif corruption == "failed-gate":
        measured[-1]["report"]["gates"]["gate-0"] = "false"
    else:
        measured[-1]["report"]["direct_adapter_warm"]["p95_ms"] = float("nan") if corruption == "NaN" else False
    with pytest.raises(ValueError):
        comparison(measured, 5)


def test_qualification_does_not_accept_a_missing_gate_container():
    report = rows()[0]["report"]
    report["gates"] = None
    assert not qualified(report, "off", "1" * 40)


@pytest.mark.parametrize("failure", ["retained-failure", "recovery", "live-descendant"])
def test_cleanup_observer_never_converts_recovery_or_live_children_into_success(monkeypatch, failure):
    import scripts.bench_guard_cigar_contention as bench

    ticks = iter((0, 6))
    monkeypatch.setattr(bench, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None))
    counts = {"benchmark_daemon_host": 1}
    if failure == "live-descendant":
        counts["other_descendant"] = 1
    sampler = SimpleNamespace(sample=lambda: {"counts": counts}, summary=lambda: {}, errors=0)
    session = SimpleNamespace(
        final_stop_diagnostic={"status": "contained"},
        last_stop_diagnostic={"status": "failed" if failure == "retained-failure" else "contained"},
        recovery_cleanup={"contained": True} if failure == "recovery" else None,
    )
    result = {"gates": {"original_latency_gate": True}}
    finish_cleanup(result, session, sampler)
    assert result["gates"]["original_latency_gate"] is True
    assert not (result["gates"]["strict_final_stop"] and result["gates"]["all_observed_live_descendants_contained"])
