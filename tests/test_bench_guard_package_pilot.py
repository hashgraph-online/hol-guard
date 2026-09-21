"""A package pilot may not qualify partial pairs or trade one metric unchecked."""

from __future__ import annotations

from scripts.bench_guard_package_pilot import summarize


def _pair(candidate_cpu=70, candidate_wall=105):
    return {
        "dependencies": 10000,
        "bundle_records": 100,
        "mode": "absent",
        "expected_native_completions": 1,
        "comparison": {"status": "equal"},
        "baseline": {"measurement": {"cpu_median_ms": 100, "wall_median_ms": 100}},
        "candidate": {"measurement": {"cpu_median_ms": candidate_cpu, "wall_median_ms": candidate_wall}},
    }


def test_cpu_gate_also_bounds_wall_regression():
    # Avoid exact floating-point decimal boundaries; these are diagnostic medians.
    assert summarize([_pair(69, 104)])[0]["diagnostic_cpu_gate_pass"]
    assert not summarize([_pair(69, 106)])[0]["diagnostic_cpu_gate_pass"]
    assert not summarize([_pair(71, 100)])[0]["diagnostic_cpu_gate_pass"]


def test_failed_or_censored_pair_blocks_numeric_gate_without_discarding_success():
    failed = _pair()
    failed["comparison"] = {"status": "not_comparable"}
    result = summarize([_pair(), failed])[0]
    assert result["pairs"] == 2 and result["equal_pairs"] == 1
    assert "diagnostic_cpu_gate_pass" not in result
    assert "cpu_median_improvement_percent" not in result


def test_fallback_controls_never_claim_a_native_scope():
    pair = _pair()
    pair["expected_native_completions"] = 0
    assert not summarize([pair])[0]["native_scope"]
