from __future__ import annotations

from copy import deepcopy

from scripts.native_slo_acceptance import scoped_acceptance
from scripts.native_slo_qualification import compare_routes, sampling_gates


def _reports() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    warm = [
        f"INSTALLED_LAUNCHER.{harness}.{event}"
        for harness in ("claude-code", "codex")
        for event in ("PreToolUse", "PostToolUse")
    ]
    warm += [route.replace("INSTALLED_LAUNCHER.", "INSTALLED_LAUNCHER.c16.") for route in warm.copy()]
    warm += ["NATIVE_CLIENT.claude-code.PostToolUse", "DAEMON_INGRESS.claude-code.PostToolUse"]
    cold = [
        f"INSTALLED_LAUNCHER.cold.{harness}.{event}"
        for harness in ("claude-code", "codex")
        for event in ("PreToolUse", "PostToolUse")
    ]
    cold += [
        "NATIVE_CLIENT.cold_oneshot",
        "NATIVE_CLIENT.policy_readiness",
        "DAEMON_PROCESS.startup",
        "DAEMON_INGRESS.recovery",
    ]
    arms = []
    for latency, cpu in ((15.0, 10.0), (10.0, 7.0)):
        report = {
            "measurements": {
                route: {"count": 2000 if route in warm else 20, "p95_ms": latency, "p99_ms": latency + 1}
                for route in warm + cold
            },
            "resources": {
                "cpu_ms_per_attempt": cpu,
                "peak": {"private_bytes": 10000, "rss_bytes": 20000},
                "metric_minimum_met": {"cpu_seconds": True, "private_bytes": True, "rss_bytes": True},
                "short_exited_descendants_cpu_complete": True,
            },
            "launcher": {"contracts_passed": True},
            "contract_corpus": {
                "implemented_scope_passed": True,
                "remaining_setups": [],
                "platform_scope": {"reference_review_qualified": True},
            },
            "registered_launcher_contract_corpus": {"implemented_scope_passed": True},
            "additional_scenarios": {
                "registered_surfaces": {"passed": True},
                "mixed_contention": {"passed": True},
                "priority_approval": {"passed": True},
                "priority_input": {"passed": True},
                "posture_transitions": {"passed": True},
            },
        }
        arms.append([deepcopy(report) for _ in range(5)])
    return arms[0], arms[1]


def test_scopes_can_qualify_without_claiming_unmeasured_program_completion() -> None:
    baseline, candidate = _reports()
    comparison = compare_routes(
        [item["measurements"] for item in baseline], [item["measurements"] for item in candidate]
    )
    sampling = sampling_gates(comparison, runs=5)
    assert all(sampling.values())
    result = scoped_acceptance(baseline, candidate, comparison, sampling)
    assert all(scope["qualified"] for scope in result["scopes"].values())
    assert result["migration_benefit_go"] is True
    assert result["program_qualification_complete"] is False
    assert "browser_approval_continuation" in result["remaining_program_evidence"]


def test_unavailable_cpu_does_not_invalidate_an_independently_measured_launcher() -> None:
    baseline, candidate = _reports()
    for report in candidate:
        report["resources"]["short_exited_descendants_cpu_complete"] = False
    comparison = compare_routes(
        [item["measurements"] for item in baseline], [item["measurements"] for item in candidate]
    )
    result = scoped_acceptance(baseline, candidate, comparison, sampling_gates(comparison, runs=5))
    assert result["scopes"]["launcher.claude-code.PostToolUse"]["qualified"] is True
    assert result["scopes"]["daemon_resources.cpu_ms_per_attempt"]["qualified"] is False
    assert result["migration_benefit_go"] is False


def test_slow_route_cannot_hide_inside_fast_routes_or_underfilled_cold_counts() -> None:
    baseline, candidate = _reports()
    candidate[0]["measurements"]["INSTALLED_LAUNCHER.codex.PostToolUse"]["p95_ms"] = 51
    candidate[0]["measurements"]["INSTALLED_LAUNCHER.cold.claude-code.PreToolUse"]["count"] = 1
    comparison = compare_routes(
        [item["measurements"] for item in baseline], [item["measurements"] for item in candidate]
    )
    result = scoped_acceptance(baseline, candidate, comparison, sampling_gates(comparison, runs=5))
    assert result["scopes"]["launcher.codex.PostToolUse"]["gates"]["p95_50ms"] is False
    assert result["scopes"]["launcher.claude-code.PreToolUse"]["gates"]["cold_launch_sampling"] is False


def test_http_fault_evidence_cannot_qualify_missing_registered_launcher_faults() -> None:
    baseline, candidate = _reports()
    del baseline[0]["registered_launcher_contract_corpus"]
    comparison = compare_routes(
        [item["measurements"] for item in baseline], [item["measurements"] for item in candidate]
    )
    result = scoped_acceptance(baseline, candidate, comparison, sampling_gates(comparison, runs=5))
    assert result["scopes"]["daemon_ingress_tail_evidence"]["qualified"] is True
    launcher = result["scopes"]["launcher.claude-code.PreToolUse"]
    assert launcher["qualified"] is False
    assert launcher["gates"]["registered_fault_contracts"] is False


def test_failed_side_scenario_is_not_qualified_by_successful_headline_samples() -> None:
    baseline, candidate = _reports()
    candidate[0]["additional_scenarios"]["mixed_contention"]["passed"] = False
    candidate[0]["additional_scenarios"]["posture_transitions"]["passed"] = False
    del candidate[1]["additional_scenarios"]["registered_surfaces"]
    comparison = compare_routes(
        [item["measurements"] for item in baseline], [item["measurements"] for item in candidate]
    )
    result = scoped_acceptance(baseline, candidate, comparison, sampling_gates(comparison, runs=5))
    assert result["scopes"]["launcher.claude-code.PostToolUse"]["qualified"] is True
    for name in ("registered_surfaces", "mixed_contention", "posture_transitions"):
        assert result["scopes"]["candidate_observed_semantics." + name]["qualified"] is False
        assert result["additional_scenario_results"][name]["candidate_passed"] is False


def test_fixed_candidate_contract_preserves_failed_baseline_semantics() -> None:
    baseline, candidate = _reports()
    baseline[0]["additional_scenarios"]["registered_surfaces"]["passed"] = False
    comparison = compare_routes(
        [item["measurements"] for item in baseline], [item["measurements"] for item in candidate]
    )
    result = scoped_acceptance(baseline, candidate, comparison, sampling_gates(comparison, runs=5))
    observed = result["additional_scenario_results"]["registered_surfaces"]
    assert observed["baseline_passed"] is False
    assert observed["candidate_passed"] is True
    assert observed["headline_timing_eligible"] is False
    assert result["scopes"]["candidate_observed_semantics.registered_surfaces"]["qualified"] is True
    assert result["program_qualification_complete"] is False
