"""Fixed, boundary-specific acceptance; unmeasured program work stays separate."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from scripts.native_slo_qualification import paired_ratio_interval

_PRIORITY = tuple(
    f"{harness}.{event}" for harness in ("claude-code", "codex") for event in ("PreToolUse", "PostToolUse")
)


def _ceiling(reports: Sequence[Mapping[str, Any]], route: str, quantile: str, budget: float) -> bool:
    for report in reports:
        values = report.get("measurements", {}).get(route)
        if not isinstance(values, Mapping):
            return False
        interval = values.get(f"{quantile}_ci95_ms")
        upper = interval[-1] if isinstance(interval, list) and len(interval) == 2 else values.get(f"{quantile}_ms")
        if not isinstance(upper, (float, int)) or not 0 <= upper <= budget:
            return False
    return bool(reports)


def resource_comparisons(
    baseline: Sequence[Mapping[str, Any]], candidate: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    compared: dict[str, Any] = {}
    for metric in ("cpu_ms_per_attempt", "private_bytes", "rss_bytes"):
        arms: list[list[float]] = []
        complete = True
        for reports in (baseline, candidate):
            values: list[float] = []
            for report in reports:
                resources = report.get("resources", {})
                value = (
                    resources.get(metric) if metric == "cpu_ms_per_attempt" else resources.get("peak", {}).get(metric)
                )
                metric_name = "cpu_seconds" if metric == "cpu_ms_per_attempt" else metric
                if (
                    not resources.get("metric_minimum_met", {}).get(metric_name)
                    or not isinstance(value, (int, float))
                    or value <= 0
                ):
                    complete = False
                else:
                    values.append(float(value))
                if (
                    metric == "cpu_ms_per_attempt"
                    and resources.get("short_exited_descendants_cpu_complete") is not True
                ):
                    complete = False
            arms.append(values)
        compared[metric] = {"qualified": complete}
        if complete:
            compared[metric]["comparison"] = paired_ratio_interval(*arms)
    return compared


def scoped_acceptance(
    baseline: Sequence[Mapping[str, Any]],
    candidate: Sequence[Mapping[str, Any]],
    comparison: Mapping[str, Any],
    sampling: Mapping[str, bool],
) -> dict[str, Any]:
    """Qualify implemented scopes without equating them to the entire Rust PRD.

    Product targets use per-run upper bootstrap bounds. Relative migration
    decisions use paired independent-run intervals and the unchanged PRD gains.
    A missing metric is unqualified, never inferred from another timer.
    """
    independent = sampling.get("independent_runs") is True
    scopes: dict[str, Any] = {}

    def scope(name: str, checks: Mapping[str, bool]) -> None:
        gates = {"independent_runs": independent, **checks}
        scopes[name] = {"qualified": all(gates.values()), "gates": gates}

    scope(
        "native_client_warm",
        {
            "sampling": sampling.get("NATIVE_CLIENT.claude-code.PostToolUse") is True,
            "p95_20ms": _ceiling(candidate, "NATIVE_CLIENT.claude-code.PostToolUse", "p95", 20),
        },
    )
    scope(
        "cold_native_process",
        {
            "sampling": sampling.get("NATIVE_CLIENT.cold_oneshot") is True,
            "p95_150ms": _ceiling(candidate, "NATIVE_CLIENT.cold_oneshot", "p95", 150),
        },
    )
    scope(
        "policy_readiness",
        {
            "sampling": sampling.get("NATIVE_CLIENT.policy_readiness") is True,
            "p95_400ms": _ceiling(candidate, "NATIVE_CLIENT.policy_readiness", "p95", 400),
        },
    )
    for route in _PRIORITY:
        key = "INSTALLED_LAUNCHER." + route
        scope(
            "launcher." + route,
            {
                "sampling": sampling.get(key) is True,
                "p95_50ms": _ceiling(candidate, key, "p95", 50),
                "p99_100ms": _ceiling(candidate, key, "p99", 100),
                "cold_launch_sampling": sampling.get("INSTALLED_LAUNCHER.cold." + route) is True,
                "c16_sampling": sampling.get("INSTALLED_LAUNCHER.c16." + route) is True,
                "c16_p99_200ms": _ceiling(candidate, "INSTALLED_LAUNCHER.c16." + route, "p99", 200),
                "launcher_contracts": all(
                    report.get("launcher", {}).get("contracts_passed") is True for report in candidate
                ),
                "registered_fault_contracts": all(
                    report.get("registered_launcher_contract_corpus", {}).get("implemented_scope_passed") is True
                    for report in [*baseline, *candidate]
                ),
            },
        )
    daemon_keys = [key for key in comparison if key.startswith("DAEMON_INGRESS.") and key != "DAEMON_INGRESS.recovery"]
    scope(
        "daemon_ingress_tail_evidence",
        {
            "sampling": bool(daemon_keys) and all(sampling.get(key) is True for key in daemon_keys),
            "frozen_contracts": all(
                report.get("contract_corpus", {}).get("implemented_scope_passed") is True
                for report in [*baseline, *candidate]
            ),
        },
    )
    scope("recovery_evidence", {"sampling": sampling.get("DAEMON_INGRESS.recovery") is True})
    scope(
        "reference_full_review",
        {
            "full_review": bool(baseline)
            and bool(candidate)
            and all(
                report.get("contract_corpus", {}).get("platform_scope", {}).get("reference_review_qualified") is True
                for report in [*baseline, *candidate]
            )
        },
    )
    resources = resource_comparisons(baseline, candidate)
    for metric, evidence in resources.items():
        scope("daemon_resources." + metric, {"measurement": evidence["qualified"]})
    scope("full_daemon_startup_evidence", {"sampling": sampling.get("DAEMON_PROCESS.startup") is True})
    # New delivery contracts can expose a real defect in the audited baseline.
    # Preserve that result while qualifying the candidate's observed semantic
    # scope separately. Neither side scenario contributes a latency sample.
    side_results: dict[str, Any] = {}
    for name in (
        "registered_surfaces",
        "mixed_contention",
        "priority_approval",
        "priority_input",
        "posture_transitions",
    ):
        observed: dict[str, list[bool]] = {}
        for arm_name, reports in (("baseline", baseline), ("candidate", candidate)):
            outcomes: list[bool] = []
            for report in reports:
                scenarios = report.get("additional_scenarios")
                scenario = scenarios.get(name) if isinstance(scenarios, Mapping) else None
                outcomes.append(isinstance(scenario, Mapping) and scenario.get("passed") is True)
            observed[arm_name] = outcomes
        side_results[name] = {
            "baseline_passed": bool(observed["baseline"]) and all(observed["baseline"]),
            "candidate_passed": bool(observed["candidate"]) and all(observed["candidate"]),
            "headline_timing_eligible": False,
            "coverage": "observed_scenarios_only",
        }
        scope(
            "candidate_observed_semantics." + name,
            {"candidate_contracts": side_results[name]["candidate_passed"]},
        )
    latency = [comparison.get("INSTALLED_LAUNCHER." + route, {}).get("p95", {}) for route in _PRIORITY]
    latency_no_regression = all(item.get("ci95_high", float("inf")) <= 1.05 for item in latency)
    latency_gain = any(item.get("ci95_high", float("inf")) <= 0.70 for item in latency)
    cpu_ratio = resources["cpu_ms_per_attempt"].get("comparison", {}).get("ci95_high", float("inf"))
    gain = independent and ((latency_gain and cpu_ratio <= 1.05) or (latency_no_regression and cpu_ratio <= 0.70))
    return {
        "scope": "observed_platform_implemented_hook_boundaries",
        "scopes": scopes,
        "qualified_scope_count": sum(item["qualified"] for item in scopes.values()),
        "resource_comparisons": resources,
        "additional_scenario_results": side_results,
        "migration_benefit_go": gain,
        "migration_gain_basis": "paired_ci_upper_30pct_gain_and_5pct_other_metric_limit",
        "program_qualification_complete": False,
        "remaining_program_evidence": [
            "all_platforms_combined",
            "native_inner_phase_attribution",
            "nonpriority_full_sampling_and_fault_matrix",
            "browser_approval_continuation",
            "malformed_launcher_input",
            *(
                []
                if scopes["reference_full_review"]["qualified"]
                else ["source_reference_full_content_review", "source_reference_identity_verification"]
            ),
        ],
    }
