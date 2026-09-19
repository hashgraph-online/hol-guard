"""Sampling, paired block ordering and confidence intervals for qualification."""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Mapping, Sequence

from scripts.native_slo_contract import percentile, summarize

QUALIFICATION_RUNS = 5
PRIORITY_SAMPLES = 10_000
OTHER_SAMPLES = 1_000
COLD_SAMPLES = 100
RECOVERY_SAMPLES = 100
RESOURCE_SAMPLES = 30
_BOOTSTRAPS = 2000


def paired_order(run: int) -> tuple[str, str]:
    return ("baseline", "candidate") if run % 2 == 0 else ("candidate", "baseline")


def sampling_plan(*, runs: int, qualification: bool) -> dict[str, int]:
    if runs < (QUALIFICATION_RUNS if qualification else 1) or runs > 20:
        raise ValueError("run count outside sampling contract")
    return {
        "runs": runs,
        "priority_per_run": math.ceil(PRIORITY_SAMPLES / runs) if qualification else 2,
        "other_per_run": math.ceil(OTHER_SAMPLES / runs) if qualification else 2,
        "cold_per_run": math.ceil(COLD_SAMPLES / runs) if qualification else 2,
        "recovery_per_run": math.ceil(RECOVERY_SAMPLES / runs) if qualification else 2,
        "resource_samples_per_run": RESOURCE_SAMPLES if qualification else 2,
    }


def confidence_summary(values: Sequence[float]) -> dict[str, object]:
    """Nearest-rank quantiles with reproducible empirical-bootstrap intervals.

    The kth order statistic of n uniform draws has a Beta(k,n+1-k)
    distribution. Mapping those draws through the empirical CDF is equivalent
    to resampling n observations and taking their nearest-rank quantile, without
    allocating and sorting n observations for every bootstrap replication.
    These intervals describe within-run variation. Independent-run comparisons
    use paired blocks separately, rather than treating all requests as IID.
    """

    result: dict[str, object] = dict(summarize(values))
    if not values:
        return result
    ordered = sorted(values)
    generator = random.Random(0)
    for quantile, label in ((0.95, "p95"), (0.99, "p99")):
        rank = math.ceil(len(ordered) * quantile)
        samples = [
            ordered[min(len(ordered) - 1, int(len(ordered) * generator.betavariate(rank, len(ordered) + 1 - rank)))]
            for _ in range(_BOOTSTRAPS)
        ]
        result[f"{label}_ci95_ms"] = [round(percentile(samples, 0.025), 3), round(percentile(samples, 0.975), 3)]
    result["interval_method"] = "empirical_percentile_bootstrap_nearest_rank_2000"
    return result


def paired_ratio_interval(baseline: Sequence[float], candidate: Sequence[float]) -> dict[str, object]:
    """Bootstrap paired run-level ratios; preserve environmental block pairing."""

    if len(baseline) != len(candidate) or not baseline:
        raise ValueError("comparison requires matched baseline and candidate blocks")
    if any(not math.isfinite(value) or value <= 0 for value in [*baseline, *candidate]):
        raise ValueError("comparison measurements must be positive finite values")
    ratios = [right / left for left, right in zip(baseline, candidate, strict=True)]
    generator = random.Random(0)
    estimates = [statistics.median(generator.choices(ratios, k=len(ratios))) for _ in range(_BOOTSTRAPS)]
    return {
        "runs": len(ratios),
        "median_ratio": round(statistics.median(ratios), 6),
        "ci95_low": round(percentile(estimates, 0.025), 6),
        "ci95_high": round(percentile(estimates, 0.975), 6),
        "interval_method": "paired_run_block_bootstrap_2000",
        "minimum_runs_met": len(ratios) >= QUALIFICATION_RUNS,
    }


def compare_routes(
    baseline: Sequence[Mapping[str, object]], candidate: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    """Compare each identical route boundary independently; never pool harnesses."""

    if len(baseline) != len(candidate) or not baseline:
        raise ValueError("comparison requires matched blocks")
    route_sets = [set(report) for report in [*baseline, *candidate]]
    if any(routes != route_sets[0] for routes in route_sets):
        raise ValueError("baseline and candidate route coverage differs")
    result: dict[str, object] = {}
    for route in sorted(route_sets[0]):
        left = [report[route] for report in baseline]
        right = [report[route] for report in candidate]
        if any(not isinstance(summary, Mapping) for summary in [*left, *right]):
            raise ValueError("invalid route measurements")
        result[route] = {
            "baseline_samples": sum(int(summary["count"]) for summary in left),
            "candidate_samples": sum(int(summary["count"]) for summary in right),
            "p95": paired_ratio_interval(
                [float(summary["p95_ms"]) for summary in left], [float(summary["p95_ms"]) for summary in right]
            ),
            "p99": paired_ratio_interval(
                [float(summary["p99_ms"]) for summary in left], [float(summary["p99_ms"]) for summary in right]
            ),
        }
    return result


def sampling_gates(comparison: Mapping[str, object], *, runs: int) -> dict[str, bool]:
    """Validate observed counts, not just the requested iteration arguments."""
    gates = {"independent_runs": runs >= QUALIFICATION_RUNS}
    for route, measurement in comparison.items():
        if not isinstance(measurement, Mapping):
            raise ValueError("invalid comparison measurement")
        if route in {
            "NATIVE_CLIENT.cold_oneshot",
            "NATIVE_CLIENT.policy_readiness",
            "DAEMON_PROCESS.startup",
        } or route.startswith("INSTALLED_LAUNCHER.cold."):
            minimum = COLD_SAMPLES
        elif route == "DAEMON_INGRESS.recovery":
            minimum = RECOVERY_SAMPLES
        elif route.startswith("INSTALLED_LAUNCHER.") or ".claude-code." in route or ".codex." in route:
            minimum = PRIORITY_SAMPLES
        else:
            minimum = OTHER_SAMPLES
        gates[route] = all(int(measurement.get(f"{arm}_samples", 0)) >= minimum for arm in ("baseline", "candidate"))
    return gates
