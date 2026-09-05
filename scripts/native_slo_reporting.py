"""Aggregate and render installed native-runtime SLO observations."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import (
    MAX_COLD_P95_MS,
    MAX_INSTALLED_ADAPTER_P95_MS,
    MAX_INSTALLED_ADAPTER_P99_MS,
    MAX_READINESS_P95_MS,
    SAFE_ROUTE_NAMES,
    SIZE_CLASSES,
    SLO_SCHEMA,
    all_gates_pass,
    assert_privacy_safe,
    gate_results,
    summarize,
)


@dataclass(frozen=True)
class SloMeasurements:
    warm: list[Observation]
    sizes: list[Observation]
    recovery: list[float]
    cold: list[float]
    concurrent_16: list[Observation]
    concurrent_64: list[Observation]
    errors_16: int
    errors_64: int
    readiness: list[float]
    rss_baseline: int
    rss_peak: int


@dataclass(frozen=True)
class SloSummary:
    all_observations: list[Observation]
    route_counts: Counter[str]
    warm_routes: Counter[str]
    warm_failures: int
    warm_fail_safe: int
    # Policy denials from size and capacity probes are expected evidence, not
    # native fail-safe outcomes. Keep their aggregate separate from the SLO.
    safe_failures: int
    security_denials: int
    safe_failure_rate: float
    safe_failures_by_size: Counter[str]
    security_denials_by_size: Counter[str]
    size_values: dict[str, list[float]]
    warm_values: list[float]
    concurrent_values: list[float]
    size_p95: dict[str, float]
    event_values: dict[str, list[float]]
    rss_growth: float
    concurrent_64_summary: dict[str, float]
    concurrent_16_overloads: int
    concurrent_64_overloads: int


def _require(condition: bool, reason: object) -> None:
    if not condition:
        raise RuntimeError(f"native_installed_slo_failed: {reason}")


def safe_failure_rate(observations: Sequence[Observation]) -> float:
    """Return the native fail-safe rate for the supplied corpus.

    ``allowed`` is a policy result, so a false value is not itself a fail-safe.
    Large source-reference and bounded-capacity probes may be intentionally
    denied. The SLO gate supplies the ordinary warm corpus here; callers can
    retain all policy denials separately for diagnostic evidence.
    """

    return sum(
        observation.route == "native_fail_safe" and not observation.overloaded for observation in observations
    ) / max(1, len(observations))


def _all_observations(measurements: SloMeasurements) -> list[Observation]:
    return measurements.warm + measurements.sizes + measurements.concurrent_16 + measurements.concurrent_64


def _latencies_by_size(observations: Sequence[Observation]) -> dict[str, list[float]]:
    return {
        size_class: [observation.latency_ms for observation in observations if observation.size_class == size_class]
        for size_class in SIZE_CLASSES
    }


def _latencies_by_event(observations: Sequence[Observation]) -> dict[str, list[float]]:
    return {
        event: [observation.latency_ms for observation in observations if observation.event == event]
        for event in ("PreToolUse", "PostToolUse")
    }


def _failure_counts(
    observations: Sequence[Observation],
) -> tuple[int, Counter[str], int, Counter[str]]:
    safe = [
        observation
        for observation in observations
        if observation.route == "native_fail_safe" and not observation.overloaded
    ]
    denials = [
        observation
        for observation in observations
        if not observation.allowed and (observation.route != "native_fail_safe" or observation.overloaded)
    ]
    return (
        len(safe),
        Counter(observation.size_class for observation in safe),
        len(denials),
        Counter(observation.size_class for observation in denials),
    )


def _rss_growth(measurements: SloMeasurements) -> float:
    if not measurements.rss_baseline:
        return 1.0
    return round(max(0, measurements.rss_peak - measurements.rss_baseline) / measurements.rss_baseline, 6)


def summarize_measurements(measurements: SloMeasurements) -> SloSummary:
    all_observations = _all_observations(measurements)
    route_counts = Counter(observation.route for observation in all_observations)
    _require(
        not (set(route_counts) - SAFE_ROUTE_NAMES),
        {"unexpected_routes": sorted(set(route_counts) - SAFE_ROUTE_NAMES)},
    )
    warm_values = [observation.latency_ms for observation in measurements.warm]
    size_values = _latencies_by_size(all_observations)
    event_values = _latencies_by_event(measurements.warm)
    safe_failures, safe_failures_by_size, security_denials, security_denials_by_size = _failure_counts(all_observations)
    return SloSummary(
        all_observations=all_observations,
        route_counts=route_counts,
        warm_routes=Counter(observation.route for observation in measurements.warm),
        warm_failures=sum(not observation.allowed for observation in measurements.warm),
        warm_fail_safe=sum(observation.route == "native_fail_safe" for observation in measurements.warm),
        safe_failures=safe_failures,
        security_denials=security_denials,
        safe_failure_rate=safe_failure_rate(measurements.warm),
        safe_failures_by_size=safe_failures_by_size,
        security_denials_by_size=security_denials_by_size,
        size_values=size_values,
        warm_values=warm_values,
        concurrent_values=[observation.latency_ms for observation in measurements.concurrent_16],
        size_p95={size_class: summarize(values)["p95_ms"] for size_class, values in size_values.items() if values},
        event_values=event_values,
        rss_growth=_rss_growth(measurements),
        concurrent_64_summary=summarize([item.latency_ms for item in measurements.concurrent_64]),
        concurrent_16_overloads=sum(item.overloaded for item in measurements.concurrent_16),
        concurrent_64_overloads=sum(item.overloaded for item in measurements.concurrent_64),
    )


def _concurrent_observations_are_bounded(
    observations: Sequence[Observation],
    *,
    allow_overload: bool,
) -> bool:
    """Require a resident decision or an explicitly bounded overload result."""

    if not observations:
        return False
    if allow_overload:
        return all(observation.overloaded or observation.route == "native_resident" for observation in observations)
    return all(not observation.overloaded and observation.route == "native_resident" for observation in observations)


def slo_gates(
    measurements: SloMeasurements,
    summary: SloSummary,
    installed_corpus: dict[str, int],
    route_count: int,
    *,
    include_capacity: bool,
) -> dict[str, bool]:
    gates = gate_results(
        resident_share=summary.warm_routes["native_resident"] / max(1, len(measurements.warm)),
        safe_fail_rate=summary.safe_failure_rate,
        warm_p95_ms=summarize(summary.warm_values)["p95_ms"],
        size_p95_ms=summary.size_p95,
        cold_p95_ms=summarize(measurements.cold)["p95_ms"],
        readiness_p95_ms=summarize(measurements.readiness)["p95_ms"],
        concurrent_p99_ms=(
            summarize(summary.concurrent_values)["p99_ms"] if summary.concurrent_values else float("inf")
        ),
        rss_growth=summary.rss_growth,
        rss_baseline_bytes=measurements.rss_baseline,
        errors=measurements.errors_16,
        errors_64=measurements.errors_64,
        python_fallback_decisions=summary.route_counts["python_semantic"],
        installed_python_fallback_decisions=installed_corpus["python_semantic_decisions"],
    )
    gates["recovery_latency"] = summarize(measurements.recovery)["p95_ms"] <= MAX_INSTALLED_ADAPTER_P95_MS
    gates["concurrency"] = gates["concurrency"] and _concurrent_observations_are_bounded(
        measurements.concurrent_16,
        allow_overload=False,
    )
    gates["concurrency_64_bounded"] = (
        include_capacity
        and measurements.errors_64 == 0
        and _concurrent_observations_are_bounded(measurements.concurrent_64, allow_overload=True)
    )
    gates["installed_corpus"] = (
        installed_corpus["routes"] == route_count
        and installed_corpus["resident"] == route_count
        and installed_corpus["oneshot"] == 0
        and installed_corpus["fail_safe"] == 0
        and installed_corpus["python_semantic_decisions"] == 0
    )
    if not include_capacity:
        gates["concurrency"] = False
        gates["concurrency_64_bounded"] = False
    return gates


def slo_result(
    runtime_summary: dict[str, object],
    routes: tuple[tuple[str, str], ...],
    installed_corpus: dict[str, int],
    measurements: SloMeasurements,
    summary: SloSummary,
    gates: dict[str, bool],
    *,
    corpus_origin: str = "installed_wheel_ownership_contract",
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": SLO_SCHEMA,
        "scope": "installed_adapter_to_decision",
        "runtime": runtime_summary,
        "corpus": {
            "harnesses": len({harness for harness, _ in routes}),
            "routes": len(routes),
            "observations": len(summary.all_observations),
            "corpus_origin": corpus_origin,
            "route_corpus": "installed_routes",
            "warm_failures": summary.warm_failures,
            # Keep the historical aliases while exposing an unambiguous name:
            # these are expected policy/capacity denials, not the fail-safe
            # SLO numerator.
            "safe_failures": summary.safe_failures,
            "security_denials": summary.security_denials,
            "safe_failure_rate": round(summary.safe_failure_rate, 6),
            "fail_safe_decisions": summary.warm_fail_safe,
            "fail_safe_rate": round(summary.warm_fail_safe / max(1, len(measurements.warm)), 6),
            "resident_share": round(summary.warm_routes["native_resident"] / max(1, len(measurements.warm)), 6),
            "python_fallback_decisions": summary.warm_routes["python_semantic"],
            "python_semantic_decisions": summary.route_counts["python_semantic"],
            "oneshot_decisions": summary.warm_routes["native_oneshot"],
            "safe_failures_by_size": dict(sorted(summary.safe_failures_by_size.items())),
            "security_denials_by_size": dict(sorted(summary.security_denials_by_size.items())),
            "rss_baseline_bytes": measurements.rss_baseline,
            "rss_peak_bytes": measurements.rss_peak,
            "rss_growth": summary.rss_growth,
            "installed": installed_corpus,
        },
        "routes": dict(sorted(summary.route_counts.items())),
        "python_semantic_decisions": summary.route_counts["python_semantic"],
        "errors_16": measurements.errors_16,
        "errors_64": measurements.errors_64,
        "latency": {
            "warm_all_harnesses": summarize(summary.warm_values),
            "warm_by_event": {event: summarize(values) for event, values in summary.event_values.items() if values},
            "size_classes": {size_class: summarize(values) for size_class, values in summary.size_values.items()},
            "cold_native_oneshot": summarize(measurements.cold),
            "resident_recovery": summarize(measurements.recovery),
            "readiness": summarize(measurements.readiness),
        },
        "thresholds": {
            "installed_adapter_p95_ms": MAX_INSTALLED_ADAPTER_P95_MS,
            "installed_adapter_concurrent_p99_ms": MAX_INSTALLED_ADAPTER_P99_MS,
            "direct_cold_p95_ms": MAX_COLD_P95_MS,
            "readiness_p95_ms": MAX_READINESS_P95_MS,
        },
        "concurrency": {
            "sixteen": {
                "latency": summarize(summary.concurrent_values),
                "errors": measurements.errors_16,
                "overloaded": summary.concurrent_16_overloads,
                "deadline_ms": MAX_INSTALLED_ADAPTER_P99_MS,
            },
            "sixty_four": {
                "latency": summary.concurrent_64_summary,
                "errors": measurements.errors_64,
                "overloaded": summary.concurrent_64_overloads,
                "fail_safe": sum(item.route == "native_fail_safe" for item in measurements.concurrent_64),
                "latency_ceiling_ms": None,
                "bounded": gates.get("concurrency_64_bounded", False),
            },
        },
        "gates": gates,
        "passed": all_gates_pass(gates),
    }
    return assert_privacy_safe(result)


__all__ = [
    "SloMeasurements",
    "SloSummary",
    "safe_failure_rate",
    "slo_gates",
    "slo_result",
    "summarize_measurements",
]
