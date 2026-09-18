"""Aggregate and render installed native-runtime SLO observations."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from scripts.native_slo_adapter import Observation
from scripts.native_slo_batch import validate_batch_routes
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
    installed_launcher: dict[str, object] | None = None
    routes_16: dict[str, int] | None = None
    routes_64: dict[str, int] | None = None
    native_overloads_16: int | None = None
    native_overloads_64: int | None = None
    source_reference_denials: list[dict[str, object]] = field(default_factory=list)


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
    concurrent_16_routes: Counter[str]
    concurrent_64_routes: Counter[str]


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
        size_class: [
            observation.latency_ms
            for observation in observations
            if observation.size_class == size_class
            and (
                size_class == "1k"
                or (observation.allowed and not observation.overloaded and observation.route == "native_resident")
            )
        ]
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


def _capacity_route_counts(
    observations: Sequence[Observation], witnessed: Mapping[str, int] | None, native_overloads: int | None
) -> Counter[str]:
    """Retain actual batch counts without assigning an overload to a route."""
    if witnessed is None:
        _require(
            all(item.route in SAFE_ROUTE_NAMES for item in observations),
            "capacity batch route evidence was missing",
        )
        return Counter(item.route for item in observations)
    _require(
        all(type(value) is int and value > 0 for value in witnessed.values()),
        "capacity batch route evidence was invalid",
    )
    attributed, actual = validate_batch_routes(
        observations, {}, {name: value for name, value in witnessed.items() if name != "engine_bypassed"}
    )
    _require(actual == witnessed, "capacity batch route evidence did not conserve observations")
    _require(
        all(item.route == verified.route for item, verified in zip(observations, attributed, strict=True)),
        "capacity batch observations were not validated",
    )
    _require(
        type(native_overloads) is int and native_overloads == actual.get("native_fail_safe", 0),
        "capacity native overload evidence was invalid",
    )
    return Counter(actual)


def summarize_measurements(measurements: SloMeasurements) -> SloSummary:
    all_observations = _all_observations(measurements)
    ordinary = measurements.warm + measurements.sizes
    route_counts = Counter(observation.route for observation in ordinary)
    _require(
        not (set(route_counts) - SAFE_ROUTE_NAMES),
        {"unexpected_routes": sorted(set(route_counts) - SAFE_ROUTE_NAMES)},
    )
    concurrent_16_routes = _capacity_route_counts(
        measurements.concurrent_16, measurements.routes_16, measurements.native_overloads_16
    )
    concurrent_64_routes = _capacity_route_counts(
        measurements.concurrent_64, measurements.routes_64, measurements.native_overloads_64
    )
    route_counts.update(concurrent_16_routes)
    route_counts.update(concurrent_64_routes)
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
        concurrent_16_routes=concurrent_16_routes,
        concurrent_64_routes=concurrent_64_routes,
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
        return all(
            (
                observation.overloaded
                and not observation.allowed
                and observation.route in {"native_fail_safe", "overload_batch_validated"}
            )
            or (not observation.overloaded and observation.allowed and observation.route == "native_resident")
            for observation in observations
        )
    return all(
        not observation.overloaded and observation.allowed and observation.route == "native_resident"
        for observation in observations
    )


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
        "scope": "daemon_ingress_and_registered_launcher",
        "evidence_class": "smoke",
        "qualification_complete": False,
        "timing_boundaries": {
            "KERNEL": "not_measured",
            "NATIVE_CLIENT": "cold_native_process",
            "DAEMON_INGRESS": "normalized_http_to_harness_decision",
            "INSTALLED_LAUNCHER": "registered_argv" if measurements.installed_launcher else "not_measured",
        },
        "installed_launcher": measurements.installed_launcher,
        "reference_review": {
            "platform_denial_cases": measurements.source_reference_denials,
            "platform_denial_timing_eligible": False,
            "full_review_qualified": bool(measurements.sizes)
            and not measurements.source_reference_denials
            and all(
                item.allowed and not item.overloaded and item.route == "native_resident" for item in measurements.sizes
            ),
            "missing_scopes": ["source_reference_full_content_review", "source_reference_identity_verification"]
            if measurements.source_reference_denials
            else [],
        },
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
            "boundary": "DAEMON_INGRESS",
            "warm_all_harnesses": summarize(summary.warm_values),
            "warm_by_route": {
                f"{harness}.{event}": summarize(
                    [item.latency_ms for item in measurements.warm if (item.harness, item.event) == (harness, event)]
                )
                for harness, event in routes
            },
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
                "routes": dict(sorted(summary.concurrent_16_routes.items())),
                "route_attribution": "isolated_batch_counter_conservation"
                if measurements.routes_16 is not None
                else "per_observation",
                "native_overloads": measurements.native_overloads_16,
                "deadline_ms": MAX_INSTALLED_ADAPTER_P99_MS,
            },
            "sixty_four": {
                "latency": summary.concurrent_64_summary,
                "errors": measurements.errors_64,
                "overloaded": summary.concurrent_64_overloads,
                "fail_safe": summary.concurrent_64_routes["native_fail_safe"],
                "routes": dict(sorted(summary.concurrent_64_routes.items())),
                "route_attribution": "isolated_batch_counter_conservation"
                if measurements.routes_64 is not None
                else "per_observation",
                "native_overloads": measurements.native_overloads_64,
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
