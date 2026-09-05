"""Aggregate reporting and enforcement for the native release benchmark."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from scripts.native_slo_contract import MAX_DIRECT_CONCURRENT_P99_MS

MIN_WARM_P95_SPEEDUP = 1.15
MAX_WARM_P95_MS = 20.0
MIN_COLD_P95_SPEEDUP = 5.0
MAX_COLD_P95_MS = 100.0
MAX_NATIVE_READINESS_MS = 250.0
DIRECT_CONCURRENCY = 16


def empty_summary() -> dict[str, float]:
    return {"p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}


def measurement_summaries(
    summarize: Callable[[list[float]], dict[str, float]],
    python_warm: list[float],
    native_warm: list[float],
    python_cold: list[float],
    native_oneshot: list[float],
    native_concurrent: list[float],
) -> tuple[dict[str, float], dict[str, float], dict[str, float], dict[str, float], dict[str, float]]:
    return (
        summarize(python_warm),
        summarize(native_warm),
        summarize(python_cold),
        summarize(native_oneshot),
        summarize(native_concurrent) if native_concurrent else empty_summary(),
    )


def build_result(
    *,
    python_warm_summary: dict[str, float],
    native_warm_summary: dict[str, float],
    python_cold_summary: dict[str, float],
    native_oneshot_summary: dict[str, float],
    native_concurrent_summary: dict[str, float],
    native_readiness_ms: float,
    native_concurrent_errors: int,
) -> tuple[dict[str, object], float, float]:
    warm_speedup = _speedup(python_warm_summary["p95_ms"], native_warm_summary["p95_ms"])
    cold_speedup = _speedup(python_cold_summary["p95_ms"], native_oneshot_summary["p95_ms"])
    result: dict[str, object] = {
        "schema": "hol-guard-native-performance.v1",
        "warm": {
            "python_hook_process": python_warm_summary,
            "native_resident": native_warm_summary,
            "p95_speedup": warm_speedup,
        },
        "cold": {
            "python_hook_process": python_cold_summary,
            "native_oneshot": native_oneshot_summary,
            "p95_speedup": cold_speedup,
        },
        "native_readiness_ms": round(native_readiness_ms, 3),
        "direct_native_concurrency": {
            "requests": DIRECT_CONCURRENCY,
            "latency": native_concurrent_summary,
            "errors": native_concurrent_errors,
        },
        "gates": {
            "warm_acceptance": "p95_ms_lte_maximum_or_speedup_gte_minimum",
            "minimum_warm_p95_speedup": MIN_WARM_P95_SPEEDUP,
            "maximum_warm_p95_ms": MAX_WARM_P95_MS,
            "minimum_cold_p95_speedup": MIN_COLD_P95_SPEEDUP,
            "maximum_cold_p95_ms": MAX_COLD_P95_MS,
            "maximum_native_readiness_ms": MAX_NATIVE_READINESS_MS,
            "maximum_direct_native_concurrent_p99_ms": MAX_DIRECT_CONCURRENT_P99_MS,
        },
    }
    return result, warm_speedup, cold_speedup


def performance_failures(
    *,
    warm_speedup: float,
    native_warm_summary: Mapping[str, float],
    cold_speedup: float,
    native_oneshot_summary: Mapping[str, float],
    native_readiness_ms: float,
    native_concurrent: list[float],
    native_concurrent_errors: int,
    native_concurrent_summary: Mapping[str, float],
) -> list[str]:
    failures: list[str] = []
    if warm_speedup < MIN_WARM_P95_SPEEDUP and native_warm_summary["p95_ms"] > MAX_WARM_P95_MS:
        failures.append(
            "warm native resident p95 neither meets the "
            f"{MAX_WARM_P95_MS:.0f}ms ceiling nor improves by "
            f"{MIN_WARM_P95_SPEEDUP:.2f}x"
        )
    if cold_speedup < MIN_COLD_P95_SPEEDUP:
        failures.append(f"cold native one-shot p95 speedup is below {MIN_COLD_P95_SPEEDUP:.0f}x")
    if native_oneshot_summary["p95_ms"] > MAX_COLD_P95_MS:
        failures.append(f"cold native one-shot p95 exceeds {MAX_COLD_P95_MS:.0f}ms")
    if native_readiness_ms > MAX_NATIVE_READINESS_MS:
        failures.append(f"native resident readiness exceeds {MAX_NATIVE_READINESS_MS:.0f}ms")
    if not native_concurrent:
        failures.append("direct native concurrency returned no completed requests")
    elif native_concurrent_errors:
        failures.append(f"direct native concurrency returned {native_concurrent_errors} errors")
    if native_concurrent and native_concurrent_summary["p99_ms"] > MAX_DIRECT_CONCURRENT_P99_MS:
        failures.append(f"direct native concurrent p99 exceeds {MAX_DIRECT_CONCURRENT_P99_MS:.0f}ms")
    return failures


def _speedup(slower_p95: float, faster_p95: float) -> float:
    return round(slower_p95 / max(faster_p95, 0.001), 2)
