"""Bounded executor setup and diagnostics for native SLO capacity probes."""

from __future__ import annotations

import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from scripts.bench_guard_native_installed_slo_runtime import _require
from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import SAFE_ROUTE_NAMES

_MAX_CONCURRENCY = 64
_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS = 10.0


def _diagnostic_route_counters(counters: Counter[str]) -> dict[str, int]:
    """Bound route labels in diagnostic output without changing gate inputs."""

    normalized: Counter[str] = Counter()
    for route, count in counters.items():
        normalized[route if route in SAFE_ROUTE_NAMES else "unknown"] += count
    return dict(normalized)


def _load_executor_worker(barrier: threading.Barrier) -> int:
    barrier.wait()
    return threading.get_ident()


def _prime_load_executor(executor: ThreadPoolExecutor, concurrency: int) -> int:
    """Start every bounded load-generator thread before a measured wave."""

    _require(0 < concurrency <= _MAX_CONCURRENCY, "load executor concurrency exceeds benchmark limit")
    barrier = threading.Barrier(concurrency + 1, timeout=_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS)
    futures = [executor.submit(_load_executor_worker, barrier) for _ in range(concurrency)]
    try:
        barrier.wait()
        worker_ids = {future.result(timeout=_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS) for future in futures}
    except (threading.BrokenBarrierError, TimeoutError) as error:
        executor.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError("native_installed_slo_failed: load executor prewarm timed out") from error
    _require(len(worker_ids) == concurrency, "load executor did not reach configured concurrency")
    return len(worker_ids)


def _classify_native_overloads(
    observations: list[Observation],
    *,
    overload_delta: int,
    errors: int,
    before: Counter[str],
    after: Counter[str],
) -> list[Observation]:
    # A native overload event may already belong to an explicit response.
    # Generic 503 responses do not identify the counter source, so neither
    # reusing nor subtracting their count proves any additional overload.
    if any(observation.overloaded for observation in observations):
        return observations
    candidates = [
        index
        for index, observation in enumerate(observations)
        if observation.route == "native_fail_safe" and not observation.allowed
    ]
    if not candidates or overload_delta != len(candidates):
        return observations
    allowed = sum(item.allowed for item in observations)
    if allowed + len(candidates) != len(observations):
        return observations
    # The native counter increments once before a terminal fail-safe return.
    # Prove every denied candidate and every allowed response against the
    # complete quiet wave before assigning any inferred overload provenance.
    if not _wave_routes_match(
        observations,
        errors=errors,
        before=before,
        after=after,
        expected=Counter({"native_resident": allowed, "native_fail_safe": len(candidates)}),
    ):
        return observations
    return [replace(item, overloaded=True) if index in candidates else item for index, item in enumerate(observations)]


def _wave_routes_match(
    observations: list[Observation],
    *,
    errors: int,
    before: Counter[str],
    after: Counter[str],
    expected: Counter[str],
) -> bool:
    if errors or not observations or any(after[key] < before[key] for key in before):
        return False
    if any(observation.route not in {"native_resident", "native_fail_safe"} for observation in observations):
        return False
    return after - before == expected


def _reconcile_wave_routes(
    observations: list[Observation],
    *,
    errors: int,
    before: Counter[str],
    after: Counter[str],
) -> list[Observation]:
    """Prove mixed-wave provenance without attributing overlapping counters.

    This private session has no other hook callers during a capacity wave.
    Every proven, denied overload must have its own fail-safe counter, and
    every remaining response must be allowed and have its own resident counter.
    A missing/extra/reset counter or an unexplained denial leaves the original
    fail-closed observation unchanged. No overload is inferred here.
    """

    overloaded = [observation for observation in observations if observation.overloaded]
    resident = [observation for observation in observations if not observation.overloaded]
    if any(observation.allowed for observation in overloaded) or not all(item.allowed for item in resident):
        return observations
    expected = Counter({"native_resident": len(resident), "native_fail_safe": len(overloaded)})
    if not _wave_routes_match(observations, errors=errors, before=before, after=after, expected=expected):
        return observations
    return [replace(item, route="native_resident") if not item.overloaded else item for item in observations]
