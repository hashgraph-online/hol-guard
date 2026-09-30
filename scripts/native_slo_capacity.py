"""Installed native-runtime concurrency and resident RSS measurements."""

from __future__ import annotations

import json
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, replace

from scripts.bench_guard_native_installed_slo_runtime import _require
from scripts.native_slo_adapter import Observation, process_rss_bytes, route_counts
from scripts.native_slo_baseline import steady_state_rss_baseline as _steady_state_rss_baseline
from scripts.native_slo_session import AdapterSession

_MAX_CONCURRENCY = 64
_STEADY_STATE_CONCURRENCY = 16
_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS = 10.0
# AdapterSession transport I/O is individually bounded at five seconds. Every
# worker is prestarted before a measured wave, and this one-second envelope lets
# those transport deadlines resolve before the executor-level no-hang bound.
_CONCURRENT_WAVE_TIMEOUT_SECONDS = 6.0
_HOOK_WORKER_STABILIZATION_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class CapacityMeasurements:
    concurrent_16: list[Observation]
    concurrent_64: list[Observation]
    errors_16: int
    errors_64: int
    rss_baseline: int
    rss_peak: int


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


def _run_concurrent(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
) -> tuple[list[Observation], int]:
    selected = tuple(routes[index % len(routes)] for index in range(concurrency))
    observations: list[Observation] = []
    errors = 0
    _require(0 < concurrency <= _MAX_CONCURRENCY, "concurrency exceeds bounded benchmark limit")
    futures = [executor.submit(session.observe, harness, event, "1k") for harness, event in selected]
    _, unfinished = wait(futures, timeout=_CONCURRENT_WAVE_TIMEOUT_SECONDS)
    if unfinished:
        # Every worker is prestarted and AdapterSession transport calls have a
        # five-second I/O bound. Fail closed without blocking executor teardown
        # if a request ever escapes that transport contract.
        for future in unfinished:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError("native_installed_slo_failed: concurrent capacity wave timed out")
    for future in futures:
        try:
            observations.append(future.result())
        except Exception:
            errors += 1
    return observations, errors


def _stabilize_ready_hook_workers(session: AdapterSession) -> int:
    """Bring every configured steady-state hook worker to ready before RSS sampling."""

    runner = session.daemon._server.hook_process_runner
    runner.notify_queued_work()
    runner.enable_full_capacity(delay_seconds=0.0, active_deferral_seconds=0.0)
    target = runner.stats()["target"]
    _require(
        isinstance(target, int) and not isinstance(target, bool) and 1 <= target <= _MAX_CONCURRENCY,
        "hook worker stabilization target was invalid",
    )
    _require(
        runner.wait_for_capacity(
            minimum_workers=target,
            timeout_seconds=_HOOK_WORKER_STABILIZATION_TIMEOUT_SECONDS,
        ),
        "hook worker stabilization did not reach the configured target",
    )
    stabilized = runner.stats()
    _require(
        stabilized["target"] == target
        and stabilized["workers"] == target
        and stabilized["ready"] == target
        and stabilized["busy"] == 0,
        "hook worker capacity changed while stabilizing",
    )
    return target


def _prewarm_ready_hook_workers(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
) -> tuple[list[Observation], int]:
    observations, errors = _run_concurrent(session, routes, concurrency, executor)
    _require_ready_hook_workers(session, concurrency)
    return observations, errors


def _require_ready_hook_workers(session: AdapterSession, ready_workers: int) -> None:
    stats = session.daemon._server.hook_process_runner.stats()
    _require(
        stats["target"] == ready_workers
        and stats["workers"] == ready_workers
        and stats["ready"] == ready_workers
        and stats["busy"] == 0,
        "hook worker capacity was not steady after prewarm",
    )


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


def _measure_classified_wave(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
) -> tuple[list[Observation], int]:
    metrics = session.daemon._server.hook_worker.metrics
    before = route_counts(metrics.snapshot())
    overloads_before = session.native_overload_count()
    observations, errors = _run_concurrent(session, routes, concurrency, executor)
    overloads_after = session.native_overload_count()
    after = route_counts(metrics.snapshot())
    original_routes = Counter(item.route for item in observations)
    explicit_overloads = sum(item.overloaded for item in observations)
    observations = _classify_native_overloads(
        observations,
        overload_delta=overloads_after - overloads_before,
        errors=errors,
        before=before,
        after=after,
    )
    observations = _reconcile_wave_routes(observations, errors=errors, before=before, after=after)
    # Aggregate-only evidence explains failed capacity gates without exposing
    # response bodies, workspace paths, credentials or request content.
    print(
        json.dumps(
            {
                "schema": "hol-guard.native-capacity-wave.v1",
                "concurrency": concurrency,
                "errors": errors,
                "route_counters_before": dict(before),
                "route_counters_after": dict(after),
                "native_overloads_before": overloads_before,
                "native_overloads_after": overloads_after,
                "observed_routes": dict(original_routes),
                "reconciled_routes": dict(Counter(item.route for item in observations)),
                "allowed_responses": sum(item.allowed for item in observations),
                "explicit_overload_responses": explicit_overloads,
                "classified_overload_responses": sum(item.overloaded for item in observations),
            },
            sort_keys=True,
        ),
        file=sys.stderr,
        flush=True,
    )
    return observations, errors


def _measure_c16(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    include_capacity: bool,
) -> tuple[list[Observation], int]:
    if not include_capacity:
        return [], 0
    executor = ThreadPoolExecutor(max_workers=_STEADY_STATE_CONCURRENCY)
    try:
        _prime_load_executor(executor, _STEADY_STATE_CONCURRENCY)
        observations, errors = _measure_classified_wave(session, routes, _STEADY_STATE_CONCURRENCY, executor)
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return observations, errors


def _prewarm_capacity_workers(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    ready_workers: int,
) -> None:
    """Initialize the measured native client concurrency before capacity timing."""

    # Native requests use their own lazy stream pool in the daemon, rather than
    # the isolated Python hook workers. Warm the measured native concurrency;
    # the Python worker target can remain two even when sixteen clients run.
    executor = ThreadPoolExecutor(max_workers=_STEADY_STATE_CONCURRENCY)
    try:
        _prime_load_executor(executor, _STEADY_STATE_CONCURRENCY)
        observations, errors = _run_concurrent(session, routes, _STEADY_STATE_CONCURRENCY, executor)
        _require(
            errors == 0 and len(observations) == _STEADY_STATE_CONCURRENCY,
            "native client capacity prewarm did not complete every request",
        )
        _require(
            all(item.allowed and item.route == "native_resident" and not item.overloaded for item in observations),
            "native client capacity prewarm did not complete native review",
        )
        _require_ready_hook_workers(session, ready_workers)
        print(
            json.dumps(
                {
                    "schema": "hol-guard.native-capacity-prewarm.v1",
                    "concurrency": _STEADY_STATE_CONCURRENCY,
                    "python_worker_target": ready_workers,
                    "responses": len(observations),
                    "errors": errors,
                    "native_resident_responses": sum(item.route == "native_resident" for item in observations),
                    "max_latency_ms": round(max(item.latency_ms for item in observations), 3),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)


def _measure_rss_and_c64(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    ready_workers: int,
    *,
    include_capacity: bool,
) -> tuple[int, int, list[Observation], int]:
    load_concurrency = _MAX_CONCURRENCY if include_capacity else ready_workers
    observations: list[Observation] = []
    errors = 0
    executor = ThreadPoolExecutor(max_workers=load_concurrency)
    try:
        _prime_load_executor(executor, load_concurrency)
        rss_baseline = _steady_state_rss_baseline(
            lambda: _prewarm_ready_hook_workers(session, routes, ready_workers, executor),
            sample_capacity=session.daemon._server.hook_process_runner.stats,
            expected_warmup_count=ready_workers,
        )
        rss_peak = rss_baseline
        if include_capacity:
            observations, errors = _measure_classified_wave(session, routes, _MAX_CONCURRENCY, executor)
        rss_peak = max(rss_peak, process_rss_bytes())
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return rss_baseline, rss_peak, observations, errors


def measure_capacity(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    include_capacity: bool,
) -> CapacityMeasurements:
    ready_workers = _stabilize_ready_hook_workers(session)
    if include_capacity:
        # Serialized warmup has not exercised the concurrent native transports,
        # so initialize them before measuring steady-state capacity.
        # Cold and recovery latency remain separate measurements; the 16-client sample still precedes
        # the larger 64-client overload wave.
        _prewarm_capacity_workers(session, routes, ready_workers)
    concurrent_16, errors_16 = _measure_c16(session, routes, include_capacity=include_capacity)
    rss_baseline, rss_peak, concurrent_64, errors_64 = _measure_rss_and_c64(
        session,
        routes,
        ready_workers,
        include_capacity=include_capacity,
    )
    return CapacityMeasurements(
        concurrent_16=concurrent_16,
        concurrent_64=concurrent_64,
        errors_16=errors_16,
        errors_64=errors_64,
        rss_baseline=rss_baseline,
        rss_peak=rss_peak,
    )
