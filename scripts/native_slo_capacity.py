"""Installed native-runtime concurrency and resident RSS measurements."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, replace

from scripts.bench_guard_native_installed_slo_runtime import _require
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import Observation, process_rss_bytes, route_counts
from scripts.native_slo_baseline import steady_state_rss_baseline as _steady_state_rss_baseline
from scripts.native_slo_batch import validate_batch_routes
from scripts.native_slo_capacity_diagnostic import CapacityDiagnostics
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_observation_failure import contextual_failure
from scripts.native_slo_session import AdapterSession

_MAX_CONCURRENCY = 64
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
    routes_16: dict[str, int]
    routes_64: dict[str, int]
    native_overloads_16: int
    native_overloads_64: int


@dataclass(frozen=True)
class CapacityWave:
    observations: list[Observation]
    errors: int
    routes: dict[str, int]
    native_overloads: int


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
    failures: list[dict[str, object]] | None = None,
    diagnostics: CapacityDiagnostics | None = None,
) -> tuple[list[Observation], int]:
    selected = tuple(routes[index % len(routes)] for index in range(concurrency))
    observations: list[Observation] = []
    errors = 0
    _require(0 < concurrency <= _MAX_CONCURRENCY, "concurrency exceeds bounded benchmark limit")

    def observe(harness: str, event: str) -> Observation:
        def operation() -> Observation:
            return session.observe(harness, event, "1k")

        return operation() if diagnostics is None else diagnostics.observe(operation)

    futures = [executor.submit(observe, harness, event) for harness, event in selected]
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
        except Exception as error:
            errors += 1
            if failures is not None and len(failures) < 4:
                failures.append(failure_evidence(error))
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
    wave = _run_capacity_wave(session, routes, concurrency, executor)
    stats = session.daemon._server.hook_process_runner.stats()
    _require(
        stats["target"] == concurrency
        and stats["workers"] == concurrency
        and stats["ready"] == concurrency
        and stats["busy"] == 0,
        "hook worker capacity was not steady after prewarm",
    )
    _require(not any(item.overloaded for item in wave.observations), "resident prewarm returned overload")
    return wave.observations, wave.errors


def _classify_native_overloads(
    observations: list[Observation],
    *,
    overload_delta: int,
    native_fail_safe_delta: int,
) -> list[Observation]:
    """Recognize denied native overloads only from exact whole-wave evidence.

    Overlapping per-hook counter spans cannot identify any individual route.
    A native health increment accounts for one native fail-safe; explicit
    capacity responses may also have bypassed the engine. Matching the complete
    native fail-safe count rules out borrowing an overload increment to hide an
    unrelated native failure. Batch conservation separately checks every allow.
    """
    candidates = [
        index
        for index, observation in enumerate(observations)
        if not observation.allowed and not observation.overloaded
    ]
    # Explicit responses may include native overloads as well as daemon
    # admission bypasses. Without an individual native witness, their health
    # increments cannot be borrowed to classify another unknown denial.
    explicit = sum(item.overloaded for item in observations)
    if not candidates:
        return observations
    if explicit or overload_delta != native_fail_safe_delta or overload_delta != len(candidates):
        return observations
    return [replace(item, overloaded=True) if index in candidates else item for index, item in enumerate(observations)]


def _run_capacity_wave(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
) -> CapacityWave:
    """Conserve one isolated completed wave before attributing successful routes."""
    metrics = session.daemon._server.hook_worker.metrics
    initial = metrics.snapshot()
    initial_routes = initial.get("routes") if isinstance(initial, Mapping) else None
    _require(
        isinstance(initial_routes, Mapping)
        and all(isinstance(name, str) and type(value) is int and value >= 0 for name, value in initial_routes.items()),
        "concurrent capacity route counters were invalid",
    )
    before = route_counts(initial)
    overloads_before = session.native_overload_count()
    failures: list[dict[str, object]] = []
    diagnostics = CapacityDiagnostics(session.daemon._server.hook_worker, concurrency)
    try:
        with diagnostics.capture_native():
            observations, errors = _run_concurrent(session, routes, concurrency, executor, failures, diagnostics)
    except Exception as error:
        raise contextual_failure(error, capacity_diagnostic=diagnostics.report()) from error
    overloads_after = session.native_overload_count()
    _require(
        type(overloads_before) is int and type(overloads_after) is int and overloads_before >= 0,
        "native overload counters were invalid",
    )
    overload_delta = overloads_after - overloads_before
    _require(
        type(overload_delta) is int and 0 <= overload_delta <= len(observations),
        "native overload counters were invalid",
    )
    _require(
        type(errors) is int and errors >= 0 and len(observations) + errors == concurrency,
        "concurrent capacity wave accounting was incomplete",
    )
    _require(
        not any(item.allowed and item.overloaded for item in observations),
        "concurrent capacity response was both allowed and overloaded",
    )
    expected = sum(before.values()) + sum(item.allowed for item in observations) + overload_delta
    after = route_counts(wait_for_route_corpus(metrics, expected=max(1, expected)))
    observations = _classify_native_overloads(
        observations,
        overload_delta=overload_delta,
        native_fail_safe_delta=after.get("native_fail_safe", 0) - before.get("native_fail_safe", 0),
    )
    try:
        attributed, witnessed = validate_batch_routes(observations, before, after)
        _require(overload_delta == witnessed.get("native_fail_safe", 0), "native overload route evidence did not match")
    except RuntimeError as error:
        raise contextual_failure(
            error,
            concurrency=concurrency,
            routes_before=dict(before),
            routes_after=dict(after),
            delivered_count=len(observations),
            delivered_allowed=sum(item.allowed for item in observations),
            delivered_overloaded=sum(item.overloaded for item in observations),
            transport_errors=errors,
            transport_failures=failures,
            native_overloads_before=overloads_before,
            native_overloads_after=overloads_after,
            capacity_diagnostic=diagnostics.report(),
        ) from error
    return CapacityWave(attributed, errors, witnessed, overload_delta)


def _measure_c16(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    include_capacity: bool,
) -> CapacityWave:
    if not include_capacity:
        return CapacityWave([], 0, {}, 0)
    executor = ThreadPoolExecutor(max_workers=16)
    try:
        _prime_load_executor(executor, 16)
        wave = _run_capacity_wave(session, routes, 16, executor)
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return wave


def _measure_rss_and_c64(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    ready_workers: int,
    *,
    include_capacity: bool,
) -> tuple[int, int, CapacityWave]:
    load_concurrency = _MAX_CONCURRENCY if include_capacity else ready_workers
    wave = CapacityWave([], 0, {}, 0)
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
            wave = _run_capacity_wave(session, routes, _MAX_CONCURRENCY, executor)
        rss_peak = max(rss_peak, process_rss_bytes())
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return rss_baseline, rss_peak, wave


def measure_capacity(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    include_capacity: bool,
) -> CapacityMeasurements:
    ready_workers = _stabilize_ready_hook_workers(session)
    wave_16 = _measure_c16(session, routes, include_capacity=include_capacity)
    rss_baseline, rss_peak, wave_64 = _measure_rss_and_c64(
        session,
        routes,
        ready_workers,
        include_capacity=include_capacity,
    )
    return CapacityMeasurements(
        concurrent_16=wave_16.observations,
        concurrent_64=wave_64.observations,
        errors_16=wave_16.errors,
        errors_64=wave_64.errors,
        rss_baseline=rss_baseline,
        rss_peak=rss_peak,
        routes_16=wave_16.routes,
        routes_64=wave_64.routes,
        native_overloads_16=wave_16.native_overloads,
        native_overloads_64=wave_64.native_overloads,
    )
