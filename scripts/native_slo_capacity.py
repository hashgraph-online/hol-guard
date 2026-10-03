"""Installed native-runtime concurrency and resident RSS measurements."""

from __future__ import annotations

import json
import sys
from collections import Counter
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from contextlib import nullcontext
from dataclasses import dataclass
from typing import TypedDict

from scripts.bench_guard_native_installed_slo_runtime import _require
from scripts.native_slo_adapter import Observation, process_rss_bytes, route_counts
from scripts.native_slo_baseline import steady_state_rss_baseline as _steady_state_rss_baseline
from scripts.native_slo_capacity_support import (
    _classify_native_overloads,
    _diagnostic_route_counters,
    _prime_load_executor,
    _reconcile_wave_routes,
)
from scripts.native_slo_contract import SAFE_FAILURE_STAGE_NAMES
from scripts.native_slo_failure_details import failure_details, summarize_request_failures
from scripts.native_slo_preflight import preflight_operation
from scripts.native_slo_progress import SloProgress
from scripts.native_slo_session import AdapterSession

_MAX_CONCURRENCY = 64
_STEADY_STATE_CONCURRENCY = 16
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


ObserveCallback = Callable[[str, str, str, str], Observation]
ProgressCountCallback = Callable[[str, int], None]
TransportObservationCallback = Callable[[list[Observation]], None]


class ObserverOptions(TypedDict, total=False):
    observer: ObserveCallback | None
    on_submitted: ProgressCountCallback
    on_cancelled: ProgressCountCallback


class ConcurrentWaveOptions(ObserverOptions, total=False):
    stage: str
    on_transport_observations: TransportObservationCallback


def _run_concurrent(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
    *,
    observer: ObserveCallback | None = None,
    stage: str = "concurrent",
    on_submitted: ProgressCountCallback | None = None,
    on_cancelled: ProgressCountCallback | None = None,
    on_transport_observations: TransportObservationCallback | None = None,
) -> tuple[list[Observation], int]:
    selected = tuple(routes[index % len(routes)] for index in range(concurrency))
    observations: list[Observation] = []
    errors = 0
    _require(0 < concurrency <= _MAX_CONCURRENCY, "concurrency exceeds bounded benchmark limit")

    def observe(harness: str, event: str) -> Observation:
        if observer is None:
            return session.observe(harness, event, "1k")
        return observer(harness, event, "1k", stage)

    futures = [executor.submit(observe, harness, event) for harness, event in selected]
    if on_submitted is not None:
        on_submitted(stage, len(futures))
    finished, unfinished = wait(futures, timeout=_CONCURRENT_WAVE_TIMEOUT_SECONDS)
    if unfinished:
        # Every worker is prestarted and AdapterSession transport calls have a
        # five-second I/O bound. Fail closed without blocking executor teardown
        # if a request ever escapes that transport contract.
        cancelled = sum(future.cancel() for future in unfinished)
        if cancelled and on_cancelled is not None:
            on_cancelled(stage, cancelled)
        if on_transport_observations is not None:

            def record_late(future: Future[Observation]) -> None:
                if future.cancelled():
                    return
                try:
                    observation = future.result()
                except Exception:
                    return
                on_transport_observations([observation])

            for future in unfinished:
                if not future.cancelled():
                    future.add_done_callback(record_late)
            finished_observations: list[Observation] = []
            for future in finished:
                if future.cancelled():
                    continue
                try:
                    finished_observations.append(future.result())
                except Exception:
                    continue
            if finished_observations:
                on_transport_observations(finished_observations)
        executor.shutdown(wait=False, cancel_futures=True)
        raise RuntimeError("native_installed_slo_failed: concurrent capacity wave timed out")
    failures: list[dict[str, str]] = []
    for future in futures:
        try:
            observations.append(future.result())
        except Exception as error:
            errors += 1
            failures.append(failure_details(error))
    if failures:
        # Preserve the individual failure classes before the caller enforces its
        # aggregate completeness gate. Do not infer retryability or change counts.
        print(
            json.dumps(
                {
                    "schema": "hol-guard.native-capacity-request-failures.v1",
                    "stage": stage if stage in SAFE_FAILURE_STAGE_NAMES else "unknown",
                    "submitted": len(futures),
                    "responses": len(observations),
                    "errors": errors,
                    **summarize_request_failures(failures),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
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
    *,
    observer: ObserveCallback | None = None,
    on_submitted: ProgressCountCallback | None = None,
    on_cancelled: ProgressCountCallback | None = None,
) -> tuple[list[Observation], int]:
    kwargs: ConcurrentWaveOptions = {}
    if observer is not None:
        kwargs.update(observer=observer, stage="rss_baseline_requests")
    if on_submitted is not None:
        kwargs["on_submitted"] = on_submitted
    if on_cancelled is not None:
        kwargs["on_cancelled"] = on_cancelled
    observations, errors = _run_concurrent(session, routes, concurrency, executor, **kwargs)
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


def _measure_classified_wave(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
    executor: ThreadPoolExecutor,
    *,
    observer: ObserveCallback | None = None,
    stage: str = "concurrent",
    on_submitted: ProgressCountCallback | None = None,
    on_cancelled: ProgressCountCallback | None = None,
    on_transport_observations: TransportObservationCallback | None = None,
) -> tuple[list[Observation], int]:
    metrics = session.daemon._server.hook_worker.metrics
    before = route_counts(metrics.snapshot())
    overloads_before = session.native_overload_count()
    wave_kwargs: ConcurrentWaveOptions = {}
    if observer is not None:
        wave_kwargs.update(observer=observer, stage=stage)
    if on_submitted is not None:
        wave_kwargs["on_submitted"] = on_submitted
    if on_cancelled is not None:
        wave_kwargs["on_cancelled"] = on_cancelled
    if on_transport_observations is not None:
        wave_kwargs["on_transport_observations"] = on_transport_observations
    observations, errors = _run_concurrent(session, routes, concurrency, executor, **wave_kwargs)
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
                "route_counters_before": _diagnostic_route_counters(before),
                "route_counters_after": _diagnostic_route_counters(after),
                "native_overloads_before": overloads_before,
                "native_overloads_after": overloads_after,
                "observed_routes": _diagnostic_route_counters(original_routes),
                "reconciled_routes": _diagnostic_route_counters(Counter(item.route for item in observations)),
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
    observer: ObserveCallback | None = None,
    on_submitted: ProgressCountCallback | None = None,
    on_cancelled: ProgressCountCallback | None = None,
    progress: SloProgress | None = None,
) -> tuple[list[Observation], int]:
    if not include_capacity:
        return [], 0
    executor = ThreadPoolExecutor(max_workers=_STEADY_STATE_CONCURRENCY)
    try:
        _prime_load_executor(executor, _STEADY_STATE_CONCURRENCY)
        observations, errors = _measure_classified_wave(
            session,
            routes,
            _STEADY_STATE_CONCURRENCY,
            executor,
            observer=observer,
            stage="concurrent_16",
            on_submitted=on_submitted,
            on_cancelled=on_cancelled,
        )
    except BaseException as error:
        if progress is not None:
            progress.record_failure(error, stage="concurrent_16", labels={"wave": "sixteen"})
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)
    return observations, errors


def _prewarm_capacity_workers(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    ready_workers: int,
    *,
    observer: ObserveCallback | None = None,
    on_submitted: ProgressCountCallback | None = None,
    on_cancelled: ProgressCountCallback | None = None,
    on_deferred_complete: ProgressCountCallback | None = None,
    on_deferred_failure: ProgressCountCallback | None = None,
    progress: SloProgress | None = None,
) -> None:
    """Initialize the measured native client concurrency before capacity timing."""

    # Native requests use their own lazy stream pool in the daemon, rather than
    # the isolated Python hook workers. Warm the measured native concurrency;
    # the Python worker target can remain two even when sixteen clients run.
    executor = ThreadPoolExecutor(max_workers=_STEADY_STATE_CONCURRENCY)

    def record_deferred(observations: list[Observation]) -> None:
        failed = sum(
            not (item.allowed and item.route == "native_resident" and not item.overloaded) for item in observations
        )
        if on_deferred_failure is not None and failed:
            on_deferred_failure("capacity_prewarm", failed)
        if on_deferred_complete is not None and len(observations) - failed:
            on_deferred_complete("capacity_prewarm", len(observations) - failed)

    try:
        _prime_load_executor(executor, _STEADY_STATE_CONCURRENCY)
        wave_kwargs: ConcurrentWaveOptions = {}
        if observer is not None:
            wave_kwargs.update(observer=observer, stage="capacity_prewarm")
        if on_submitted is not None:
            wave_kwargs["on_submitted"] = on_submitted
        if on_cancelled is not None:
            wave_kwargs["on_cancelled"] = on_cancelled
        if on_deferred_complete is not None or on_deferred_failure is not None:
            wave_kwargs["on_transport_observations"] = record_deferred
        observations, errors = _run_concurrent(
            session,
            routes,
            _STEADY_STATE_CONCURRENCY,
            executor,
            **wave_kwargs,
        )
        try:
            _require(
                errors == 0 and len(observations) == _STEADY_STATE_CONCURRENCY,
                "native client capacity prewarm did not complete every request",
            )
            _require(
                all(item.allowed and item.route == "native_resident" and not item.overloaded for item in observations),
                "native client capacity prewarm did not complete native review",
            )
        except BaseException:
            if on_deferred_complete is not None or on_deferred_failure is not None:
                record_deferred(observations)
            raise
        if on_deferred_complete is not None:
            on_deferred_complete("capacity_prewarm", len(observations))
        with preflight_operation(progress, "capacity_prewarm_ready") if progress is not None else nullcontext():
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
    except BaseException as error:
        if progress is not None:
            progress.record_failure(error, stage="capacity_prewarm", labels={"wave": "prewarm"})
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
    observer: ObserveCallback | None = None,
    on_submitted: ProgressCountCallback | None = None,
    on_cancelled: ProgressCountCallback | None = None,
    progress: SloProgress | None = None,
) -> tuple[int, int, list[Observation], int]:
    load_concurrency = _MAX_CONCURRENCY if include_capacity else ready_workers
    observations: list[Observation] = []
    errors = 0
    executor: ThreadPoolExecutor | None = None
    baseline_completed = False
    failure_stage = "rss_baseline"
    if progress is not None:
        progress.activate("rss_baseline")
        progress.submit("rss_baseline")
        progress.attempt("rss_baseline")
    try:
        executor = ThreadPoolExecutor(max_workers=load_concurrency)
        _prime_load_executor(executor, load_concurrency)
        baseline_kwargs: ObserverOptions = {}
        if progress is not None:
            baseline_kwargs.update(
                observer=observer,
                on_submitted=progress.submit,
                on_cancelled=progress.cancel,
            )
        rss_baseline = _steady_state_rss_baseline(
            lambda: _prewarm_ready_hook_workers(session, routes, ready_workers, executor, **baseline_kwargs),
            sample_capacity=session.daemon._server.hook_process_runner.stats,
            expected_warmup_count=ready_workers,
        )
        baseline_completed = True
        if progress is not None:
            progress.complete("rss_baseline")
            # Restore the enclosing stage after baseline request observations.
            progress.activate("rss_baseline")
        rss_peak = rss_baseline
        if include_capacity:
            failure_stage = "concurrent_64"
            observations, errors = _measure_classified_wave(
                session,
                routes,
                _MAX_CONCURRENCY,
                executor,
                observer=observer,
                stage="concurrent_64",
                on_submitted=on_submitted,
                on_cancelled=on_cancelled,
            )
        failure_stage = "rss_peak"
        rss_peak = max(rss_peak, process_rss_bytes())
    except BaseException as error:
        if progress is not None and not baseline_completed:
            progress.fail_request("rss_baseline")
        if progress is not None:
            progress.record_failure(
                error,
                stage=failure_stage,
                labels={"wave": "sixty_four"} if failure_stage == "concurrent_64" else {},
            )
        if executor is not None:
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
    observer: ObserveCallback | None = None,
    on_submitted: ProgressCountCallback | None = None,
    on_cancelled: ProgressCountCallback | None = None,
    on_deferred_complete: ProgressCountCallback | None = None,
    on_deferred_failure: ProgressCountCallback | None = None,
    progress: SloProgress | None = None,
) -> CapacityMeasurements:
    with preflight_operation(progress, "capacity_stabilization") if progress is not None else nullcontext():
        ready_workers = _stabilize_ready_hook_workers(session)
    if include_capacity:
        # Serialized warmup has not exercised the concurrent native transports,
        # so initialize them before measuring steady-state capacity.
        # Cold and recovery latency remain separate measurements; the 16-client sample still precedes
        # the larger 64-client overload wave.
        _prewarm_capacity_workers(
            session,
            routes,
            ready_workers,
            observer=observer,
            on_submitted=on_submitted,
            on_cancelled=on_cancelled,
            on_deferred_complete=on_deferred_complete,
            on_deferred_failure=on_deferred_failure,
            progress=progress,
        )
    concurrent_16, errors_16 = _measure_c16(
        session,
        routes,
        include_capacity=include_capacity,
        observer=observer,
        on_submitted=on_submitted,
        on_cancelled=on_cancelled,
        progress=progress,
    )
    rss_baseline, rss_peak, concurrent_64, errors_64 = _measure_rss_and_c64(
        session,
        routes,
        ready_workers,
        include_capacity=include_capacity,
        observer=observer,
        on_submitted=on_submitted,
        on_cancelled=on_cancelled,
        progress=progress,
    )
    return CapacityMeasurements(
        concurrent_16=concurrent_16,
        concurrent_64=concurrent_64,
        errors_16=errors_16,
        errors_64=errors_64,
        rss_baseline=rss_baseline,
        rss_peak=rss_peak,
    )
