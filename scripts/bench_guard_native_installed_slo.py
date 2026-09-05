#!/usr/bin/env python3
"""Measure installed adapter-to-decision native runtime SLOs.

Synthetic requests cross the daemon adapter boundary; output is aggregate-only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import replace
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

_PROBE_SPEC = importlib.util.spec_from_file_location(
    "hol_guard_installed_default_probe",
    _REPO_ROOT / "ci/native_runtime/probe_native_default_auto.py",
)
if _PROBE_SPEC is None or _PROBE_SPEC.loader is None:
    raise RuntimeError("native_installed_slo_failed: installed hook probe could not be loaded")
_PROBE_MODULE = importlib.util.module_from_spec(_PROBE_SPEC)
_PROBE_SPEC.loader.exec_module(_PROBE_MODULE)
_installed_hook_corpus = _PROBE_MODULE._installed_hook_corpus
from scripts.bench_guard_native_installed_slo_runtime import (  # noqa: E402
    _clear_proof_overrides,
    _readiness_samples,
    _require,
    _runtime_summary,
)
from scripts.native_slo_adapter import (  # noqa: E402
    Observation,
    payload,
    process_rss_bytes,
    route_matrix,
    source_payloads,
)
from scripts.native_slo_baseline import steady_state_rss_baseline as _steady_state_rss_baseline  # noqa: E402
from scripts.native_slo_contract import SIZE_CLASSES  # noqa: E402
from scripts.native_slo_reporting import (  # noqa: E402
    SloMeasurements,
    safe_failure_rate,
    slo_gates,
    slo_result,
    summarize_measurements,
)
from scripts.native_slo_session import AdapterSession, stop_native_resident  # noqa: E402

_DEFAULT_WARM_ITERATIONS = 2
_DEFAULT_COLD_ITERATIONS = 3
_DEFAULT_RECOVERY_ITERATIONS = 3
_MAX_READINESS_SAMPLES = 8
_MAX_CONCURRENCY = 64
# RSS includes this benchmark process as well as the daemon's descendants. Keep
# the bounded c64 load-generator workers alive across baseline and c64 stress so
# their thread allocation cannot be misclassified as resident runtime growth.
_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS = 10.0
# AdapterSession transport I/O is individually bounded at five seconds. Every
# worker is prestarted before a measured wave, and this one-second envelope lets
# those transport deadlines resolve before the executor-level no-hang bound.
_CONCURRENT_WAVE_TIMEOUT_SECONDS = 6.0
_HOOK_WORKER_STABILIZATION_TIMEOUT_SECONDS = 30.0
_INSTALLED_WHEEL_OWNERSHIP_CONTRACT = "installed_wheel_ownership_contract"

# Keep the historical private import available to contract tests and downstream tooling.
_safe_failure_rate = safe_failure_rate


def _installed_corpus(runtime: Path, expected_routes: int) -> dict[str, int]:
    """Exercise the canonical all-harness installed ingress corpus."""

    with tempfile.TemporaryDirectory(prefix="hol-guard-installed-corpus-") as temporary:
        root = Path(temporary)
        report: Mapping[str, object] | None = None
        try:
            candidate = _installed_hook_corpus(root)
            if isinstance(candidate, Mapping):
                report = candidate
        finally:
            stop_native_resident(runtime, root / "hook-home")
        if report is None:
            raise RuntimeError("native_installed_slo_failed: installed all-harness corpus returned no aggregate")
        values_by_name: dict[str, object] = {}
        for name in (
            "route_count",
            "native_resident_decisions",
            "native_oneshot_decisions",
            "fail_safe_decisions",
            "python_semantic_decisions",
        ):
            if name not in report:
                raise RuntimeError(f"native_installed_slo_failed: installed corpus omitted {name}")
            values_by_name[name] = report[name]
        route_count = values_by_name["route_count"]
        resident = values_by_name["native_resident_decisions"]
        oneshot = values_by_name["native_oneshot_decisions"]
        fail_safe = values_by_name["fail_safe_decisions"]
        python_semantic = values_by_name["python_semantic_decisions"]
        values = (route_count, resident, oneshot, fail_safe, python_semantic)
        if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values):
            raise RuntimeError("native_installed_slo_failed: installed corpus aggregate was invalid")
        route_count = cast(int, route_count)
        resident = cast(int, resident)
        oneshot = cast(int, oneshot)
        fail_safe = cast(int, fail_safe)
        python_semantic = cast(int, python_semantic)
        _require(route_count == expected_routes, "installed corpus did not cover every declared route")
        _require(resident == expected_routes, "installed corpus did not stay resident")
        _require(oneshot == 0 and fail_safe == 0 and python_semantic == 0, "installed corpus left the native route")
        return {
            "routes": route_count,
            "resident": resident,
            "oneshot": oneshot,
            "fail_safe": fail_safe,
            "python_semantic": python_semantic,
            "python_semantic_decisions": python_semantic,
        }


def _run_warm(session: AdapterSession, routes: tuple[tuple[str, str], ...], iterations: int) -> list[Observation]:
    for harness, event in routes:
        session.observe(harness, event, "1k")
    observations: list[Observation] = []
    for _ in range(iterations):
        observations.extend(session.observe(harness, event, "1k") for harness, event in routes)
    return observations


def _run_sizes(session: AdapterSession, routes: tuple[tuple[str, str], ...]) -> list[Observation]:
    post_routes = tuple((harness, event) for harness, event in routes if event == "PostToolUse")
    selected = post_routes or (routes[0],)
    large_payloads = source_payloads(session.workspace)
    observations: list[Observation] = []
    for size_class in SIZE_CLASSES[1:]:
        request_payload = large_payloads[size_class]
        observations.extend(session.observe(harness, event, size_class, request_payload) for harness, event in selected)
    return observations


def _wire_request(workspace: Path, guard_home: Path, request_id: str) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": payload("PostToolUse", "1k"),
            "guard_remaining_ms": 1_000,
            "cwd": str(workspace),
            "home_dir": str(workspace),
            "guard_home": str(guard_home),
            "source_ref_external_allowed": False,
            "observe_mode": False,
            "deadline_budget_ms": 5_000,
        },
        separators=(",", ":"),
    )


def _run_cold(runtime: Path, session: AdapterSession, iterations: int) -> list[float]:
    values: list[float] = []
    environment = {
        "HOME": str(session.workspace),
        "TMPDIR": tempfile.gettempdir(),
        **{key: value for key in ("LANG", "LC_ALL") if (value := os.environ.get(key))},
    }
    request = _wire_request(session.workspace, session.guard_home, "native-slo-cold")
    for _ in range(iterations):
        _require(session.stop_resident(), "cold native resident stop was not contained")
        started = time.perf_counter()
        completed = subprocess.run(
            (str(runtime), "hook", "--stdin"),
            input=request.encode("utf-8"),
            cwd=runtime.parent,
            env=environment,
            capture_output=True,
            check=False,
            timeout=5,
        )
        elapsed_ms = (time.perf_counter() - started) * 1_000.0
        _require(completed.returncode == 0, "cold native one-shot failed")
        try:
            response = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("cold native one-shot returned invalid JSON") from error
        _require(isinstance(response, Mapping) and response.get("decision") == "allow", "cold decision was unsafe")
        values.append(elapsed_ms)
    return values


def _run_recovery(session: AdapterSession, iterations: int) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        _ = session.observe("claude-code", "PostToolUse", "1k")
        _require(
            session.stop_resident(),
            f"resident stop failed during recovery sample {index}",
        )
        started = time.perf_counter()
        observation = session.observe("claude-code", "PostToolUse", "1k")
        values.append((time.perf_counter() - started) * 1_000.0)
        _require(observation.allowed and observation.route == "native_resident", f"recovery sample {index} failed")
    return values


def _load_executor_worker(barrier: threading.Barrier) -> int:
    barrier.wait()
    return threading.get_ident()


def _prime_load_executor(executor: ThreadPoolExecutor, concurrency: int) -> int:
    """Start every bounded load-generator thread before a measured wave."""

    _require(0 < concurrency <= _MAX_CONCURRENCY, "load executor concurrency exceeds benchmark limit")
    barrier = threading.Barrier(
        concurrency + 1,
        timeout=_LOAD_EXECUTOR_PREWARM_TIMEOUT_SECONDS,
    )
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
        # five-second I/O bound, so the six-second wave envelope should outlive
        # legitimate in-flight work. Fail closed without a blocking executor
        # shutdown if that contract is ever violated.
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
    # AdapterSession starts with a two-worker floor and defers backfill. Clear
    # that startup deferral, then request the normal target explicitly. The
    # bounded wait below proves that target is actually ready before measuring.
    runner.notify_queued_work()
    runner.enable_full_capacity(delay_seconds=0.0, active_deferral_seconds=0.0)
    initial = runner.stats()
    target = initial["target"]
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
    """Exercise ready workers; a wave timeout aborts the benchmark."""

    observations, errors = _run_concurrent(session, routes, concurrency, executor)
    stats = session.daemon._server.hook_process_runner.stats()
    _require(
        stats["target"] == concurrency
        and stats["workers"] == concurrency
        and stats["ready"] == concurrency
        and stats["busy"] == 0,
        "hook worker capacity was not steady after prewarm",
    )
    return observations, errors


def _classify_native_overloads(
    observations: list[Observation],
    *,
    overload_delta: int,
) -> list[Observation]:
    """Attach the native runtime's explicit overload count to fail-safe calls.

    The native client deliberately turns ``native_overloaded`` into a generic
    fail-safe hook response at the production adapter boundary.  The
    process-local health counter preserves that explicit capacity signal for
    this aggregate-only proof.  Require an exact one-to-one match; an
    unexplained fail-safe remains unclassified and fails the c64 gate.
    """

    candidates = [
        index
        for index, observation in enumerate(observations)
        if observation.route == "native_fail_safe" and not observation.overloaded
    ]
    if overload_delta != len(candidates):
        return observations
    for index in candidates:
        observations[index] = replace(observations[index], overloaded=True)
    return observations


def _measure_slo(
    runtime: Path,
    routes: tuple[tuple[str, str], ...],
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
) -> SloMeasurements:
    rss_baseline = 0
    rss_peak = 0
    concurrent_16: list[Observation] = []
    concurrent_64: list[Observation] = []
    errors_16 = 0
    errors_64 = 0
    # Cold probes stop the session's resident before each one-shot call. Keep
    # them in a separate session so this lifecycle exercise does not consume
    # the bounded restart budget used by warmup and recovery.
    with AdapterSession(runtime) as cold_session:
        cold = _run_cold(runtime, cold_session, cold_iterations)
    with AdapterSession(runtime) as session:
        warm = _run_warm(session, routes, warm_iterations)
        sizes = _run_sizes(session, routes)
        recovery = _run_recovery(session, recovery_iterations)
        warmup_harness, warmup_event = routes[0]
        serialized_warmup = session.observe(warmup_harness, warmup_event, "1k")
        _require(
            serialized_warmup.allowed and serialized_warmup.route == "native_resident",
            "serialized resident pool warmup did not stay on the allowed native route",
        )
        ready_workers = _stabilize_ready_hook_workers(session)

        # Keep the c16 latency proof faithful to production contention: it needs
        # only sixteen client workers. Prestart those exact workers so thread
        # creation is not charged to request latency and every transport timeout
        # begins well inside the executor-level no-hang envelope.
        if include_capacity:
            latency_executor = ThreadPoolExecutor(max_workers=16)
            try:
                _prime_load_executor(latency_executor, 16)
                native_overloads_before_16 = session.native_overload_count()
                concurrent_16, errors_16 = _run_concurrent(session, routes, 16, latency_executor)
                native_overloads_after_16 = session.native_overload_count()
            except BaseException:
                latency_executor.shutdown(wait=False, cancel_futures=True)
                raise
            else:
                latency_executor.shutdown(wait=True)
            concurrent_16 = _classify_native_overloads(
                concurrent_16,
                overload_delta=native_overloads_after_16 - native_overloads_before_16,
            )

        # RSS is a separate steady-state proof. Prime the c64 load generator
        # before the RSS baseline, then keep exactly that allocation alive for
        # the c64 wave so benchmark-side thread stacks cannot appear as runtime
        # growth. The preceding c16 proof is folded into steady state instead of
        # trading latency validity for RSS accounting.
        load_concurrency = _MAX_CONCURRENCY if include_capacity else ready_workers
        load_executor = ThreadPoolExecutor(max_workers=load_concurrency)
        try:
            _prime_load_executor(load_executor, load_concurrency)
            rss_baseline = _steady_state_rss_baseline(
                lambda: _prewarm_ready_hook_workers(
                    session,
                    routes,
                    ready_workers,
                    load_executor,
                ),
                sample_capacity=session.daemon._server.hook_process_runner.stats,
                expected_warmup_count=ready_workers,
            )
            rss_peak = rss_baseline
            native_overloads_before_64 = session.native_overload_count()
            if include_capacity:
                concurrent_64, errors_64 = _run_concurrent(session, routes, 64, load_executor)
            native_overloads_after_64 = session.native_overload_count()
            if include_capacity:
                concurrent_64 = _classify_native_overloads(
                    concurrent_64,
                    overload_delta=native_overloads_after_64 - native_overloads_before_64,
                )
            # The post-stress sample keeps daemon/runtime growth in the comparison
            # while the same bounded c64 load-generator allocation stays in baseline.
            rss_peak = max(rss_peak, process_rss_bytes())
        except BaseException:
            load_executor.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            load_executor.shutdown(wait=True)
        readiness = [session.readiness_ms]
    if readiness_samples > 1:
        readiness.extend(_readiness_samples(runtime, readiness_samples - 1))
    rss_peak = max(rss_peak, process_rss_bytes())
    return SloMeasurements(
        warm=warm,
        sizes=sizes,
        recovery=recovery,
        cold=cold,
        concurrent_16=concurrent_16,
        concurrent_64=concurrent_64,
        errors_16=errors_16,
        errors_64=errors_64,
        readiness=readiness,
        rss_baseline=rss_baseline,
        rss_peak=rss_peak,
    )


def run_slo(
    runtime: Path,
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
) -> dict[str, object]:
    _clear_proof_overrides()
    runtime_summary = _runtime_summary(runtime)
    routes = route_matrix()
    installed_corpus = _installed_corpus(runtime, len(routes))
    measurements = _measure_slo(
        runtime,
        routes,
        warm_iterations=warm_iterations,
        cold_iterations=cold_iterations,
        recovery_iterations=recovery_iterations,
        readiness_samples=readiness_samples,
        include_capacity=include_capacity,
    )
    summary = summarize_measurements(measurements)
    gates = slo_gates(
        measurements,
        summary,
        installed_corpus,
        len(routes),
        include_capacity=include_capacity,
    )
    return slo_result(
        runtime_summary,
        routes,
        installed_corpus,
        measurements,
        summary,
        gates,
        corpus_origin=_INSTALLED_WHEEL_OWNERSHIP_CONTRACT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--warm-iterations", type=int, default=_DEFAULT_WARM_ITERATIONS)
    parser.add_argument("--cold-iterations", type=int, default=_DEFAULT_COLD_ITERATIONS)
    parser.add_argument("--recovery-iterations", type=int, default=_DEFAULT_RECOVERY_ITERATIONS)
    parser.add_argument("--readiness-samples", type=int, default=3)
    parser.add_argument("--skip-capacity", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.warm_iterations <= 0 or args.cold_iterations <= 0 or args.recovery_iterations <= 0:
        parser.error("iteration counts must be positive")
    if not 1 <= args.readiness_samples <= _MAX_READINESS_SAMPLES:
        parser.error("readiness samples must be between one and eight")
    runtime = args.runtime.expanduser().resolve(strict=True)
    _require(runtime.is_file() and not args.runtime.is_symlink(), "runtime must be a regular non-symlink file")
    result = run_slo(
        runtime,
        warm_iterations=args.warm_iterations,
        cold_iterations=args.cold_iterations,
        recovery_iterations=args.recovery_iterations,
        readiness_samples=args.readiness_samples,
        include_capacity=not args.skip_capacity,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.enforce or result.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
