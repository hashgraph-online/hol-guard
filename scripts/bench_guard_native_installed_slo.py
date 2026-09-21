#!/usr/bin/env python3
"""Measure daemon ingress and registered installed-launcher native SLOs.

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
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

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
from scripts.native_slo_baseline import (  # noqa: E402, F401
    steady_state_rss_baseline as _steady_state_rss_baseline,
)
from scripts.native_slo_capacity import (  # noqa: E402, F401
    _stabilize_ready_hook_workers,
    measure_capacity,
)
from scripts.native_slo_contract import SIZE_CLASSES, assert_privacy_safe  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_launcher import measure_registered_launcher  # noqa: E402
from scripts.native_slo_observation_failure import (  # noqa: E402
    SloProgress,
    capture_recovery_observation,
    contextual_failure,
)
from scripts.native_slo_reporting import (  # noqa: E402
    SloMeasurements,
    safe_failure_rate,
    slo_gates,
    slo_result,
    summarize_measurements,
)
from scripts.native_slo_session import AdapterSession, stop_native_resident  # noqa: E402
from scripts.native_slo_workloads import source_reference_supported  # noqa: E402

_DEFAULT_WARM_ITERATIONS = 2
_DEFAULT_COLD_ITERATIONS = 3
_DEFAULT_RECOVERY_ITERATIONS = 3
_MAX_READINESS_SAMPLES = 8
_INSTALLED_WHEEL_OWNERSHIP_CONTRACT = "installed_wheel_ownership_contract"

# Keep historical private imports available to contract tests and downstream tooling.
_safe_failure_rate = safe_failure_rate


class _LifecycleSession(Protocol):
    workspace: Path
    guard_home: Path

    def stop_resident(self) -> bool: ...

    def observe(self, harness: str, event: str, size_class: str) -> Observation: ...


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


def _run_sizes(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    *,
    unsupported_evidence: list[dict[str, object]] | None = None,
) -> list[Observation]:
    post_routes = tuple((harness, event) for harness, event in routes if event == "PostToolUse")
    selected = post_routes or (routes[0],)
    large_payloads = source_payloads(session.workspace)
    observations: list[Observation] = []
    completed = 0
    for size_class in SIZE_CLASSES[1:]:
        request_payload = large_payloads[size_class]
        for harness, event in selected:
            try:
                if not source_reference_supported():
                    if unsupported_evidence is None:
                        raise RuntimeError("unsupported source review requires a separate evidence destination")
                    unsupported_evidence.append(
                        session.probe_source_reference_denial(harness, event, size_class, request_payload)
                    )
                else:
                    observations.append(session.observe(harness, event, size_class, request_payload))
                completed += 1
            except Exception as error:
                raise contextual_failure(
                    error,
                    harness=harness,
                    event=event,
                    size_class=size_class,
                    sample_index=completed,
                    sample_phase="sizes",
                    completed_sample_counts={"sizes": completed},
                ) from error
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


def _run_cold(runtime: Path, session: _LifecycleSession, iterations: int) -> list[float]:
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


def _run_recovery(session: _LifecycleSession, iterations: int) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        _ = session.observe("claude-code", "PostToolUse", "1k")
        _require(
            session.stop_resident(),
            f"resident stop failed during recovery sample {index}",
        )
        started = time.perf_counter()
        with capture_recovery_observation() as detail:
            observation = session.observe("claude-code", "PostToolUse", "1k")
        values.append((time.perf_counter() - started) * 1_000.0)
        try:
            _require(observation.allowed and observation.route == "native_resident", f"recovery sample {index} failed")
        except Exception as error:
            raise contextual_failure(
                error,
                sample_phase="resident_recovery",
                sample_index=index,
                completed_sample_counts={"recovery": len(values) - 1},
                harness=observation.harness,
                event=observation.event,
                size_class=observation.size_class,
                route=observation.route,
                allowed=observation.allowed,
                overloaded=observation.overloaded,
                resident_stop_contained=True,
                **detail,
            ) from error
    return values


def _measure_slo(
    runtime: Path,
    routes: tuple[tuple[str, str], ...],
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
    launcher_iterations: int = 0,
) -> SloMeasurements:
    # Cold probes stop the session's resident before each one-shot call. Keep
    # them separate so this lifecycle exercise does not consume the bounded
    # restart budget used by warmup and recovery.
    progress = SloProgress()
    with progress.phase("cold_session"), AdapterSession(runtime) as cold_session, progress.phase("cold"):
        cold = _run_cold(runtime, cold_session, cold_iterations)
        progress.counts["cold"] = len(cold)
    with progress.phase("active_session"), AdapterSession(runtime) as session:
        with progress.phase("warm"):
            warm = _run_warm(session, routes, warm_iterations)
            progress.counts["warm"] = len(warm)
        source_denials: list[dict[str, object]] = []
        with progress.phase("sizes"):
            sizes = _run_sizes(session, routes, unsupported_evidence=source_denials)
            progress.counts["sizes"] = len(sizes) + len(source_denials)
        with progress.phase("recovery"):
            recovery = _run_recovery(session, recovery_iterations)
            progress.counts["recovery"] = len(recovery)
        with progress.phase("pool_warmup"):
            warmup_harness, warmup_event = routes[0]
            serialized_warmup = session.observe(warmup_harness, warmup_event, "1k")
            _require(
                serialized_warmup.allowed and serialized_warmup.route == "native_resident",
                "serialized resident pool warmup did not stay on the allowed native route",
            )
        with progress.phase("capacity"):
            capacity = measure_capacity(session, routes, include_capacity=include_capacity)
            progress.counts["capacity_16"] = len(capacity.concurrent_16)
            progress.counts["capacity_64"] = len(capacity.concurrent_64)
        readiness = [session.readiness_ms]
        with progress.phase("launcher"):
            launcher = (
                measure_registered_launcher(session, iterations=launcher_iterations) if launcher_iterations else None
            )
    if readiness_samples > 1:
        with progress.phase("readiness"):
            readiness.extend(_readiness_samples(runtime, readiness_samples - 1))
    rss_peak = max(capacity.rss_peak, process_rss_bytes())
    return SloMeasurements(
        warm=warm,
        sizes=sizes,
        recovery=recovery,
        cold=cold,
        concurrent_16=capacity.concurrent_16,
        concurrent_64=capacity.concurrent_64,
        errors_16=capacity.errors_16,
        errors_64=capacity.errors_64,
        readiness=readiness,
        rss_baseline=capacity.rss_baseline,
        rss_peak=rss_peak,
        installed_launcher=launcher,
        routes_16=capacity.routes_16,
        routes_64=capacity.routes_64,
        native_overloads_16=capacity.native_overloads_16,
        native_overloads_64=capacity.native_overloads_64,
        source_reference_denials=source_denials,
    )


def run_slo(
    runtime: Path,
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
    launcher_iterations: int = 0,
) -> dict[str, object]:
    progress = SloProgress()
    with progress.phase("runtime_identity"):
        _clear_proof_overrides()
        runtime_summary = _runtime_summary(runtime)
        routes = route_matrix()
    with progress.phase("installed_corpus"):
        installed_corpus = _installed_corpus(runtime, len(routes))
    with progress.phase("measurement"):
        measurements = _measure_slo(
            runtime,
            routes,
            warm_iterations=warm_iterations,
            cold_iterations=cold_iterations,
            recovery_iterations=recovery_iterations,
            readiness_samples=readiness_samples,
            include_capacity=include_capacity,
            launcher_iterations=launcher_iterations,
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
    parser.add_argument("--launcher-iterations", type=int, default=2)
    parser.add_argument("--skip-capacity", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.warm_iterations <= 0 or args.cold_iterations <= 0 or args.recovery_iterations <= 0:
        parser.error("iteration counts must be positive")
    if not 1 <= args.readiness_samples <= _MAX_READINESS_SAMPLES:
        parser.error("readiness samples must be between one and eight")
    if args.launcher_iterations < 0:
        parser.error("launcher iterations must be non-negative; zero explicitly skips launcher coverage")
    failed = False
    try:
        runtime = args.runtime.expanduser().resolve(strict=True)
        _require(runtime.is_file() and not args.runtime.is_symlink(), "runtime must be a regular non-symlink file")
        result = run_slo(
            runtime,
            warm_iterations=args.warm_iterations,
            cold_iterations=args.cold_iterations,
            recovery_iterations=args.recovery_iterations,
            readiness_samples=args.readiness_samples,
            include_capacity=not args.skip_capacity,
            launcher_iterations=args.launcher_iterations,
        )
    except Exception as error:
        failed = True
        result = assert_privacy_safe(
            {
                "schema": "hol-guard.native-installed-slo-failure.v1",
                "scope": "daemon_ingress_and_registered_launcher",
                "evidence_class": "smoke",
                "passed": False,
                "qualification_complete": False,
                "failure": failure_evidence(error),
            }
        )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not failed and (not args.enforce or result.get("passed") is True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
