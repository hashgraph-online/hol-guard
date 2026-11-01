"""Installed Guard hook latency and complete observed-tree RSS under real CIGAR load.

One fresh subprocess per variant; use a private HOME before importing Guard.
This focused probe supplements, and never replaces, the complete installed SLO.
Only aggregate synthetic measurements are written to its result document.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from functools import partial
from pathlib import Path

# Running a tooling file directly does not put the repository on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def finish_cleanup(result, session, sampler) -> None:
    """Observe completed cleanup outside every request/resource timing window."""
    deadline = time.monotonic() + 5
    while True:
        remaining = sampler.sample()
        live = sum(
            count
            for kind, count in remaining["counts"].items()
            if kind not in {"benchmark_daemon_host", "terminated_child"}
        )
        if live == 0 or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    final = getattr(session, "final_stop_diagnostic", {})
    retained = getattr(session, "last_stop_diagnostic", {})
    result["cleanup"] = {
        "final_stop_status": final.get("status", "missing"),
        "retained_stop_status": retained.get("status", "missing"),
        "recovery_used": getattr(session, "recovery_cleanup", None) is not None,
        "daemon_stop_contained": getattr(session, "daemon_stop_contained", False) is True,
        "observed_at_end": remaining,
        "live_descendants_remaining": live,
    }
    result["gates"].update(
        strict_final_stop=all(d.get("status") in {"contained", "already-stopped"} for d in (final, retained))
        and not result["cleanup"]["recovery_used"],
        all_observed_live_descendants_contained=live == 0,
        daemon_shutdown_contained=result["cleanup"]["daemon_stop_contained"],
        process_sampling_complete=sampler.errors == 0,
    )
    result["all_observed_processes"] = sampler.summary()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("baseline-off", "off", "on"), required=True)
    parser.add_argument("--expected-build-sha", default="75c78563ed4e3c949c01285133fff9e15aa24193")
    parser.add_argument("--warm-iterations", type=int, default=200)
    parser.add_argument("--waves", type=int, default=5)
    parser.add_argument("--transport-diagnostics", action="store_true")
    args = parser.parse_args()
    if not 50 <= args.warm_iterations <= 2000 or not 2 <= args.waves <= 20:
        parser.error("benchmark iteration counts exceed bounded profile")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_build_sha) is None:
        parser.error("expected build SHA must name the exact installed artifact source")
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    profile = root / "profile"
    profile.mkdir(mode=0o700)
    os.environ["HOME"] = str(profile)
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CODEX_HOME"):
        os.environ.pop(key, None)
    os.environ["HOL_GUARD_NATIVE"] = "force"
    os.environ["HOL_GUARD_NATIVE_BINARY"] = str(args.runtime.resolve(strict=True))

    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from scripts.bench_guard_native_release_gate import _bench_native_warm_production, _summary
    from scripts.cigar_benchmark_processes import ProcessSampler
    from scripts.native_slo_capacity import _measure_classified_wave
    from scripts.native_slo_contract import summarize
    from scripts.native_slo_diagnostics import capture_inflight_failure, capture_transport_refusals
    from scripts.native_slo_session import AdapterSession

    status = native_runtime_status()
    if not status.available or not status.compatible or status.identity is None:
        raise RuntimeError("installed benchmark native runtime is unavailable")
    if not status.capabilities or status.capabilities.build_sha != args.expected_build_sha:
        raise RuntimeError("measured native build differs from the explicitly selected installed source")
    if args.mode != "baseline-off":
        from codex_plugin_scanner.guard.native_context_assistance import control
        from scripts.cigar_benchmark_workload import ContextWorkload, activate, configure

    workload = None
    result = {
        "schema": "guard-cigar-installed-contention.v1",
        "mode": args.mode,
        "build_sha": status.capabilities.build_sha,
        "full_installed_SLO": False,
        "diagnostic_transport_observer": args.transport_diagnostics,
        "client_topology": "driver, authenticated hook clients and daemon share one Python process",
        "root_python": list(sys.version_info[:3]),
        "completed": False,
        "active_stage": "startup",
        "stages": {},
    }
    try:
        with ExitStack() as stack:
            selected_python = Path(json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())["python"])
            sampler = stack.enter_context(ProcessSampler(selected_python))
            session = AdapterSession(args.runtime, diagnostics_dir=root / "diagnostics")
            stack.callback(session.close)
            if args.transport_diagnostics:
                capture_transport_refusals(session.daemon._server)
                stack.push(partial(capture_inflight_failure, destination=root / "failure-live.json"))
            if args.mode != "baseline-off":
                configure(args.runtime, session.guard_home, args.mode == "on")
            session.start()
            result["native_readiness_ms"] = session.readiness_ms
            result["candidate_activation_ms"] = activate(session.guard_home) if args.mode == "on" else None
            if args.mode == "on":
                workload = ContextWorkload(session.guard_home, session.workspace)
                stack.callback(workload.close)
                workload.start()
            elif args.mode == "off" and control("status", guard_home=session.guard_home)["runtime"] is not None:
                raise RuntimeError("off-state benchmark unexpectedly started CIGAR")
            routes = (("claude-code", "PostToolUse"), ("codex", "PostToolUse"))
            with ThreadPoolExecutor(max_workers=64) as executor:
                # Warm both the ordinary transport and every bounded capacity
                # worker before comparing memory during the measured c64 waves.
                for _ in range(2):
                    result["active_stage"] = "capacity_prewarm"
                    _, errors = _measure_classified_wave(session, routes, 64, executor, stage="capacity_prewarm")
                    if errors:
                        raise RuntimeError("installed benchmark capacity prewarm failed")
                for _ in range(20):
                    result["active_stage"] = "serial_prewarm"
                    session.observe("claude-code", "PostToolUse", "1k")
                baseline_mark = sampler.checkpoint()
                result["active_stage"] = "rss_baseline"
                time.sleep(1)
                baseline = sampler.summary(baseline_mark)
                result["rss_baseline"] = baseline
                for concurrency in (1, 16, 64):
                    result["active_stage"] = f"concurrent_{concurrency}"
                    mark = sampler.checkpoint()
                    compiles_before = workload.successes if workload else 0
                    observations, errors = [], 0
                    if concurrency == 1:
                        for _ in range(args.warm_iterations):
                            observations.append(session.observe("claude-code", "PostToolUse", "1k"))
                    else:
                        for _ in range(args.waves):
                            values, failures = _measure_classified_wave(
                                session, routes, concurrency, executor, stage=f"concurrent_{concurrency}"
                            )
                            observations.extend(values)
                            errors += failures
                    sampler.sample()
                    result["stages"][str(concurrency)] = {
                        "latency": summarize([item.latency_ms for item in observations]),
                        "routes": dict(Counter(item.route for item in observations)),
                        "errors": errors,
                        "allowed": sum(item.allowed for item in observations),
                        "explicit_capacity": sum(item.overloaded for item in observations),
                        "unclassified_refusals": sum(not item.allowed and not item.overloaded for item in observations),
                        "successful_overlapping_compiles": (workload.successes - compiles_before) if workload else 0,
                        "memory": sampler.summary(mark),
                    }
                # Keep the direct production adapter boundary distinct from HTTP.
                snapshot = session.daemon._server.hook_worker.policy_snapshot_publisher.current_snapshot_binding()
                result["active_stage"] = "direct_adapter_warm"
                if snapshot is None:
                    raise RuntimeError("benchmark lost its admitted policy binding")
                compiles_before = workload.successes if workload else 0
                direct = _bench_native_warm_production(
                    workspace=session.workspace,
                    guard_home=session.guard_home,
                    iterations=args.warm_iterations,
                    policy_snapshot=snapshot,
                )
                result["direct_adapter_warm"] = _summary(direct)
                result["successful_direct_overlapping_compiles"] = (
                    workload.successes - compiles_before if workload else 0
                )
            if workload:
                result["context_workload"] = workload.close()
                workload = None
            result["all_observed_processes"] = sampler.summary()
            observed = result["all_observed_processes"]["maximum_counts"]
            coverage = (
                bool(observed.get("sdk_worker", 0) and observed.get("python_bridge", 0))
                if args.mode == "on"
                else not any(
                    observed.get(kind, 0)
                    for kind in ("sdk_worker", "selected_python", "python_bridge", "other_python_child")
                )
            )
            if not coverage:
                print(
                    json.dumps(
                        {
                            "worker_coverage_failed": True,
                            "observed_executable_basenames": sorted(sampler.observed_names),
                        }
                    )
                )
            steady_peak = max(stage["memory"]["peak_rss_bytes"] for stage in result["stages"].values())
            result["steady_rss_growth"] = steady_peak / baseline["median_rss_bytes"] - 1
            result["gates"] = {
                "direct_warm_p95_20ms": result["direct_adapter_warm"]["p95_ms"] <= 20,
                "installed_warm_p95_1000ms": result["stages"]["1"]["latency"]["p95_ms"] <= 1000,
                "installed_c16_p99_1000ms": result["stages"]["16"]["latency"]["p99_ms"] <= 1000,
                "no_request_errors_or_unclassified_refusals": all(
                    stage["errors"] == stage["unclassified_refusals"] == 0 for stage in result["stages"].values()
                ),
                "complete_observed_tree_rss_growth_12_percent": result["steady_rss_growth"] <= 0.12,
                "process_sampling_complete": sampler.errors == 0,
                "optional_worker_coverage": coverage,
                "real_compile_overlap": args.mode != "on"
                or (
                    all(stage["successful_overlapping_compiles"] > 0 for stage in result["stages"].values())
                    and result["successful_direct_overlapping_compiles"] > 0
                ),
                "no_unexpected_context_refusals": args.mode != "on"
                or not (set(result["context_workload"]["refusals"]) - {"native_context_assistance_context_busy"}),
                "unchanged_graph_revision_reused": args.mode != "on"
                or result["context_workload"]["unchanged_graph_revision_reused"],
            }
            if args.mode != "baseline-off":
                control("stop", guard_home=session.guard_home)
        finish_cleanup(result, session, sampler)
        result["active_stage"] = "completed"
        result["completed"] = True
    except Exception as error:
        result["fatal_error"] = {"type": type(error).__name__, "cause_type": type(error.__cause__).__name__}
        raise
    finally:
        if workload:
            workload.close()
        with (root / "result.json").open("x") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
    print(json.dumps({"mode": args.mode, "gates": result["gates"]}))
    return 0 if all(result["gates"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
