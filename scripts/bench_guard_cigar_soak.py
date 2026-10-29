"""Six-minute installed hook/resource observation with real optional CIGAR load.

Supplementary fixed-input soak, including a complete five-minute SDK lease.
Not the full installed SLO, an exhaustive process trace or a memory plateau proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--expected-build-sha", required=True)
    parser.add_argument("--mode", required=True, choices=("off", "on"))
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_build_sha) is None:
        parser.error("expected build must be an exact source SHA")
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    profile = root / "profile"
    profile.mkdir(mode=0o700)
    os.environ["HOME"] = str(profile)
    for name in ("CODEX_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
        os.environ.pop(name, None)
    os.environ["HOL_GUARD_NATIVE"] = "force"
    os.environ["HOL_GUARD_NATIVE_BINARY"] = str(args.runtime.resolve(strict=True))

    from codex_plugin_scanner.guard.native_context_assistance import control
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from scripts.bench_guard_native_release_gate import _bench_native_warm_production, _summary
    from scripts.cigar_benchmark_processes import ProcessSampler
    from scripts.cigar_benchmark_workload import ContextWorkload, activate, configure
    from scripts.native_slo_capacity import _measure_classified_wave
    from scripts.native_slo_contract import summarize
    from scripts.native_slo_diagnostics import capture_inflight_failure, capture_transport_refusals
    from scripts.native_slo_session import AdapterSession

    status = native_runtime_status()
    if not status.available or not status.compatible or status.capabilities is None or status.identity is None:
        raise RuntimeError("installed soak runtime is unavailable")
    if status.capabilities.build_sha != args.expected_build_sha:
        raise RuntimeError("installed soak artifact does not match selected source")
    result = {
        "schema": "guard-cigar-installed-soak.v1",
        "build_sha": args.expected_build_sha,
        "mode": args.mode,
        "Guard_python": list(sys.version_info[:3]),
        "native_sha256": status.identity.sha256,
        "native_bytes": status.identity.size,
        "duration_seconds": 360,
        "completed": False,
        "full_installed_SLO": False,
        "client_topology": "driver, hook clients and daemon share one Python process",
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "bench_guard_cigar_soak.py",
                "cigar_benchmark_workload.py",
                "cigar_benchmark_processes.py",
                "native_slo_session.py",
                "native_slo_diagnostics.py",
            )
        },
        "windows": [],
    }
    try:
        with ExitStack() as stack:
            selected = Path(json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())["python"])
            sampler = stack.enter_context(ProcessSampler(selected))
            session = AdapterSession(args.runtime, diagnostics_dir=root / "diagnostics")
            stack.callback(session.close)
            capture_transport_refusals(session.daemon._server)
            stack.push(partial(capture_inflight_failure, destination=root / "failure-live.json"))
            configure(args.runtime, session.guard_home, args.mode == "on")
            session.start()
            result["activation_ms"] = activate(session.guard_home) if args.mode == "on" else None
            workload = None
            if args.mode == "on":
                # Every compile is checked and counted. Downsample only latency
                # storage so the unchanged 8192-sample bound covers six minutes.
                workload = ContextWorkload(session.guard_home, session.workspace, latency_sample_every=8)
                stack.callback(workload.close)
                workload.start()
            elif control("status", guard_home=session.guard_home)["runtime"] is not None:
                raise RuntimeError("off-state soak unexpectedly started CIGAR")
            routes = (("claude-code", "PostToolUse"), ("codex", "PostToolUse"))
            ordinary, waves = [], {16: [], 64: []}
            with ThreadPoolExecutor(max_workers=64) as executor:
                for _ in range(2):
                    _, errors = _measure_classified_wave(session, routes, 64, executor, stage="capacity_prewarm")
                    if errors:
                        raise RuntimeError("soak capacity prewarm failed")
                for _ in range(20):
                    session.observe("claude-code", "PostToolUse", "1k")
                mark = sampler.checkpoint()
                time.sleep(1)
                result["rss_baseline"] = sampler.summary(mark)
                started = time.monotonic()
                for index in range(12):
                    mark = sampler.checkpoint()
                    before = workload.successes if workload else 0
                    while time.monotonic() < started + (index + 1) * 30:
                        for harness, event in routes:
                            ordinary.append(session.observe(harness, event, "1k"))
                        time.sleep(0.2)
                    for concurrency in (16, 64):
                        values, errors = _measure_classified_wave(
                            session, routes, concurrency, executor, stage=f"soak_{index + 1}_c{concurrency}"
                        )
                        waves[concurrency].extend(values)
                        if errors:
                            raise RuntimeError("soak capacity request error")
                    window = {
                        "window": index + 1,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "memory": sampler.summary(mark),
                        "successful_overlapping_compiles": workload.successes - before if workload else 0,
                    }
                    result["windows"].append(window)
                    print(json.dumps({"mode": args.mode, **window}), flush=True)
                binding = session.daemon._server.hook_worker.policy_snapshot_publisher.current_snapshot_binding()
                if binding is None:
                    raise RuntimeError("soak lost native policy binding")
                result["direct_warm"] = _summary(
                    _bench_native_warm_production(
                        workspace=session.workspace,
                        guard_home=session.guard_home,
                        iterations=200,
                        policy_snapshot=binding,
                    )
                )
            for label, values in (("ordinary", ordinary), ("c16", waves[16]), ("c64", waves[64])):
                result[label] = {
                    "latency": summarize([item.latency_ms for item in values]),
                    "native_resident": sum(item.route == "native_resident" for item in values),
                    "explicit_capacity": sum(item.overloaded for item in values),
                    "unclassified_refusals": sum(not item.allowed and not item.overloaded for item in values),
                }
            final = control("status", guard_home=session.guard_home)
            result["effective_enabled_at_end"] = final["effective_enabled"]
            result["selected_CIGAR_interpreter"] = (
                final["runtime"]["interpreter"]["version"] if final["runtime"] else None
            )
            if workload:
                result["context_workload"] = workload.close()
            result["observed_processes"] = sampler.summary()
            observed = result["observed_processes"]["maximum_counts"]
            optional = ("sdk_worker", "selected_python", "python_bridge", "other_python_child")
            growth = (
                max(w["memory"]["peak_rss_bytes"] for w in result["windows"])
                / result["rss_baseline"]["median_rss_bytes"]
                - 1
            )
            result["steady_rss_growth"] = growth
            result["gates"] = {
                "direct_p95_20ms": result["direct_warm"]["p95_ms"] <= 20,
                "ordinary_p95_1000ms": result["ordinary"]["latency"]["p95_ms"] <= 1000,
                "c16_p99_1000ms": result["c16"]["latency"]["p99_ms"] <= 1000,
                "no_unclassified_refusals": all(
                    result[key]["unclassified_refusals"] == 0 for key in ("ordinary", "c16", "c64")
                ),
                "no_python_or_unknown_routes": all(
                    item.route in {"native_resident", "native_fail_safe"}
                    for values in (ordinary, waves[16], waves[64])
                    for item in values
                ),
                "observed_tree_rss_growth_12_percent": growth <= 0.12,
                "process_sampling_complete": sampler.errors == 0,
                "worker_coverage": bool(observed.get("sdk_worker") and observed.get("python_bridge"))
                if args.mode == "on"
                else not any(observed.get(key) for key in optional),
                "real_compiles_in_every_window": all(
                    w["successful_overlapping_compiles"] > 0 for w in result["windows"]
                )
                if workload
                else True,
                "runtime_still_effective": final["effective_enabled"] == (args.mode == "on"),
                "no_context_refusals": not result.get("context_workload", {}).get("refusals"),
            }
            control("stop", guard_home=session.guard_home)
        result["completed"] = True
    except Exception as error:
        result["fatal_error"] = {"type": type(error).__name__, "cause_type": type(error.__cause__).__name__}
        raise
    finally:
        with (root / "result.json").open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    return 0 if all(result["gates"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
