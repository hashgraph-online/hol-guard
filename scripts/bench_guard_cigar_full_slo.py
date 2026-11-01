"""Run every installed SLO gate with explicit on/off CIGAR fixture activity.

This driver preserves the original native measurements, deadlines and gates.
Context setup, settling and post-restart authority checks are separate work.
No model, account, live Guard home or release activation is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from contextlib import nullcontext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("on", "off"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    parser.add_argument("--warm-iterations", type=int, default=2)
    parser.add_argument("--settle-seconds", type=int, default=5)
    parser.add_argument("--trace-stop-helpers", action="store_true")
    args = parser.parse_args()
    if not 2 <= args.warm_iterations <= 200 or not 0 <= args.settle_seconds <= 30:
        parser.error("context SLO profile exceeds its bounded range")
    if re.fullmatch(r"[0-9a-f]{40}", args.expected_build_sha) is None:
        parser.error("expected build SHA must be the exact installed source")
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    profile = root / "profile"
    profile.mkdir(mode=0o700)
    os.environ["HOME"] = str(profile)
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CODEX_HOME"):
        os.environ.pop(key, None)

    from scripts.bench_guard_native_installed_slo import run_slo
    from scripts.bench_guard_native_installed_slo_runtime import _clear_proof_overrides, _runtime_summary
    from scripts.cigar_benchmark_processes import ProcessSampler
    from scripts.cigar_slo_activity import CigarSloActivity
    from scripts.native_slo_process_tree import observe_rss_reads
    from scripts.native_slo_progress import SloProgress, incomplete_slo_result

    runtime = args.runtime.resolve(strict=True)
    _clear_proof_overrides()
    identity = _runtime_summary(runtime)
    if identity["build_sha"] != args.expected_build_sha:
        raise RuntimeError("context SLO installed artifact differs from the selected source")
    selected_python = Path(json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())["python"])
    progress = SloProgress()
    result = {
        "schema": "guard-cigar-full-installed-slo.v1",
        "completed": False,
        "mode": args.mode,
        "runtime": identity,
        "qualification": "local installed fixture; platform bound to runtime identity",
        "client_topology": "driver, authenticated hook clients and daemon share one Python process",
        "stop_helper_diagnostic": args.trace_stop_helpers,
    }
    repo = Path(__file__).resolve().parents[1]
    inputs = sorted(
        set(
            list((repo / "scripts").glob("native_slo*.py"))
            + list((repo / "scripts").glob("bench_guard_native_installed_slo*.py"))
            + [
                repo / name
                for name in (
                    "scripts/bench_guard_cigar_full_slo.py",
                    "scripts/cigar_slo_activity.py",
                    "scripts/cigar_benchmark_workload.py",
                    "scripts/cigar_benchmark_processes.py",
                    "scripts/native_installed_hook_corpus.py",
                    "scripts/native_probe_receipts.py",
                    "ci/native_runtime/probe_native_default_auto.py",
                    "ci/native_runtime/installed_hook_client.py",
                )
            ]
        )
    )
    result["tooling_source_sha256"] = {
        str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs
    }
    started = time.monotonic()
    activity = None
    try:
        with ProcessSampler(selected_python) as sampler:
            activity = CigarSloActivity(
                runtime,
                enabled=args.mode == "on",
                sampler=sampler,
                settle_seconds=args.settle_seconds,
                diagnostics_dir=root / "diagnostics",
            )
            trace = None
            if args.trace_stop_helpers:
                from scripts.native_slo_stop_trace import StopTrace

                trace = StopTrace(
                    runtime,
                    sampler,
                    case=lambda: (
                        f"session_{activity.session_count}:"
                        + (activity.phases[-1]["phase"] if activity.phases else "setup")
                    ),
                )
            try:
                with trace if trace is not None else nullcontext(), observe_rss_reads(activity.record_rss):
                    result["installed_slo"] = run_slo(
                        runtime,
                        warm_iterations=args.warm_iterations,
                        cold_iterations=3,
                        recovery_iterations=3,
                        readiness_samples=3,
                        include_capacity=True,
                        progress=progress,
                        activity=activity,
                    )
            finally:
                if trace is not None:
                    result["strict_stop_trace"] = trace.events
                    result["strict_stop_trace_complete"] = bool(trace.events) and all(
                        e["stderr_within_bound"]
                        and not any("sampling_error_type" in e[side] for side in ("before", "after"))
                        for e in trace.events
                    )
                result["context_activity"] = activity.summary()
                deadline = time.monotonic() + 5
                pending = (
                    "native_runtime",
                    "sdk_worker",
                    "python_bridge",
                    "selected_python",
                    "other_python_child",
                    "guard_python_worker",
                )
                final = sampler.sample()
                while any(final["counts"].get(kind, 0) for kind in pending) and time.monotonic() < deadline:
                    time.sleep(0.1)
                    final = sampler.sample()
                result["observed_processes_at_end"] = final
                result["context_activity"]["gates"]["observed_workers_contained_at_end"] = not any(
                    final["counts"].get(kind, 0) for kind in pending
                )
                result["all_observed_processes"] = sampler.summary()
        result["completed"] = True
    except Exception as error:
        progress.record_failure(error, stage="context_activity")
        result.setdefault("installed_slo", incomplete_slo_result(progress, include_capacity=True))
        result["fatal_error"] = {"type": type(error).__name__}
        raise
    finally:
        result["seconds"] = round(time.monotonic() - started, 3)
        result["tooling_unchanged_during_run"] = all(
            hashlib.sha256((repo / name).read_bytes()).hexdigest() == digest
            for name, digest in result["tooling_source_sha256"].items()
        )
        with (root / "result.json").open("x") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
    native_pass = result["installed_slo"]["passed"]
    context_pass = all(result["context_activity"]["gates"].values())
    print(json.dumps({"mode": args.mode, "all_installed_gates": native_pass, "all_activity_gates": context_pass}))
    trace_pass = result.get("strict_stop_trace_complete", True)
    return 0 if native_pass and context_pass and trace_pass and result["tooling_unchanged_during_run"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
