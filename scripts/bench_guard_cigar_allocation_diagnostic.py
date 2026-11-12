"""Instrument compiler calls and traced allocations in a private focused run.

This observer changes Python scheduling and allocation costs. Its latency and
RSS gates cannot qualify or replace the frozen, uninstrumented cohort. Retain
only fixed operation labels, allocation locations and aggregate process data;
never inspect request values, object contents, argv or environment values.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import threading
import time
import tracemalloc
from collections import Counter
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_contention as benchmark  # noqa: E402
from scripts.cigar_benchmark_processes import ProcessSampler  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment  # noqa: E402

COMPILER_SUFFIX = "/guard/extension_builder/native_source_compiler.py"
FUNCTIONS = {"_read_regular", "_verify_compiler", "_verify_manifest", "run_source_compiler", "_run_bounded"}
OPERATIONS = {
    "compile",
    "validate",
    "check",
    "test",
    "compare",
    "schema",
    "descriptor-schema",
    "authoring-admission",
    "bundle-metadata",
    "bundle-compatibility",
}
LABELS = {"source compiler", "source compiler manifest", "packaged native command program"}


class CompilerObserver:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.active = {}
        self.counts = {}
        self.timeline = []
        self.dropped_timeline_events = 0
        self.started = time.perf_counter()

    def profile(self, frame, event, value):
        if event not in {"call", "return"}:
            return
        code = frame.f_code
        if code.co_name not in FUNCTIONS or not code.co_filename.endswith(COMPILER_SUFFIX):
            return
        with self.lock:
            if event == "call":
                category = "all"
                if code.co_name == "run_source_compiler":
                    candidate = frame.f_locals.get("subcommand")
                    category = candidate if candidate in OPERATIONS else "other"
                elif code.co_name == "_read_regular":
                    candidate = frame.f_locals.get("label")
                    category = candidate if candidate in LABELS else "other"
                key = f"{code.co_name}:{category}"
                row = self.counts.setdefault(key, Counter())
                row["calls"] += 1
                row["active"] += 1
                row["max_concurrent"] = max(row["max_concurrent"], row["active"])
                self.active[id(frame)] = (key, time.perf_counter())
                return
            key, started = self.active.pop(id(frame))
            row = self.counts[key]
            elapsed = (time.perf_counter() - started) * 1000
            returned_bytes = len(value) if type(value) is bytes else 0
            current, peak = tracemalloc.get_traced_memory()
            row["active"] -= 1
            row["returns"] += 1
            row["returned_none"] += value is None
            row["returned_bytes"] += returned_bytes
            row["large_returns"] += returned_bytes >= 1024 * 1024
            row["duration_sum_ms"] += elapsed
            row["duration_max_ms"] = max(row["duration_max_ms"], elapsed)
            row["traced_current_max_bytes"] = max(row["traced_current_max_bytes"], current)
            row["traced_peak_max_bytes"] = max(row["traced_peak_max_bytes"], peak)
            if len(self.timeline) < 1024:
                self.timeline.append(
                    {
                        "operation": key,
                        "since_start_ms": round((time.perf_counter() - self.started) * 1000, 3),
                        "duration_ms": round(elapsed, 3),
                        "returned_bytes": returned_bytes,
                        "traced_current_bytes": current,
                        "traced_peak_bytes": peak,
                    }
                )
            else:
                self.dropped_timeline_events += 1

    def report(self):
        with self.lock:
            return {
                "counts": {key: dict(value) for key, value in sorted(self.counts.items())},
                "unreturned_calls": len(self.active),
                "timeline": list(self.timeline),
                "dropped_timeline_events": self.dropped_timeline_events,
            }


def allocation_locations(installed: Path) -> list[dict]:
    snapshot = tracemalloc.take_snapshot()
    rows = Counter()
    for stat in snapshot.statistics("lineno"):
        frame = stat.traceback[0]
        label, line = "external-or-standard-library", 0
        for prefix, name in ((str(installed) + "/", "installed/"), (str(REPO) + "/", "repository/")):
            if frame.filename.startswith(prefix):
                label, line = name + frame.filename[len(prefix) :], frame.lineno
                break
        rows[label, line] += stat.size
    return [{"source": label, "line": line, "traced_bytes": size} for (label, line), size in rows.most_common(25)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("off", "on"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    installed = runtime.parents[2]
    origin = importlib.util.find_spec("codex_plugin_scanner")
    if origin is None or Path(origin.origin).resolve() != installed / "codex_plugin_scanner/__init__.py":
        raise RuntimeError("diagnostic must import the selected installed package")
    if sys.getprofile() is not None or threading.getprofile() is not None or tracemalloc.is_tracing():
        raise RuntimeError("diagnostic requires an uninstrumented fresh process")
    clear_proof_environment()
    for key in ("HOL_GUARD_HOME", "HOL_GUARD_RESIDENT_TEST_SEAMS", "NATIVE_STOP_DIAGNOSTIC_PATH"):
        os.environ.pop(key, None)
    os.environ["PYTHONPATH"] = os.pathsep.join((str(installed), str(REPO)))
    wrapper_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    measured = {
        "schema": "guard-cigar-allocation-diagnostic.v1",
        "mode": args.mode,
        "diagnostic_only": True,
        "not_matched_cohort_qualification": True,
        "profile_and_tracemalloc_change_scheduling_and_memory": True,
        "tracemalloc_frames": 1,
        "wrapper_sha256": wrapper_sha,
        "checkpoints": [],
    }
    observer = CompilerObserver()
    original = ProcessSampler.checkpoint

    def checkpoint(sampler):
        current, peak = tracemalloc.get_traced_memory()
        row = {
            "index": len(measured["checkpoints"]),
            "processes": sampler.sample(),
            "traced_current_bytes": current,
            "traced_peak_bytes": peak,
            "tracer_overhead_bytes": tracemalloc.get_tracemalloc_memory(),
            "compiler_counts": observer.report()["counts"],
        }
        if not measured["checkpoints"]:
            row["allocation_locations"] = allocation_locations(installed)
        measured["checkpoints"].append(row)
        return original(sampler)

    arguments = [
        str(REPO / "scripts/bench_guard_cigar_contention.py"),
        "--runtime",
        str(runtime),
        "--root",
        str(args.root),
        "--mode",
        args.mode,
        "--expected-build-sha",
        args.expected_build_sha,
        "--warm-iterations",
        "200",
        "--waves",
        "5",
    ]
    tracemalloc.start(1)
    try:
        threading.setprofile_all_threads(observer.profile)
        with patch.object(sys, "argv", arguments), patch.object(ProcessSampler, "checkpoint", checkpoint):
            result = benchmark.main()
        measured["underlying_returncode"] = result
        return result
    finally:
        threading.setprofile_all_threads(None)
        measured["compiler"] = observer.report()
        measured["final_traced_current_bytes"], measured["final_traced_peak_bytes"] = tracemalloc.get_traced_memory()
        measured["final_allocation_locations"] = allocation_locations(installed)
        tracemalloc.stop()
        measured["wrapper_source_unchanged"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == wrapper_sha
        if args.root.is_dir():
            with (args.root / "allocation-diagnostic.json").open("x") as output:
                json.dump(measured, output, indent=2)
                output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
