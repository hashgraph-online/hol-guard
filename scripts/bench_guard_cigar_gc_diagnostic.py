"""Explicit heap-collection diagnostic; never a matched-cohort qualification.

Run the focused profile with one full collection before its RSS baseline.
Only allocation counters and aggregate process RSS are retained. This changes
the measurement procedure and cannot replace the frozen failed cohort.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_contention as benchmark  # noqa: E402
from scripts.cigar_benchmark_processes import ProcessSampler  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("off", "on"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    clear_proof_environment()
    for key in ("HOL_GUARD_HOME", "HOL_GUARD_RESIDENT_TEST_SEAMS", "NATIVE_STOP_DIAGNOSTIC_PATH"):
        os.environ.pop(key, None)
    os.environ["PYTHONPATH"] = os.pathsep.join((str(runtime.parents[2]), str(REPO)))
    measured = {
        "schema": "guard-cigar-gc-diagnostic.v1",
        "mode": args.mode,
        "diagnostic_only": True,
        "not_matched_cohort_qualification": True,
        "checkpoints": [],
        "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    original = ProcessSampler.checkpoint

    def checkpoint(sampler):
        if not measured["checkpoints"]:
            before = sampler.sample()
            stats = gc.get_stats()
            started = time.perf_counter()
            collected = gc.collect()
            elapsed = (time.perf_counter() - started) * 1000
            measured["checkpoints"].append(
                {
                    "before": before,
                    "after": sampler.sample(),
                    "collected_objects": collected,
                    "collection_ms": round(elapsed, 3),
                    "before_gc_counters": stats,
                    "after_gc_counters": gc.get_stats(),
                }
            )
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
    try:
        with patch.object(sys, "argv", arguments), patch.object(ProcessSampler, "checkpoint", checkpoint):
            result = benchmark.main()
        measured["underlying_returncode"] = result
        if len(measured["checkpoints"]) != 1:
            raise RuntimeError("diagnostic did not observe exactly one setup collection")
        return result
    finally:
        if args.root.is_dir():
            with (args.root / "gc-diagnostic.json").open("x") as output:
                json.dump(measured, output, indent=2)
                output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
