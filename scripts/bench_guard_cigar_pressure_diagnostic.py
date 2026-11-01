"""macOS allocator-pressure experiment, separate from cohort qualification.

One allocator intervention before the first focused RSS checkpoint. This is
not production behavior, a memory-savings claim or a latency qualification.
Only allocator counters and complete observed-process aggregates are retained.
"""

from __future__ import annotations

import argparse
import ctypes
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


class MallocStatistics(ctypes.Structure):
    # Apple SDK malloc/malloc.h: malloc_statistics_t, not a heap/object reader.
    _fields_ = [
        ("blocks_in_use", ctypes.c_uint),
        ("size_in_use", ctypes.c_size_t),
        ("max_size_in_use", ctypes.c_size_t),
        ("size_allocated", ctypes.c_size_t),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("off", "on"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("allocator-pressure diagnostic requires macOS")
    runtime = args.runtime.resolve(strict=True)
    clear_proof_environment()
    for key in ("HOL_GUARD_HOME", "HOL_GUARD_RESIDENT_TEST_SEAMS", "NATIVE_STOP_DIAGNOSTIC_PATH"):
        os.environ.pop(key, None)
    os.environ["PYTHONPATH"] = os.pathsep.join((str(runtime.parents[2]), str(REPO)))
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    pressure_relief = library.malloc_zone_pressure_relief
    pressure_relief.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    pressure_relief.restype = ctypes.c_size_t
    statistics = library.malloc_zone_statistics
    statistics.argtypes = (ctypes.c_void_p, ctypes.POINTER(MallocStatistics))
    statistics.restype = None

    def counters():
        value = MallocStatistics()
        statistics(None, ctypes.byref(value))
        return {name: getattr(value, name) for name, _ in value._fields_}

    measured = {
        "schema": "guard-cigar-allocator-pressure-diagnostic.v1",
        "mode": args.mode,
        "diagnostic_only": True,
        "not_matched_cohort_qualification": True,
        "intervention": "one malloc_zone_pressure_relief(NULL, 0) before first RSS checkpoint; no explicit gc.collect",
        "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "checkpoints": [],
    }
    original = ProcessSampler.checkpoint
    diagnostic_started = time.monotonic()

    def checkpoint(sampler):
        if not measured["checkpoints"]:
            before = sampler.sample()
            before_counters = counters()
            started = time.perf_counter()
            released = pressure_relief(None, 0)
            elapsed = (time.perf_counter() - started) * 1000
            after_counters = counters()
            measured["checkpoints"].append(
                {
                    "since_diagnostic_start_ms": round((time.monotonic() - diagnostic_started) * 1000, 3),
                    "before": before,
                    "after": sampler.sample(),
                    "before_allocator": before_counters,
                    "after_allocator": after_counters,
                    "allocator_reported_bytes_released": released,
                    "intervention_ms": round(elapsed, 3),
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
            raise RuntimeError("diagnostic did not observe exactly one allocator intervention")
        return result
    finally:
        if args.root.is_dir():
            with (args.root / "pressure-diagnostic.json").open("x") as output:
                json.dump(measured, output, indent=2)
                output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
