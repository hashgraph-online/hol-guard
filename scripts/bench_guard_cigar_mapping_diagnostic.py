"""Observe aggregate macOS mappings before the private focused RSS baseline.

vmmap takes an OS snapshot and can affect scheduling/accounting. This is an
explicit diagnostic, never a replacement for the frozen failed cohort. Only
fixed region groups and numeric totals survive parsing; no addresses, process
headers, mapped filenames, request contents or stderr text are retained.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts import bench_guard_cigar_contention as benchmark  # noqa: E402
from scripts.cigar_benchmark_processes import ProcessSampler  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment  # noqa: E402

SIZE = r"[0-9]+(?:\.[0-9]+)?[KMGT]?"
REGION = re.compile(r"^(.+?)\s{2,}" + r"\s+".join([f"({SIZE})"] * 7) + r"\s+([0-9]+)(?:\s.*)?$")
IMAGE_SECTIONS = {
    "__AUTH",
    "__AUTH_CONST",
    "__CTF",
    "__DATA",
    "__DATA_CONST",
    "__DATA_DIRTY",
    "__FONT_DATA",
    "__LINKEDIT",
    "__OBJC_RO",
    "__OBJC_RW",
    "__TEXT",
    "__TPRO_CONST",
}
FIELDS = ("virtual", "resident", "dirty", "swapped", "volatile", "nonvolatile", "empty")
MALLOC_TYPES = {
    "MALLOC_LARGE",
    "MALLOC_LARGE (reserved)",
    "MALLOC_LARGE_REUSABLE",
    "MALLOC_LARGE (reusable)",
    "MALLOC_MEDIUM",
    "MALLOC_MEDIUM (empty)",
    "MALLOC_SMALL",
    "MALLOC_SMALL (empty)",
    "MALLOC_TINY",
    "MALLOC_TINY (empty)",
    "MALLOC_NANO",
    "MALLOC_NANO (empty)",
    "MALLOC metadata",
    "MALLOC guard page",
    "MALLOC_NANO metadata",
}


def size_bytes(value: str) -> int:
    suffix = value[-1]
    power = "KMGT".find(suffix) + 1 if suffix in "KMGT" else 0
    return int(Decimal(value[:-1] if power else value) * (1024**power))


def parse_summary(output: str) -> dict:
    groups = {}
    malloc_types = {}
    for line in output.splitlines():
        matched = REGION.fullmatch(line)
        if matched is None:
            continue
        name, *values, count = matched.groups()
        name = name.strip()
        group = (
            "total"
            if name == "TOTAL"
            else "malloc"
            if name.startswith("MALLOC")
            else "vm_allocate"
            if name == "VM_ALLOCATE"
            else "mapped_file"
            if name == "mapped file"
            else "stack"
            if name in {"Stack", "STACK GUARD"}
            else "image_sections"
            if name in IMAGE_SECTIONS
            else "other"
        )
        converted = {f"{field}_approx_bytes": size_bytes(value) for field, value in zip(FIELDS, values, strict=True)}
        converted["region_count"] = int(count)
        groups.setdefault(group, Counter()).update(converted)
        if name in MALLOC_TYPES:
            malloc_types.setdefault(name, Counter()).update(converted)
    physical = re.search(r"^Physical footprint:\s*(" + SIZE + r")\s*$", output, re.MULTILINE)
    peak = re.search(r"^Physical footprint \(peak\):\s*(" + SIZE + r")\s*$", output, re.MULTILINE)
    if "total" not in groups or physical is None or peak is None:
        raise RuntimeError("vmmap summary format is incomplete or unsupported")
    return {
        "displayed_sizes_are_rounded": True,
        "groups": {key: dict(value) for key, value in groups.items()},
        "malloc_types": {key: dict(value) for key, value in malloc_types.items()},
        "physical_footprint_approx_bytes": size_bytes(physical[1]),
        "physical_footprint_peak_approx_bytes": size_bytes(peak[1]),
    }


def mappings() -> dict:
    result = subprocess.run(
        ["/usr/bin/vmmap", "-summary", str(os.getpid())], capture_output=True, text=True, timeout=15
    )
    if result.returncode or len(result.stdout) + len(result.stderr) > 1024 * 1024:
        raise RuntimeError("bounded own-process vmmap summary failed")
    return parse_summary(result.stdout)


def sqlite_allocations() -> dict:
    """Read numeric allocator totals from Python's already loaded SQLite ABI."""
    import _sqlite3
    import sqlite3

    try:
        library = ctypes.CDLL(_sqlite3.__file__)
        version = library.sqlite3_libversion
        version.argtypes = ()
        version.restype = ctypes.c_char_p
        status = library.sqlite3_status64
        status.argtypes = (
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_longlong),
            ctypes.POINTER(ctypes.c_longlong),
            ctypes.c_int,
        )
        status.restype = ctypes.c_int
    except (OSError, AttributeError) as error:
        return {"available": False, "error_type": type(error).__name__}
    if version().decode("ascii") != sqlite3.sqlite_version:
        raise RuntimeError("SQLite allocator observer resolved a different library version")
    result = {"available": True, "sqlite_version": sqlite3.sqlite_version, "reset_highwater": False}
    # sqlite3.h: SQLITE_STATUS_MEMORY_USED = 0; SQLITE_STATUS_MALLOC_COUNT = 9.
    for operation, label in ((0, "memory_used_bytes"), (9, "malloc_count")):
        current, highwater = ctypes.c_longlong(), ctypes.c_longlong()
        if status(operation, ctypes.byref(current), ctypes.byref(highwater), 0) != 0:
            raise RuntimeError("SQLite allocator status failed")
        result[label] = {"current": current.value, "highwater": highwater.value}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", choices=("off", "on"), required=True)
    parser.add_argument("--expected-build-sha", required=True)
    parser.add_argument("--observe-off-idle-seconds", type=int, default=0)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("aggregate mapping diagnostic requires macOS")
    if not 0 <= args.observe_off_idle_seconds <= 60 or (args.observe_off_idle_seconds and args.mode != "off"):
        parser.error("additional idle observation is bounded to 0..60 seconds in off mode")
    runtime = args.runtime.resolve(strict=True)
    clear_proof_environment()
    for key in ("HOL_GUARD_HOME", "HOL_GUARD_RESIDENT_TEST_SEAMS", "NATIVE_STOP_DIAGNOSTIC_PATH"):
        os.environ.pop(key, None)
    os.environ["PYTHONPATH"] = os.pathsep.join((str(runtime.parents[2]), str(REPO)))
    measured = {
        "schema": "guard-cigar-mapping-diagnostic.v1",
        "mode": args.mode,
        "diagnostic_only": True,
        "not_matched_cohort_qualification": True,
        "os_snapshot_changes_scheduling_and_accounting": True,
        "wrapper_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "checkpoints": [],
        "observe_off_idle_seconds": args.observe_off_idle_seconds,
    }
    original = ProcessSampler.checkpoint
    diagnostic_started = time.monotonic()

    def observe(sampler, phase):
        before = sampler.sample()
        started = time.perf_counter()
        summary = mappings()
        measured["checkpoints"].append(
            {
                "phase": phase,
                "since_diagnostic_start_ms": round((time.monotonic() - diagnostic_started) * 1000, 3),
                "before": before,
                "mapping": summary,
                "sqlite_allocations": sqlite_allocations(),
                "observer_ms": round((time.perf_counter() - started) * 1000, 3),
                "after": sampler.sample(),
            }
        )

    def checkpoint(sampler):
        if not measured["checkpoints"]:
            observe(sampler, "initial")
            if args.observe_off_idle_seconds:
                time.sleep(args.observe_off_idle_seconds)
                observe(sampler, "after_off_idle")
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
        if len(measured["checkpoints"]) != 1 + bool(args.observe_off_idle_seconds):
            raise RuntimeError("diagnostic did not observe the declared mapping summaries")
        return result
    finally:
        if args.root.is_dir():
            with (args.root / "mapping-diagnostic.json").open("x") as output:
                json.dump(measured, output, indent=2)
                output.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
