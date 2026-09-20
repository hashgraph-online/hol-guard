#!/usr/bin/env python3
"""Paired fresh-process package correction or explicit native-pilot diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
from pathlib import Path

if __package__:
    from .bench_guard_package_matrix import (
        compare_results,
        run_arm,
        source_identity,
        validate_arm_source,
        write_checkpoint,
    )
else:
    from bench_guard_package_matrix import (
        compare_results,
        run_arm,
        source_identity,
        validate_arm_source,
        write_checkpoint,
    )

NATIVE_CASES = (
    (10000, 100, "absent"),
    (10000, 1000, "absent"),
    (10000, 1000, "exact"),
    (10000, 10000, "deny"),
    (100, 1000, "exact"),
    (100, 10000, "deny"),
)
CORRECTION_CASES = ((100, 10000, "deny"), (100, 1000, "exact"), (10000, 1000, "absent"))


def summarize(rows):
    cases = []
    for dependencies, bundle_size, mode in dict.fromkeys(
        (row["dependencies"], row["bundle_records"], row["mode"]) for row in rows
    ):
        pairs = [
            row
            for row in rows
            if (row["dependencies"], row["bundle_records"], row["mode"]) == (dependencies, bundle_size, mode)
        ]
        equal = [row for row in pairs if row["comparison"]["status"] == "equal"]
        summary = {
            "dependencies": dependencies,
            "bundle_records": bundle_size,
            "mode": mode,
            "pairs": len(pairs),
            "equal_pairs": len(equal),
            "native_scope": pairs[0].get("expected_native_completions") == 1,
        }
        if len(equal) == len(pairs):
            for metric in ("cpu", "wall"):
                values = {
                    arm: [row[arm]["measurement"][metric + "_median_ms"] for row in pairs]
                    for arm in ("baseline", "candidate")
                }
                summary[metric + "_ms"] = values
                summary[metric + "_median_improvement_percent"] = 100 * (
                    1 - statistics.median(values["candidate"]) / statistics.median(values["baseline"])
                )
            summary["diagnostic_cpu_gate_pass"] = (
                summary["cpu_median_improvement_percent"] >= 30 and summary["wall_median_improvement_percent"] >= -5
            )
        cases.append(summary)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("correction", "native"), required=True)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--native-pilot-binary", type=Path)
    parser.add_argument("--measurement-lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    if args.repeats < 1 or args.timeout <= 0 or os.name != "posix":
        parser.error("Positive repeats/cutoff and POSIX advisory locking required")
    if (args.suite == "native") != bool(args.native_pilot_binary):
        parser.error("The native suite requires an explicit binary; the correction suite must not use one")
    if args.suite == "native" and args.baseline_root.resolve() != args.candidate_root.resolve():
        parser.error("The parser pilot must compare both arms against the same optimized Python source")
    import fcntl

    args.baseline_samples = args.candidate_samples = 1
    args.profile = False
    sources = {"baseline": source_identity(args.baseline_root), "candidate": source_identity(args.candidate_root)}
    for root in (args.baseline_root, args.candidate_root):
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=root):
            parser.error("Freeze both source trees clean before collecting timings")
    script_directory = Path(__file__).resolve().parent
    identities = {
        name: hashlib.sha256((script_directory / name).read_bytes()).hexdigest()
        for name in (
            "bench_guard_package_pilot.py",
            "bench_guard_package_local.py",
            "bench_guard_package_matrix.py",
            "package_native_pilot.py",
        )
    }
    artifact = hashlib.sha256(args.native_pilot_binary.read_bytes()).hexdigest() if args.native_pilot_binary else None
    report = {
        "schema": "guard-package-paired-pilot-v1",
        "suite": args.suite,
        "qualification": "shared-host Linux source-route diagnostic; no installed or tail-quantile qualification",
        "sources": sources,
        "harnesses": identities,
        "native_binary_sha256": artifact,
        "method": {
            "repeats": args.repeats,
            "samples_per_arm_process": 1,
            "fresh_process_store_each_arm": True,
            "warmups": 0,
            "order": "alternating AB/BA within each case across repeated blocks",
            "coordination": "shared advisory lock per paired case; unrelated contention remains possible",
            "cpu": "parent process plus all children reaped during the full evaluation",
            "semantics": "all public result fields and all persisted evidence columns; no normalization",
            "native_boundary": (
                "one whole captured lockfile; process startup, request/response copies, "
                "decoding and Python result construction included"
            )
            if args.suite == "native"
            else None,
        },
        "environment": {"python": platform.python_version(), "os": platform.platform(), "machine": platform.machine()},
        "matrix": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    cases = NATIVE_CASES if args.suite == "native" else CORRECTION_CASES
    write_checkpoint(args.output, report)
    for repeat in range(args.repeats):
        for case_index, (dependencies, bundle_size, mode) in enumerate(cases):
            order = ("baseline", "candidate") if (repeat + case_index) % 2 == 0 else ("candidate", "baseline")
            args.allow_native_fallback = dependencies < 10000
            row = {
                "repeat": repeat + 1,
                "dependencies": dependencies,
                "bundle_records": bundle_size,
                "mode": mode,
                "arm_order": list(order),
                "whole_process_cutoff_seconds": args.timeout,
                "expected_native_completions": int(dependencies == 10000) if args.suite == "native" else None,
            }
            with args.measurement_lock.open("a") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                for arm in order:
                    print(
                        json.dumps({"event": "starting", "repeat": repeat + 1, "case": case_index + 1, "arm": arm}),
                        flush=True,
                    )
                    row[arm] = validate_arm_source(
                        run_arm(
                            args,
                            root=args.baseline_root if arm == "baseline" else args.candidate_root,
                            dependencies=dependencies,
                            bundle_size=bundle_size,
                            mode=mode,
                            candidate=arm == "candidate",
                        ),
                        sources[arm],
                    )
                    if row[arm]["status"] == "complete":
                        measurement = row[arm]["measurement"]
                        if measurement["harness_sha256"] != identities["bench_guard_package_local.py"]:
                            row[arm]["status"] = "harness_changed_during_collection"
                        if arm == "candidate" and artifact:
                            native = measurement.get("native_pilot", {})
                            if (
                                native.get("binary_sha256") != artifact
                                or native.get("adapter_sha256") != identities["package_native_pilot.py"]
                            ):
                                row[arm]["status"] = "native_source_changed_during_collection"
                            if native.get("counts", {}).get("native_complete", 0) != row["expected_native_completions"]:
                                row[arm]["status"] = "native_engine_scope_mismatch"
            row["comparison"] = compare_results(row["baseline"], row["candidate"])
            report["matrix"].append(row)
            report["summary"] = summarize(report["matrix"])
            write_checkpoint(args.output, report)
            print(
                json.dumps(
                    {"event": "complete", "repeat": repeat + 1, "case": case_index + 1, "comparison": row["comparison"]}
                ),
                flush=True,
            )
    report["final_sources"] = {
        "baseline": source_identity(args.baseline_root),
        "candidate": source_identity(args.candidate_root),
    }
    report["final_harnesses"] = {
        name: hashlib.sha256((script_directory / name).read_bytes()).hexdigest() for name in identities
    }
    report["final_native_binary_sha256"] = (
        hashlib.sha256(args.native_pilot_binary.read_bytes()).hexdigest() if args.native_pilot_binary else None
    )
    report["source_identity_stable"] = (
        report["final_sources"] == sources
        and report["final_harnesses"] == identities
        and report["final_native_binary_sha256"] == artifact
    )
    write_checkpoint(args.output, report)
    return (
        0
        if report["source_identity_stable"] and all(row["comparison"]["status"] == "equal" for row in report["matrix"])
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
