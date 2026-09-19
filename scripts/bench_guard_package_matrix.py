#!/usr/bin/env python3
"""Run independent package cardinalities with alternating, serialized source arms.

Each comparison acquires the specified advisory lock. The lock coordinates other
harnesses but cannot exclude unrelated host work; this is diagnostic evidence,
not installed multi-platform qualification. Timeout records remain censored.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def compare_results(baseline: dict, candidate: dict) -> dict:
    if baseline["status"] != "complete" or candidate["status"] != "complete":
        return {"status": "not_comparable"}
    reference, optimized = baseline["measurement"], candidate["measurement"]
    fields = ("corpus_sha256", "semantic_sha256", "complete_result_sha256", "persisted_evidence_sha256")
    parity = {}
    for field in fields:
        a, b = reference[field], optimized[field]
        parity[field] = len(set(a)) == len(set(b)) == 1 and set(a) == set(b) if isinstance(a, list) else a == b
    if not all(parity.values()):
        return {"status": "mismatch", "parity": parity}
    return {
        "status": "equal",
        "parity": parity,
        "median_wall_improvement_percent": 100 * (1 - optimized["wall_median_ms"] / reference["wall_median_ms"]),
        "median_cpu_improvement_percent": 100 * (1 - optimized["cpu_median_ms"] / reference["cpu_median_ms"]),
    }


def observed_phase(stdout: str | bytes | None) -> str:
    if isinstance(stdout, bytes):
        stdout = stdout.decode(errors="replace")
    phase = "process_setup"
    for line in (stdout or "").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("event") in ("measurement_started", "profile_started"):
            phase = event["event"]
    return phase


def run_arm(args, *, root: Path, dependencies: int, bundle_size: int, mode: str, candidate: bool) -> dict:
    harness = Path(__file__).with_name("bench_guard_package_local.py")
    with tempfile.TemporaryDirectory(prefix="guard-package-matrix-") as temporary:
        output = Path(temporary) / "result.json"
        command = [
            sys.executable,
            str(harness),
            "--source-root",
            str(root),
            "--dependencies",
            str(dependencies),
            "--bundle-size",
            str(bundle_size),
            "--mode",
            mode,
            "--samples",
            str(args.candidate_samples if candidate else args.baseline_samples),
            "--output",
            str(output),
        ]
        if candidate and args.profile and mode != "unversioned":
            command.append("--profile")
        if candidate and getattr(args, "native_pilot_binary", None):
            command.extend(["--native-pilot-binary", str(args.native_pilot_binary)])
            if getattr(args, "allow_native_fallback", False):
                command.append("--allow-native-fallback")
        started = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout, check=False)
        except subprocess.TimeoutExpired as error:
            return {
                "status": "censored_whole_process_timeout",
                "whole_process_timeout_seconds": args.timeout,
                "measurement_started": "measurement_started" in str(error.stdout),
                "last_observed_phase": observed_phase(error.stdout),
            }
        elapsed = time.monotonic() - started
        if result.returncode:
            return {
                "status": "harness_error",
                "returncode": result.returncode,
                "error_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
                "whole_process_seconds": elapsed,
                "last_observed_phase": observed_phase(result.stdout),
                **({"diagnostic_measurement": json.loads(output.read_text())} if output.exists() else {}),
            }
        return {"status": "complete", "whole_process_seconds": elapsed, "measurement": json.loads(output.read_text())}


def source_identity(root: Path) -> dict:
    return {
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "source_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "HEAD", "--", "src"], cwd=root)
        ).hexdigest(),
    }


def validate_arm_source(result: dict, expected: dict) -> dict:
    if result["status"] == "complete" and any(
        result["measurement"][field] != value for field, value in expected.items()
    ):
        return {**result, "status": "source_changed_during_collection", "expected_source": expected}
    return result


def write_checkpoint(path: Path, report: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def resume_checkpoint(path: Path, *, expected: dict, cases: list[tuple[int, int, str]]) -> dict:
    report = json.loads(path.read_text())
    if report.get("schema") != expected["schema"] or report.get("harness_sha256") != expected["harness_sha256"]:
        raise ValueError("Checkpoint schema and measurement harness must match")
    for field in ("baseline_samples_per_cell", "candidate_samples_per_cell", "order"):
        if report.get("method", {}).get(field) != expected["method"][field]:
            raise ValueError("Checkpoint sample counts and per-mode order must match")
    rows = report.get("matrix", [])
    if [(row["dependencies"], row["bundle_records"], row["mode"]) for row in rows] != cases[: len(rows)]:
        raise ValueError("Checkpoint must be an ordered prefix of the complete matrix")
    if report.get("sources", expected["sources"]) != expected["sources"]:
        raise ValueError("Checkpoint source commits and changes must match")
    for row in rows:
        for arm in ("baseline", "candidate"):
            if row[arm]["status"] == "complete":
                measurement = row[arm]["measurement"]
                if any(measurement[field] != value for field, value in expected["sources"][arm].items()):
                    raise ValueError("Checkpoint source commits and changes must match")
    report["sources"] = expected["sources"]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--measurement-lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-samples", type=int, default=1)
    parser.add_argument("--candidate-samples", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument(
        "--resume", action="store_true", help="Continue a matching checkpoint without discarding failures"
    )
    args = parser.parse_args()
    if args.baseline_samples < 1 or args.candidate_samples < 1 or args.timeout <= 0:
        parser.error("sample counts and timeout must be positive")
    if args.baseline_samples != args.candidate_samples:
        parser.error("Both arms must use equal sample counts and matching initial/replacement evidence state")
    if os.name != "posix":
        parser.error("This shared-host runner requires POSIX advisory locking")
    import fcntl

    report = {
        "schema": "rsp-package-matrix-v2",
        "qualification": "source-route diagnostic; shared host; no installed or reliable tail-quantile claim",
        "harness_sha256": hashlib.sha256(
            Path(__file__).with_name("bench_guard_package_local.py").read_bytes()
        ).hexdigest(),
        "matrix_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "sources": {
            "baseline": source_identity(args.baseline_root),
            "candidate": source_identity(args.candidate_root),
        },
        "environment": {
            "python": platform.python_version(),
            "os": platform.platform(),
            "machine": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "power_mode": "not exposed by this shared container",
        },
        "method": {
            "baseline_samples_per_cell": args.baseline_samples,
            "candidate_samples_per_cell": args.candidate_samples,
            "order": "order flips within each mode across cardinality cells; both arms use equal counts",
            "coordination": "shared advisory lock per pair; unrelated host contention remains possible",
            "profile": "additional candidate sample, excluded from primary wall/CPU arrays",
            "unversioned": "cached-bundle API diagnostic; production lockfile route resolves exact versions",
            "semantic_scope": (
                "complete public result and all persisted evidence fields for full evaluator routes; "
                "complete cached-bundle decisions without persistence for unversioned batches; no normalization"
            ),
        },
        "matrix": [],
    }
    if Path("/proc/cpuinfo").is_file():
        report["environment"]["cpu_model"] = next(
            (
                line.partition(":")[2].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")
            ),
            "unavailable",
        )
    if Path("/proc/meminfo").is_file():
        report["environment"]["ram_bytes"] = int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1]) * 1024
    args.output.parent.mkdir(parents=True, exist_ok=True)
    cases = list(itertools.product((100, 1000, 10000), (100, 1000, 10000), ("absent", "exact", "unversioned", "deny")))
    if args.resume:
        report = resume_checkpoint(args.output, expected=report, cases=cases)
    report.setdefault("collection_segments", []).append(
        {
            "first_cell": len(report["matrix"]) + 1,
            "whole_process_cutoff_seconds": args.timeout,
            "profile_enabled": args.profile,
            "matrix_runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }
    )
    for index in range(len(report["matrix"]), len(cases)):
        dependencies, bundle_size, mode = cases[index]
        row = {"dependencies": dependencies, "bundle_records": bundle_size, "mode": mode}
        arms = ("baseline", "candidate") if (index // 4 + index % 4) % 2 == 0 else ("candidate", "baseline")
        row["arm_order"] = list(arms)
        row["whole_process_cutoff_seconds"] = args.timeout
        with args.measurement_lock.open("a") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            for arm in arms:
                print(
                    json.dumps(
                        {
                            "event": "started",
                            "cell": index + 1,
                            "arm": arm,
                            "dependencies": dependencies,
                            "bundle_records": bundle_size,
                            "mode": mode,
                        }
                    ),
                    flush=True,
                )
                row[arm] = validate_arm_source(
                    run_arm(
                        args,
                        root=args.candidate_root if arm == "candidate" else args.baseline_root,
                        dependencies=dependencies,
                        bundle_size=bundle_size,
                        mode=mode,
                        candidate=arm == "candidate",
                    ),
                    report["sources"][arm],
                )
        row["comparison"] = compare_results(row["baseline"], row["candidate"])
        report["matrix"].append(row)
        write_checkpoint(args.output, report)
        print(json.dumps({"event": "completed", "cell": index + 1, "comparison": row["comparison"]}), flush=True)
    report["final_source_identities"] = {
        "baseline": source_identity(args.baseline_root),
        "candidate": source_identity(args.candidate_root),
    }
    report["sources_unchanged_at_completion"] = report["final_source_identities"] == report["sources"]
    write_checkpoint(args.output, report)
    return (
        0
        if report["sources_unchanged_at_completion"]
        and all(row["comparison"]["status"] == "equal" for row in report["matrix"])
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
