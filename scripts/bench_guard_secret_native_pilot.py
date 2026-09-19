#!/usr/bin/env python3
"""Qualify the explicit regex pilot through the real richer Secrets CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import statistics
import sys
import tempfile
import time
from pathlib import Path

from bench_guard_secret_scans import (
    _cli_contracts,
    _digest,
    _full_cli,
    _measurement_block,
    _qualify_detector,
    _source_identity,
    _summary,
    _utc_now,
)
from secret_scan_benchmark_cache import prepare_cache
from secret_scan_benchmark_fixtures import WORKLOADS, create_fixture


class CacheUnavailableError(RuntimeError):
    pass


def prepare_fixture_cache(target, state):
    try:
        return prepare_cache(target, state)
    except (OSError, RuntimeError) as error:
        raise CacheUnavailableError(type(error).__name__) from error


def _p95(values):
    return sorted(values)[max(0, math.ceil(len(values) * 0.95) - 1)]


def comparison(groups):
    baseline, native = groups["optimized_python"], groups["native_regex_pilot"]
    wall = ([row["full_cli_wall_ms"] for row in baseline], [row["full_cli_wall_ms"] for row in native])
    cpu = (
        [row["full_cli_process_tree_cpu_ms"] for row in baseline],
        [row["full_cli_process_tree_cpu_ms"] for row in native],
    )
    ratios = {
        "p95_wall_ratio": _p95(wall[1]) / _p95(wall[0]),
        "mean_process_tree_cpu_ratio": statistics.mean(cpu[1]) / statistics.mean(cpu[0]),
    }
    rng = random.Random(739)
    boots = {name: [] for name in ratios}
    for _ in range(2000):
        indices = [rng.randrange(len(baseline)) for _ in baseline]
        boots["p95_wall_ratio"].append(_p95([wall[1][i] for i in indices]) / _p95([wall[0][i] for i in indices]))
        boots["mean_process_tree_cpu_ratio"].append(
            statistics.mean(cpu[1][i] for i in indices) / statistics.mean(cpu[0][i] for i in indices)
        )
    intervals = {key: [sorted(values)[50], sorted(values)[1949]] for key, values in boots.items()}

    def gate(wall_ratio, cpu_ratio):
        return (wall_ratio <= 0.70 and cpu_ratio <= 1.05) or (cpu_ratio <= 0.70 and wall_ratio <= 1.05)

    return {
        **ratios,
        "paired_bootstrap_95pct_intervals": intervals,
        "point_threshold_passed": gate(ratios["p95_wall_ratio"], ratios["mean_process_tree_cpu_ratio"]),
        "conservative_interval_threshold_passed": gate(
            intervals["p95_wall_ratio"][1], intervals["mean_process_tree_cpu_ratio"][1]
        ),
        "qualification": "local Linux source CLI pilot; installed/platform release gates remain separate",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--native-pilot-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--measurement-lock", type=Path)
    parser.add_argument("--environment-note", default="No executable-backing intervention declared by caller")
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument(
        "--case", action="append", choices=[item.name for item in WORKLOADS if item.workflow != "plugin"]
    )
    parser.add_argument("--cache-state", action="append", choices=("prewarmed", "evicted", "uncontrolled"))
    args = parser.parse_args()
    if not 5 <= args.repeats <= 100:
        parser.error("--repeats must be between 5 and 100")
    args.source_root = args.source_root.resolve()
    args.native_pilot_binary = args.native_pilot_binary.resolve()
    sys.path.insert(0, str(args.source_root / "src"))
    from secret_scan_native_pilot import install

    def identities():
        scripts = [
            "secret_scan_native_pilot.py",
            "secret_scan_benchmark_fixtures.py",
            "secret_scan_benchmark_cache.py",
            "bench_guard_secret_scans.py",
            "bench_guard_secret_native_pilot.py",
        ]
        digest = hashlib.sha256()
        for name in scripts:
            digest.update(name.encode() + b"\0" + (Path(__file__).parent / name).read_bytes())
        native_source = hashlib.sha256()
        for relative in [
            "rust/Cargo.lock",
            "rust/crates/guard-offline-regex-pilot/Cargo.toml",
            "rust/crates/guard-offline-regex-pilot/src/main.rs",
        ]:
            native_source.update(relative.encode() + b"\0" + (args.source_root / relative).read_bytes())
        return {
            "python": _source_identity(args.source_root),
            "bridge_and_runner_sha256": digest.hexdigest(),
            "native_source_sha256": native_source.hexdigest(),
            "native_binary_sha256": hashlib.sha256(args.native_pilot_binary.read_bytes()).hexdigest(),
        }

    source = identities()
    rows, contracts = [], {}
    with _measurement_block(args.measurement_lock):
        expected = _qualify_detector()
        installed = install(args.native_pilot_binary)
        try:
            actual = _qualify_detector()
            if actual != expected:
                raise RuntimeError("native pilot differs from independent detector/HMAC oracle")
            detector_contracts = {"expected": expected, "pilot": actual, "boundary_use": dict(installed.client.stats)}
        finally:
            installed.close()
    report = {
        "schema": "guard-offline-regex-pilot-benchmark.v1",
        "run_complete": False,
        "run_started_utc": _utc_now(),
        "sources": source,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
            "native_executable_resolved_path": str(args.native_pilot_binary),
            "native_executable_device": args.native_pilot_binary.stat().st_dev,
            "environment_note": args.environment_note,
        },
        "method": {
            "repeats": args.repeats,
            "order": "alternating paired arms per workload/state",
            "boundary": "fresh Python source CLI + lazily started persistent Rust child, JSON input/span output",
            "measurement_lock_scope": "workload/state",
            "cpu": "complete reaped process tree",
            "p95": "nearest rank",
            "interval": "2000 paired bootstrap resamples, seed739, central95%",
            "cache_scope": "fixture regular-file data only; code/dentry/metadata caches uncontrolled",
            "native_scope": "ASCII text <=4MiB per logical file; Python owns findings and unsupported text",
            "activation": "benchmark-only explicit bridge; no installed CLI or default native routing",
        },
        "detector_contracts": detector_contracts,
        "cli_contracts": contracts,
        "cases": rows,
    }

    def checkpoint(complete=False):
        report["run_complete"] = complete
        report["checkpoint_utc"] = _utc_now()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pending = args.output.with_suffix(args.output.suffix + ".partial")
        pending.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        pending.replace(args.output)

    checkpoint()
    cases = [item for item in WORKLOADS if item.workflow != "plugin" and (not args.case or item.name in args.case)]
    states = list(dict.fromkeys(args.cache_state or ["prewarmed", "evicted"]))
    with tempfile.TemporaryDirectory(prefix="guard-regex-pilot-") as directory:
        for case in cases:
            target = Path(directory) / case.name
            # Keep fixture creation outside measured samples, but serialize its IO.
            print(f"{_utc_now()} {case.name}: fixture/contracts waiting for measurement lock", flush=True)
            with _measurement_block(args.measurement_lock):
                print(f"{_utc_now()} {case.name}: fixture/contracts acquired measurement lock", flush=True)
                dimensions = create_fixture(target, case)
                key = case.workflow + ("_findings" if case.content != "safe" else "_clean")
                key += "_large" if case.files >= 500 or case.content in {"dense", "catalog"} else "_small"
                if key not in contracts:
                    oracle = _cli_contracts(
                        args.source_root, target, case.workflow, has_findings=case.content != "safe"
                    )
                    candidate = _cli_contracts(
                        args.source_root,
                        target,
                        case.workflow,
                        has_findings=case.content != "safe",
                        native_pilot_binary=args.native_pilot_binary,
                    )
                    if oracle != candidate:
                        raise RuntimeError("native pilot changes CLI coverage/default bound/exit contracts")
                    contracts[key] = {"optimized_python": oracle, "native_regex_pilot": candidate}
                checkpoint()
            print(f"{_utc_now()} {case.name}: fixture/contracts released measurement lock", flush=True)
            time.sleep(0.1)
            for state in states:
                print(f"{_utc_now()} {case.name}: {state} waiting for measurement lock", flush=True)
                with _measurement_block(args.measurement_lock):
                    started_utc = _utc_now()
                    print(f"{started_utc} {case.name}: {state} starting", flush=True)
                    groups = {"optimized_python": [], "native_regex_pilot": []}
                    active_attempt = {}
                    expected_digest = None
                    expected_findings = (
                        dimensions["file_occurrences"]
                        * ({"safe": 0, "providers": 1, "catalog": 17, "dense": 170}[case.content])
                    )
                    try:
                        cache = prepare_fixture_cache(target, state)
                        for repeat in range(args.repeats):
                            for name in list(groups) if repeat % 2 == 0 else list(reversed(groups)):
                                active_attempt = {"arm": name, "pair": repeat + 1, "started_utc": _utc_now()}
                                prepare_fixture_cache(target, state)
                                sample, public = _full_cli(
                                    args.source_root,
                                    target,
                                    case.workflow,
                                    extra_args=("--fail-on-findings",),
                                    expected_exit=3 if case.content != "safe" else 0,
                                    native_pilot_binary=args.native_pilot_binary
                                    if name == "native_regex_pilot"
                                    else None,
                                )
                                digest = _digest(public)
                                if expected_digest is None:
                                    expected_digest = digest
                                if digest != expected_digest:
                                    raise RuntimeError("native pilot changed the complete public CLI result")
                                if (
                                    public["files_scanned"] != dimensions["file_occurrences"]
                                    or public["bytes_scanned"] != dimensions["file_occurrences"] * case.size
                                    or public["finding_count"] != expected_findings
                                    or public["truncated"]
                                    or public["errors"]
                                ):
                                    raise RuntimeError("CLI lost complete file/byte coverage")
                                if name == "native_regex_pilot" and (
                                    sample["native_pilot_native_files"] < 1
                                    or sample["native_pilot_python_fallback_files"] != 0
                                ):
                                    raise RuntimeError("ASCII fixture did not exercise the declared native boundary")
                                sample["bytes_per_second"] = public["bytes_scanned"] / (
                                    sample["full_cli_wall_ms"] / 1000
                                )
                                sample["finding_count"] = public["finding_count"]
                                groups[name].append(sample)
                    except CacheUnavailableError as error:
                        rows.append(
                            {
                                "case": case.name,
                                "cache_state": state,
                                "status": "cache-unavailable",
                                "reason": str(error),
                                "samples": groups,
                                "state_started_utc": started_utc,
                                "state_finished_utc": _utc_now(),
                            }
                        )
                    except Exception as error:
                        rows.append(
                            {
                                "case": case.name,
                                "cache_state": state,
                                "status": "failed",
                                "samples": groups,
                                "state_started_utc": started_utc,
                                "state_finished_utc": _utc_now(),
                                "failed_attempt": {
                                    **active_attempt,
                                    "exception_type": type(error).__name__,
                                    "command_evidence": getattr(error, "evidence", None),
                                },
                            }
                        )
                        checkpoint()
                        raise
                    else:
                        rows.append(
                            {
                                "case": case.name,
                                "cache_state": state,
                                "cache": cache,
                                "dimensions": dimensions,
                                "status": "equivalent",
                                "samples": groups,
                                "statistics": {name: _summary(group) for name, group in groups.items()},
                                "comparison": comparison(groups),
                                "state_started_utc": started_utc,
                                "state_finished_utc": _utc_now(),
                            }
                        )
                    checkpoint()
                    print(f"{_utc_now()} {case.name}: {state} {rows[-1]['status']}", flush=True)
                print(f"{_utc_now()} {case.name}: {state} released measurement lock", flush=True)
                time.sleep(0.1)
    if identities() != source:
        raise RuntimeError("pilot code or binary changed during comparison")
    checkpoint(complete=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
