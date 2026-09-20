#!/usr/bin/env python3
"""Measure actual local legacy pool components; this is not daemon qualification.

Run under the shared performance-measurement.lock. The fresh worker processes
use the installed editable interpreter and production spawn/containment code.
SessionStart exercises the isolated request protocol, not approval reevaluation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def process_rows():
    import psutil

    rows = []
    for process in psutil.Process().children(recursive=True):
        try:
            with process.oneshot():
                cpu = process.cpu_times()
                rows.append(
                    {
                        "pid": process.pid,
                        "ppid": process.ppid(),
                        "name": process.name(),
                        "rss_bytes": process.memory_info().rss,
                        "cpu_seconds": cpu.user + cpu.system,
                        "resource_tracker": "multiprocessing.resource_tracker" in " ".join(process.cmdline()),
                    }
                )
        except psutil.NoSuchProcess:
            continue
    return rows


def run_sample(workers: int, sample: int):
    from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner

    with tempfile.TemporaryDirectory(prefix="hol-pool-component-") as directory:
        root = Path(directory)
        runner = HookProcessRunner(guard_home=root, process_limit=workers, timeout_seconds=2.8)
        started = time.perf_counter()
        try:
            runner.start()
            startup_seconds = time.perf_counter() - started
            ready_stats = runner.stats()
            ready_rows = process_rows()
            if ready_stats["ready"] != workers:
                return {
                    "sample": sample,
                    "workers_requested": workers,
                    "startup_seconds": startup_seconds,
                    "status": "worker_readiness_failed",
                    "stats": ready_stats,
                }
            idle_started = time.perf_counter()
            time.sleep(1.0)
            idle_seconds = time.perf_counter() - idle_started
            idle_rows = process_rows()
            requests = []
            # Queue ordering means the first N requests initialize N evaluators.
            for request_index in range(workers + 10):
                request_started = time.perf_counter()
                review = runner.review(
                    payload={"hook_event_name": "SessionStart"},
                    harness="pi",
                    home_dir=root,
                    guard_home=root,
                    workspace=root,
                    hook_env={},
                )
                requests.append(
                    {
                        "request_index": request_index,
                        "cold_evaluator": request_index < workers,
                        "seconds": time.perf_counter() - request_started,
                        "reason_code": review.reason_code,
                        "payload_received": review.payload is not None,
                        "payload": review.payload,
                    }
                )
            after_requests = process_rows()
            after_stats = runner.stats()
        finally:
            closing = time.perf_counter()
            contained = runner.close_contained()
            close_seconds = time.perf_counter() - closing
        ready_cpu = {row["pid"]: row["cpu_seconds"] for row in ready_rows}
        idle_cpu_seconds = sum(
            max(0.0, row["cpu_seconds"] - ready_cpu.get(row["pid"], row["cpu_seconds"])) for row in idle_rows
        )
        return {
            "sample": sample,
            "workers_requested": workers,
            "status": "measured" if contained and all(row["payload_received"] for row in requests) else "failed",
            "startup_seconds": startup_seconds,
            "idle_observation_seconds": idle_seconds,
            "idle_child_cpu_seconds": idle_cpu_seconds,
            "ready_stats": ready_stats,
            "ready_children": ready_rows,
            "after_request_children": after_requests,
            "after_request_stats": after_stats,
            "requests": requests,
            "close_seconds": close_seconds,
            "contained": contained,
            "remaining_children": process_rows(),
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.samples <= 20:
        parser.error("samples must be between 1 and 20")
    root = Path(__file__).resolve().parents[1]
    sources = (
        "src/codex_plugin_scanner/guard/daemon/hook_process_runner.py",
        "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py",
        "src/codex_plugin_scanner/guard/daemon/hook_process_capacity.py",
    )
    report = {
        "schema": "guard.legacy-pool-component-profile.v1",
        "scope": "local spawned pool, SessionStart protocol, no HTTP or approval qualification",
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "python": sys.version,
        "platform": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources},
        "samples": [],
    }
    for sample in range(args.samples):
        for workers in (1, 2):
            row = run_sample(workers, sample)
            report["samples"].append(row)
            print(
                json.dumps({key: row[key] for key in ("sample", "workers_requested", "status", "startup_seconds")}),
                flush=True,
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
