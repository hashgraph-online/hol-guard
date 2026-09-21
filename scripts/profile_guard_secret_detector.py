#!/usr/bin/env python3
"""Attribute the richer offline detector without changing its public findings."""

from __future__ import annotations

import argparse
import cProfile
import dataclasses
import json
import pstats
import sys
import time
from pathlib import Path

from bench_guard_secret_scans import _source_identity
from secret_scan_benchmark_fixtures import WORKLOADS, _file_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    sys.path.insert(0, str(args.source_root / "src"))
    from codex_plugin_scanner.guard.secrets import secret_detection as detector

    workload = next(case for case in WORKLOADS if case.name == "working_provider_large")
    content = _file_bytes(workload, 0, 0).decode()
    original_rules, original_assignment = detector.SECRET_RULES, detector._ASSIGNMENT
    measured: dict[str, dict[str, float | int]] = {}

    class TimedPattern:
        def __init__(self, name, pattern):
            self.name, self.original = name, pattern
            self.pattern, self.flags = pattern.pattern, pattern.flags

        def finditer(self, text):
            row = measured.setdefault(self.name, {"cpu_seconds": 0.0, "matches": 0})
            started = time.process_time()
            iterator = self.original.finditer(text)
            row["cpu_seconds"] += time.process_time() - started
            while True:
                started = time.process_time()
                try:
                    match = next(iterator)
                except StopIteration:
                    row["cpu_seconds"] += time.process_time() - started
                    return
                row["cpu_seconds"] += time.process_time() - started
                row["matches"] += 1
                yield match

    expected = detector.scan_secret_text(content, path="src/config.ts", max_findings=10000)
    detector.SECRET_RULES = tuple(
        dataclasses.replace(rule, pattern=TimedPattern(rule.rule_id, rule.pattern)) for rule in original_rules
    )
    detector._ASSIGNMENT = TimedPattern("credential-assignment", original_assignment)
    samples = []
    try:
        for _ in range(args.repeats):
            measured.clear()
            start = time.process_time()
            result = detector.scan_secret_text(content, path="src/config.ts", max_findings=10000)
            elapsed = time.process_time() - start
            if result != expected:
                raise RuntimeError("profiling instrumentation changed findings")
            samples.append({"detector_cpu_seconds": elapsed, "regex": dict(measured)})
    finally:
        detector.SECRET_RULES, detector._ASSIGNMENT = original_rules, original_assignment

    profiler = cProfile.Profile(timer=time.process_time)
    profiler.enable()
    result = detector.scan_secret_text(content, path="src/config.ts", max_findings=10000)
    profiler.disable()
    if result != expected:
        raise RuntimeError("profiled findings changed")
    stats = pstats.Stats(profiler)
    top = sorted(stats.stats.items(), key=lambda item: item[1][2], reverse=True)[:25]
    payload = {
        "schema": "guard-offline-detector-profile-v1",
        "source": _source_identity(args.source_root),
        "scope": "one 256KiB ASCII source file; all 17 provider formats, 10 occurrences each",
        "method": (
            "process CPU inside each regex iterator next excludes Python candidate consumers; separate cProfile pass"
        ),
        "interpretation": "attribution diagnostic only, instrumentation adds overhead; not full CLI acceptance",
        "input_bytes": len(content.encode()),
        "detector_findings": len(expected.findings),
        "samples": samples,
        "cprofile_top_self_cpu": [
            {
                "file": Path(key[0]).name,
                "line": key[1],
                "function": key[2],
                "calls": value[1],
                "self_cpu_seconds": value[2],
                "cumulative_cpu_seconds": value[3],
            }
            for key, value in top
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    for sample in samples:
        regex = sum(row["cpu_seconds"] for row in sample["regex"].values())
        print(
            f"detector={sample['detector_cpu_seconds']:.4f}s regex={regex:.4f}s "
            f"share={regex / sample['detector_cpu_seconds']:.1%}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
