#!/usr/bin/env python3
"""Measure Python hook-engine and native one-shot PostToolUse latency.

This benchmark uses synthetic data only. It deliberately reports the backend
and process boundary so in-process Python numbers are not mistaken for
end-to-end adapter latency.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * percentile))
    return ordered[index]


def _native_request(size: int) -> bytes:
    text = "const value = 1;\n" * max(1, size // 17)
    payload = {
        "protocol_version": 1,
        "request_id": "benchmark",
        "harness": "claude-code",
        "event_name": "PostToolUse",
        "payload": {"tool_response": [{"type": "text", "text": text}]},
        "cwd": None,
        "home_dir": "/tmp",
        "guard_home": "/tmp/hol-guard-bench",
        "source_ref_external_allowed": False,
        "observe_mode": False,
        "deadline_budget_ms": 9000,
    }
    return json.dumps(payload, separators=(",", ":")).encode()


def bench_native(binary: Path, payload: bytes, iterations: int) -> list[float]:
    latencies: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        completed = subprocess.run(
            [str(binary), "hook", "--stdin"],
            input=payload,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))
        latencies.append((time.perf_counter() - started) * 1000)
    return latencies


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-binary", type=Path, required=True)
    parser.add_argument("--size", type=int, default=1024)
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    payload = _native_request(args.size)
    latencies = bench_native(args.native_binary.resolve(), payload, args.iterations)
    result = {
        "backend": "native-oneshot",
        "boundary": "subprocess",
        "payload_bytes": len(payload),
        "iterations": len(latencies),
        "p50_ms": round(statistics.median(latencies), 3),
        "p95_ms": round(_percentile(latencies, 0.95), 3),
        "p99_ms": round(_percentile(latencies, 0.99), 3),
        "max_ms": round(max(latencies), 3),
    }
    print(json.dumps(result, indent=2))
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
