#!/usr/bin/env python3
"""Source-checkout diagnostic for the added review fence and binding components.

This does not measure installed hooks, resident IPC, SQL, approval consumption,
or tool execution. Coordinate the shared host before taking its advisory lock.
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import re
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from codex_plugin_scanner.guard.daemon.hook_native_review_binding import native_review_policy_binding  # noqa: E402
from codex_plugin_scanner.guard.daemon.hook_native_review_fence import native_review_fence  # noqa: E402
from tests.test_native_review_policy_binding import _bound_edge  # noqa: E402


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    rank = (len(ordered) - 1) * fraction
    low = int(rank)
    return ordered[low] + (ordered[min(low + 1, len(ordered) - 1)] - ordered[low]) * (rank - low)


def _measure(operation: Callable[[], object], count: int) -> dict[str, int | float]:
    for _ in range(200):
        operation()
    values: list[float] = []
    for _ in range(count):
        started = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - started) / 1000)
    return {
        "count": len(values),
        "p50_us": statistics.median(values),
        "p95_us": _percentile(values, 0.95),
        "p99_us": _percentile(values, 0.99),
        "max_us": max(values),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--coordination-lock", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--samples", type=int, default=2000)
    args = parser.parse_args()
    if not 1 <= args.samples <= 100_000 or re.fullmatch(r"[a-f0-9]{7,40}", args.source_commit) is None:
        parser.error("invalid sample count or source commit")
    if sys.platform == "win32":
        parser.error("this component diagnostic uses a POSIX host coordination lock")
    import fcntl

    edge = _bound_edge()
    with args.coordination_lock.open("a+b") as marker:
        fcntl.flock(marker.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            deadline = time.monotonic() + 60

            def fence(bound: bool) -> None:
                with native_review_fence(
                    policy_snapshot={"command_extensions_bound": True} if bound else {},
                    event_name="PreToolUse",
                    recording_only=False,
                    guard_home=home,
                    deadline=deadline,
                ):
                    pass

            def binding() -> object:
                return native_review_policy_binding(
                    harness="cursor", native_result=edge["result"], verified_receipt=edge["receipt"]
                )

            def combined() -> None:
                with native_review_fence(
                    policy_snapshot={"command_extensions_bound": True},
                    event_name="PreToolUse",
                    recording_only=False,
                    guard_home=home,
                    deadline=deadline,
                ):
                    binding()

            fence(True)  # Initialize the retained private lock before warm measurements.
            result = {
                "schema": "hol-guard.native-review-fence-component.v1",
                "source_commit": args.source_commit,
                "python": platform.python_version(),
                "system": platform.system(),
                "machine": platform.machine(),
                "gc_enabled": gc.isenabled(),
                "clock": "perf_counter_ns",
                "fixture": "typed_native_review_observation",
                "unbound_context": _measure(lambda: fence(False), args.samples),
                "warm_shared_fence": _measure(lambda: fence(True), args.samples),
                "verified_review_binding": _measure(binding, args.samples),
                "fence_and_binding": _measure(combined, args.samples),
            }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
