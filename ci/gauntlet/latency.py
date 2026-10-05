"""Summarize observed hook round trips, including unsuccessful attempts."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def _distribution(samples: list[float]) -> dict[str, Any]:
    ordered = sorted(samples)
    result: dict[str, Any] = {"samples": len(ordered)}
    for label, percentile in (("p50_ms", 0.5), ("p90_ms", 0.9), ("p95_ms", 0.95), ("p99_ms", 0.99)):
        result[label] = round(ordered[math.ceil(len(ordered) * percentile) - 1], 3) if ordered else None
    result["max_ms"] = round(ordered[-1], 3) if ordered else None
    result["mean_ms"] = round(sum(ordered) / len(ordered), 3) if ordered else None
    return result


def summarize_hook_latency(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Use nearest-rank percentiles; missing timing is never treated as zero.

    These are host-observed HTTP round trips through response-body completion,
    not inference time or full process startup. Small samples expose their count.
    """
    samples: list[float] = []
    groups: dict[str, list[float]] = defaultdict(list)
    missing = failed = 0
    for row in observations:
        failed += bool(row.get("observer_error") or row.get("transport_error") or row.get("http_status") != 200)
        elapsed = row.get("elapsed_ms")
        if type(elapsed) not in {int, float} or not math.isfinite(elapsed) or elapsed < 0:
            missing += 1
            continue
        samples.append(float(elapsed))
        event = row.get("event")
        group = event if event in {"PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"} else "other"
        groups[group].append(float(elapsed))
    return {
        "method": "nearest-rank",
        "scope": "hook-http-round-trip",
        **_distribution(samples),
        "missing_samples": missing,
        "failed_attempts": failed,
        "by_event": {event: _distribution(values) for event, values in sorted(groups.items())},
    }
