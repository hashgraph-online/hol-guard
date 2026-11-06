"""Small statistics helpers shared by the warm-path latency measurement scripts."""

from __future__ import annotations

import math
from collections.abc import Sequence


def percentile(values: Sequence[float], q: float) -> float:
    """Return the q-th percentile (0-100) using linear interpolation between ranks."""

    if not values:
        raise ValueError("percentile of an empty sample")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * (q / 100.0)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    fraction = position - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def median(values: Sequence[float]) -> float:
    return percentile(values, 50.0)


def describe(values: Sequence[float]) -> dict[str, float]:
    """Return count, mean and p50/p95/p99 of a latency sample in the sample's own unit."""

    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "mean": sum(values) / len(values),
        "min": min(values),
        "p50": percentile(values, 50.0),
        "p95": percentile(values, 95.0),
        "p99": percentile(values, 99.0),
        "max": max(values),
    }


def spread_ratio(values: Sequence[float]) -> float:
    """Return (max - min) / median, the relative range across repeated runs."""

    if len(values) < 2:
        return 0.0
    centre = median(values)
    return (max(values) - min(values)) / centre if centre > 0 else 0.0
