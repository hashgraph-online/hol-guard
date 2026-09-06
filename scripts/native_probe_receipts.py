"""Wait for native decision receipts before daemon shutdown expires them."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import cast


def receipt_corpus_is_complete(stats: Mapping[str, object], *, expected: int) -> bool:
    """Return true when every accepted receipt has been processed or dropped."""

    return (
        stats.get("receipt_accepted") == expected
        and stats.get("receipt_processed") == expected
        and stats.get("receipt_dropped") == 0
        and stats.get("receipt_durable_pending") == 0
    )


def wait_for_receipt_corpus(
    writer: object,
    *,
    expected: int,
    timeout_seconds: float = 5.0,
) -> Mapping[str, object]:
    """Poll evidence-writer stats until the corpus is durable or the budget expires."""

    stats_fn = getattr(writer, "stats", None)
    if not callable(stats_fn):
        raise RuntimeError("native_default_auto_probe_failed: evidence writer has no stats()")
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    stats = cast(object, stats_fn())
    if not isinstance(stats, Mapping):
        raise RuntimeError(f"native_default_auto_probe_failed: invalid evidence stats: {stats}")
    current = cast(Mapping[str, object], stats)
    while time.monotonic() < deadline:
        if receipt_corpus_is_complete(current, expected=expected):
            return current
        time.sleep(0.05)
        stats = cast(object, stats_fn())
        if not isinstance(stats, Mapping):
            raise RuntimeError(f"native_default_auto_probe_failed: invalid evidence stats: {stats}")
        current = cast(Mapping[str, object], stats)
    return current


def wait_for_route_corpus(
    metrics: object,
    *,
    expected: int,
    timeout_seconds: float = 5.0,
) -> Mapping[str, object]:
    """Observe completed route accounting before changing modes or inspecting counts.

    An installed hook response can reach the caller before its serving thread
    finishes route bookkeeping. This wait is outside the measured policy-readiness
    budget. Wrong routes and incomplete counts remain visible to the probe's exact
    assertions; reaching a count is not itself proof of correct routing.
    """
    if expected < 1:
        raise ValueError("Expected route count must be positive")
    snapshot_fn = getattr(metrics, "snapshot", None)
    if not callable(snapshot_fn):
        raise RuntimeError("native_default_auto_probe_failed: route recorder has no snapshot()")
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        snapshot = cast(object, snapshot_fn())
        if not isinstance(snapshot, Mapping):
            raise RuntimeError("native_default_auto_probe_failed: invalid route metric snapshot")
        current = cast(Mapping[str, object], snapshot)
        routes = current.get("routes")
        if not isinstance(routes, Mapping):
            raise RuntimeError("native_default_auto_probe_failed: invalid route metric inventory")
        values = tuple(routes.values())
        if any(type(value) is not int or value < 0 for value in values):
            raise RuntimeError("native_default_auto_probe_failed: invalid route metric count")
        if sum(cast(tuple[int, ...], values)) >= expected or time.monotonic() >= deadline:
            return current
        time.sleep(0.05)
