"""Bounded, aggregate-only resident RSS baseline stabilization."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import cast

from scripts.native_slo_adapter import process_rss_bytes

RSS_PLATEAU_SAMPLE_COUNT = 3
RSS_PLATEAU_TOLERANCE = 0.02
RSS_BASELINE_TIMEOUT_SECONDS = 30.0
RSS_SAMPLE_INTERVAL_SECONDS = 0.1


@dataclass(frozen=True, slots=True)
class WorkerCapacity:
    """Aggregate worker state observed after one bounded capacity wave."""

    target: int
    workers: int
    ready: int
    busy: int


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(f"native_installed_slo_failed: {reason}")


def _worker_capacity(value: object) -> WorkerCapacity:
    if not isinstance(value, Mapping):
        raise RuntimeError("native_installed_slo_failed: worker capacity was unavailable")
    values = tuple(value.get(name) for name in ("target", "workers", "ready", "busy"))
    _require(
        all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in values),
        "worker capacity report was invalid",
    )
    target, workers, ready, busy = cast(tuple[int, int, int, int], values)
    return WorkerCapacity(target, workers, ready, busy)


def _is_full_capacity(capacity: WorkerCapacity, expected_workers: int) -> bool:
    return (
        capacity.target == expected_workers
        and capacity.workers == expected_workers
        and capacity.ready == expected_workers
        and capacity.busy == 0
    )


def _same_worker_counts(previous: WorkerCapacity, current: WorkerCapacity) -> bool:
    return (
        previous.target == current.target
        and previous.workers == current.workers
        and previous.ready == current.ready
        and previous.busy == current.busy
    )


def _rss_is_plateau(samples: Sequence[int], *, tolerance: float) -> bool:
    if len(samples) < RSS_PLATEAU_SAMPLE_COUNT:
        return False
    highest = max(samples)
    lowest = min(samples)
    return highest - lowest <= max(1, int(highest * tolerance))


def steady_state_rss_baseline(
    run_capacity_wave: Callable[[], tuple[Sequence[object], int]],
    *,
    sample_capacity: Callable[[], object],
    sample_rss: Callable[[], int] = process_rss_bytes,
    expected_warmup_count: int,
    timeout_seconds: float = RSS_BASELINE_TIMEOUT_SECONDS,
    interval_seconds: float = RSS_SAMPLE_INTERVAL_SECONDS,
    plateau_sample_count: int = RSS_PLATEAU_SAMPLE_COUNT,
    plateau_tolerance: float = RSS_PLATEAU_TOLERANCE,
) -> int:
    """Warm bounded capacity waves until worker counts and RSS both plateau.

    Each callback is bounded by its caller's request timeout. The wall-clock
    deadline makes an unavailable worker report, a leaking pool, or a noisy
    RSS process fail closed instead of silently choosing an early baseline.
    """

    _require(expected_warmup_count > 0, "resident pool warmup count was invalid")
    _require(timeout_seconds > 0, "RSS baseline timeout was invalid")
    _require(interval_seconds >= 0, "RSS sample interval was invalid")
    _require(plateau_sample_count >= 2, "RSS plateau sample count was invalid")
    _require(0 <= plateau_tolerance <= 0.1, "RSS plateau tolerance was invalid")
    _require(
        plateau_sample_count == RSS_PLATEAU_SAMPLE_COUNT,
        "RSS plateau sample count must remain the reviewed bounded count",
    )
    initial = _worker_capacity(sample_capacity())
    _require(
        _is_full_capacity(initial, expected_warmup_count),
        "resident worker capacity was not full before RSS baseline",
    )
    deadline = time.monotonic() + timeout_seconds
    previous = initial
    samples: list[int] = []
    while time.monotonic() < deadline:
        observations, errors = run_capacity_wave()
        _require(errors == 0, "resident capacity wave returned request errors")
        _require(
            len(observations) == expected_warmup_count,
            "resident capacity wave did not complete every request",
        )
        current = _worker_capacity(sample_capacity())
        _require(_is_full_capacity(current, expected_warmup_count), "worker capacity changed during RSS baseline")
        rss = sample_rss()
        _require(isinstance(rss, int) and not isinstance(rss, bool) and rss > 0, "resident RSS sample was unavailable")
        if _same_worker_counts(previous, current):
            samples.append(rss)
        else:
            samples = [rss]
        previous = current
        if len(samples) >= plateau_sample_count and _rss_is_plateau(
            samples[-plateau_sample_count:], tolerance=plateau_tolerance
        ):
            return max(samples[-plateau_sample_count:])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval_seconds, remaining))
    raise RuntimeError("native_installed_slo_failed: resident RSS did not reach a bounded plateau before 30 seconds")


__all__ = [
    "RSS_BASELINE_TIMEOUT_SECONDS",
    "RSS_PLATEAU_SAMPLE_COUNT",
    "RSS_PLATEAU_TOLERANCE",
    "RSS_SAMPLE_INTERVAL_SECONDS",
    "WorkerCapacity",
    "steady_state_rss_baseline",
]
