"""Bounded caller clocks; they never change the lifecycle acceptance deadline."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping
from typing import cast

CLOCK_BOUNDARIES = frozenset(
    {
        "setup_ack_return",
        "replacement_enter",
        "replacement_return",
        "store_constructor_enter",
        "store_constructor_return",
        "server_constructor_enter",
        "server_constructor_return",
        "cold_registrations_return",
        "expiry_enter",
        "expiry_return",
        "publisher_start_enter",
        "publisher_start_return",
        "daemon_start_enter",
        "daemon_start_return",
        "recovered_ack_enter",
        "recovered_ack_return",
    }
)


class LifecycleClocks:
    """Record each fixed boundary at most once in the calling thread."""

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._started = self._clock()
        self.boundaries: dict[str, float] = {}

    def mark(self, name: str) -> None:
        if name not in CLOCK_BOUNDARIES or name in self.boundaries:
            raise ValueError("workspace lifecycle clock boundary invalid")
        self.boundaries[name] = (self._clock() - self._started) * 1000

    def report(self) -> dict[str, object]:
        return {
            "origin": "lifecycle_cell_entry_monotonic",
            "scope": "instrumented_caller_boundaries",
            "acceptance_deadline_changed": False,
            "boundaries_ms": dict(self.boundaries),
        }


def valid_lifecycle_clocks(value: object) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "origin",
        "scope",
        "acceptance_deadline_changed",
        "boundaries_ms",
    }:
        return False
    boundaries = value["boundaries_ms"]
    if (
        value["origin"] != "lifecycle_cell_entry_monotonic"
        or value["scope"] != "instrumented_caller_boundaries"
        or value["acceptance_deadline_changed"] is not False
        or not isinstance(boundaries, Mapping)
        or not set(boundaries) <= CLOCK_BOUNDARIES
    ):
        return False
    for item in boundaries.values():
        if type(item) not in (int, float):
            return False
        number = cast(int | float, item)
        if not math.isfinite(number) or not 0 <= number < 2**63:
            return False
    measured = cast(Mapping[str, int | float], boundaries)
    return all(
        measured[name] <= measured[name.removesuffix("_enter") + "_return"]
        for name in measured
        if name.endswith("_enter") and name.removesuffix("_enter") + "_return" in measured
    )
