"""Qualification phase timings; measurements never change acceptance outcomes."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class PhaseTimings:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self.seconds: dict[str, float] = {}

    @contextmanager
    def measure(self, phase: str) -> Iterator[None]:
        started = self.clock()
        try:
            yield
        finally:
            self.seconds[phase] = self.seconds.get(phase, 0.0) + self.clock() - started

    def report(self) -> dict[str, float]:
        return {phase: round(seconds, 3) for phase, seconds in self.seconds.items()}
