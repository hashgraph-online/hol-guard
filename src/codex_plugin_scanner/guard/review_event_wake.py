"""Process-local wake hints for the durable Review event outbox."""

from __future__ import annotations

import threading
import weakref
from pathlib import Path
from typing import Protocol


class ReviewEventWake(Protocol):
    """Minimal wake contract used by the sync worker."""

    def generation(self) -> int: ...

    def wait(self, generation: int, timeout: float) -> int: ...


class ReviewEventWakeSignal:
    """Generation-based condition that cannot lose a wake between sync and wait."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._generation = 0
        self._outbox_generation: int | None = None

    def generation(self) -> int:
        with self._condition:
            return self._generation

    def notify(self) -> None:
        with self._condition:
            self._generation += 1
            self._condition.notify_all()

    def notify_if_outbox_changed(self, outbox_generation: int) -> None:
        with self._condition:
            if self._outbox_generation == outbox_generation:
                return
            self._outbox_generation = outbox_generation
            self._generation += 1
            self._condition.notify_all()

    def wait(self, generation: int, timeout: float) -> int:
        with self._condition:
            self._condition.wait_for(lambda: self._generation != generation, timeout=max(timeout, 0.0))
            return self._generation


_SIGNALS_LOCK = threading.Lock()
_SIGNALS: weakref.WeakValueDictionary[str, ReviewEventWakeSignal] = weakref.WeakValueDictionary()


def review_event_wake_signal(database_path: Path) -> ReviewEventWakeSignal:
    """Return the process-local wake signal for one durable store."""
    key = str(database_path.resolve())
    with _SIGNALS_LOCK:
        signal = _SIGNALS.get(key)
        if signal is None:
            signal = ReviewEventWakeSignal()
            _SIGNALS[key] = signal
        return signal


__all__ = [
    "ReviewEventWake",
    "ReviewEventWakeSignal",
    "review_event_wake_signal",
]
