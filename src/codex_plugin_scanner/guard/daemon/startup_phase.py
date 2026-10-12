"""Bounded startup phase timing for the local Guard daemon.

A slow daemon start on a cold host is otherwise a single opaque interval. Each
phase records one ``startup_phase`` diagnostic carrying its elapsed milliseconds
so the frozen packaging tests and operators can see which phase was slow. The
records are diagnostic only; no decision reads them.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Final

PhaseSink = Callable[[str, str], object]

_MAX_PENDING: Final = 32
_FIRST_IMPORT_MONOTONIC: Final = time.monotonic()
_lock = threading.Lock()
_pending: list[tuple[str, int]] = []
_default_sink: PhaseSink | None = None


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _detail(name: str, elapsed_ms: int) -> str:
    return f"phase={name} elapsed_ms={elapsed_ms} since_first_import_ms={_elapsed_ms(_FIRST_IMPORT_MONOTONIC)}"


def _emit(name: str, elapsed: int, sink: PhaseSink | None) -> None:
    sink = sink or _default_sink
    if sink is not None:
        sink("startup_phase", _detail(name, elapsed))
        return
    with _lock:
        if len(_pending) < _MAX_PENDING:
            _pending.append((_detail(name, elapsed), elapsed))


@contextmanager
def timed_phase(name: str, sink: PhaseSink | None = None) -> Iterator[None]:
    """Time the enclosed block; buffer the record until a sink exists."""

    started = time.monotonic()
    try:
        yield
    finally:
        _emit(name, _elapsed_ms(started), sink)


def record_phase_since(name: str, started_monotonic: float) -> None:
    """Record a phase whose block cannot be wrapped in ``timed_phase``."""

    _emit(name, _elapsed_ms(started_monotonic), None)


def flush_pending_phases(sink: PhaseSink) -> None:
    """Emit the phases buffered before the daemon diagnostics existed.

    The sink also becomes the default for phases timed without an explicit sink.
    """

    global _default_sink
    with _lock:
        _default_sink = sink
        pending = list(_pending)
        _pending.clear()
    for detail, _elapsed in pending:
        sink("startup_phase", detail)


def release_default_sink(sink: PhaseSink) -> None:
    """Stop routing phases to ``sink`` once its diagnostics have closed.

    A newer daemon's sink is left alone, so later early phases buffer for it.
    """

    global _default_sink
    with _lock:
        if _default_sink == sink:
            _default_sink = None


__all__ = ["PhaseSink", "flush_pending_phases", "record_phase_since", "release_default_sink", "timed_phase"]
