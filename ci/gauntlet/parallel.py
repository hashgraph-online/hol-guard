"""Bounded, order-preserving scheduling of independent Gauntlet cases.

The scheduler knows nothing about Guard or Oh My Pi. It starts at most ``jobs`` workers,
collects each result by catalog index, and on any failure or termination signal cancels
and reaps every in-flight worker through handles it started itself (never by name).
"""

from __future__ import annotations

import signal
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from typing import Any, Protocol, TypeVar

MAX_JOBS = 8
CANCEL_GRACE_SECONDS = 90.0

T = TypeVar("T")


class CaseWorkerHandle(Protocol):
    """One started worker owned by the scheduler."""

    def poll(self) -> int | None: ...

    def collect(self) -> Any:
        """Return the finished worker's result or raise if it did not produce one."""

    def terminate(self) -> None:
        """Ask the worker to unwind its own cleanup."""

    def kill(self) -> None:
        """Forcibly end and reap the worker's own process group."""


def validate_jobs(jobs: int) -> int:
    """Bound concurrency; provider rate limits are the reason for the ceiling."""
    if isinstance(jobs, bool) or not isinstance(jobs, int) or not 1 <= jobs <= MAX_JOBS:
        raise ValueError(f"--jobs must be an integer from 1 to {MAX_JOBS}")
    return jobs


@contextmanager
def terminate_as_exit() -> Iterator[None]:
    """Turn SIGTERM/SIGHUP into SystemExit so every finally block and reaper runs."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def _exit(number: int, _frame: Any) -> None:
        raise SystemExit(128 + number)

    names = [getattr(signal, name) for name in ("SIGTERM", "SIGHUP") if hasattr(signal, name)]
    previous = {number: signal.signal(number, _exit) for number in names}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


@contextmanager
def deferred_signals() -> Iterator[None]:
    """Hold interrupts until a started worker is registered for cleanup.

    Children spawned inside this block inherit the blocked mask across exec, so the
    case worker unblocks these signals itself at startup (see ``case_worker.main``).
    """
    if not hasattr(signal, "pthread_sigmask") or threading.current_thread() is not threading.main_thread():
        yield
        return
    names = [getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name)]
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, names)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def cancel_all(
    running: Sequence[CaseWorkerHandle],
    *,
    grace: float = CANCEL_GRACE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Request cooperative cleanup from every worker, then force-reap survivors.

    A signal that interrupts the grace wait still reaches the final kill, and the kill
    itself runs with interrupts held so a second Ctrl-C cannot strand a worker group.
    """
    try:
        for handle in running:
            with suppress(Exception):
                handle.terminate()
        deadline = clock() + grace
        while clock() < deadline and any(handle.poll() is None for handle in running):
            sleep(0.1)
    finally:
        with deferred_signals():
            for handle in running:
                with suppress(Exception):
                    handle.kill()


def run_scheduled(
    items: Sequence[T],
    *,
    jobs: int,
    spawn: Callable[[T], CaseWorkerHandle],
    on_complete: Callable[[int, Any], None] | None = None,
    poll_interval: float = 0.2,
    grace: float = CANCEL_GRACE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> list[Any]:
    """Run every item with at most ``jobs`` concurrent workers; results follow input order."""
    validate_jobs(jobs)
    pending = deque(enumerate(items))
    running: dict[int, CaseWorkerHandle] = {}
    results: dict[int, Any] = {}
    with terminate_as_exit():
        try:
            while pending or running:
                while pending and len(running) < jobs:
                    index, item = pending.popleft()
                    with deferred_signals():
                        running[index] = spawn(item)
                finished = [index for index, handle in running.items() if handle.poll() is not None]
                for index in finished:
                    handle = running.pop(index)
                    results[index] = handle.collect()
                    if on_complete is not None:
                        on_complete(index, results[index])
                if not finished:
                    sleep(poll_interval)
        finally:
            if running:
                cancel_all(list(running.values()), grace=grace, sleep=sleep, clock=clock)
    return [results[index] for index in range(len(items))]
