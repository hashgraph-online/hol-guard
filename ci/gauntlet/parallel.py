"""Bounded, order-preserving scheduling of independent Gauntlet cases.

The scheduler knows nothing about Guard or Oh My Pi. It starts at most ``jobs`` workers,
collects each result by catalog index, and on any failure or termination signal cancels
and reaps every in-flight worker through handles it started itself (never by name).
"""

from __future__ import annotations

import os
import signal
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, Protocol, TypeVar

if os.name == "posix":
    import fcntl

MAX_JOBS = 8
MAX_SLOTS = 64
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


class Lease:
    """One held host-wide case slot; ``release`` is idempotent and process exit frees it."""

    def __init__(self, fd: int):
        self._fd: int | None = fd

    def release(self) -> None:
        """Unlock and close the slot file exactly once."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        with suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(fd)

    def __enter__(self) -> Lease:
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


class HostSlots:
    """A host-wide cap on running cases shared by every Gauntlet process (POSIX only).

    One ``slot-<i>.lock`` file per slot is ``flock``'d for the life of a case worker;
    the kernel frees the lease when the holder's process dies, so crashes cannot pin
    a slot forever.
    """

    def __init__(self, directory: Path, count: int):
        """Create the private slot directory and bound the shared slot inventory."""
        if os.name != "posix":
            raise ValueError("host slots require a POSIX host")
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_SLOTS:
            raise ValueError(f"host slot count must be an integer from 1 to {MAX_SLOTS}")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = directory
        self.paths = tuple(directory / f"slot-{index}.lock" for index in range(count))

    def try_acquire(self) -> Lease | None:
        """Take the first free slot without blocking, or return None."""
        for path in self.paths:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                continue
            except BaseException:
                os.close(fd)
                raise
            return Lease(fd)
        return None

    def acquire(self, *, sleep: Callable[[float], None] = time.sleep, poll: float = 0.5) -> Lease:
        """Wait until another holder frees a slot; the caller owns the lease."""
        while (lease := self.try_acquire()) is None:
            sleep(poll)
        return lease


def run_scheduled(
    items: Sequence[T],
    *,
    jobs: int,
    spawn: Callable[[T], CaseWorkerHandle],
    on_complete: Callable[[int, Any], None] | None = None,
    order: Sequence[int] | None = None,
    should_stop: Callable[[int, Any], bool] | None = None,
    slots: HostSlots | None = None,
    poll_interval: float = 0.2,
    grace: float = CANCEL_GRACE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> list[Any]:
    """Run every item with at most ``jobs`` concurrent workers; results follow input order.

    ``order`` is the spawn order as item indices and must be a permutation of them.
    When ``slots`` is given a worker starts only while a host slot is held, without
    ever blocking the scheduling loop. A true ``should_stop`` result ends scheduling
    and cancels in-flight workers; unrun items come back as ``None``.
    """
    validate_jobs(jobs)
    if order is None:
        order = range(len(items))
    elif sorted(order) != list(range(len(items))):
        raise ValueError("order must be a permutation of the item indices")
    pending = deque(order)
    running: dict[int, CaseWorkerHandle] = {}
    leases: dict[int, Lease] = {}
    results: dict[int, Any] = {}
    with terminate_as_exit():
        try:
            stop = False
            while pending or running:
                while pending and len(running) < jobs:
                    lease = slots.try_acquire() if slots is not None else None
                    if slots is not None and lease is None:
                        # Every host slot is held; keep polling workers this tick.
                        break
                    index = pending.popleft()
                    try:
                        with deferred_signals():
                            running[index] = spawn(items[index])
                    except BaseException:
                        if lease is not None:
                            lease.release()
                        raise
                    if lease is not None:
                        leases[index] = lease
                finished = [index for index, handle in running.items() if handle.poll() is not None]
                for index in finished:
                    handle = running.pop(index)
                    results[index] = handle.collect()
                    if (lease := leases.pop(index, None)) is not None:
                        lease.release()
                    if on_complete is not None:
                        on_complete(index, results[index])
                    if should_stop is not None and should_stop(index, results[index]):
                        stop = True
                if stop:
                    break
                if not finished:
                    sleep(poll_interval)
        finally:
            if running:
                cancel_all(list(running.values()), grace=grace, sleep=sleep, clock=clock)
            for lease in leases.values():
                lease.release()
    return [results.get(index) for index in range(len(items))]
