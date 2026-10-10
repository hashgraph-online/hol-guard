"""Bounded, order-preserving scheduling of independent Gauntlet cases.

The scheduler knows nothing about Guard or Oh My Pi. It starts at most ``jobs`` workers,
collects each result by catalog index, and on any failure or termination signal cancels
and reaps every in-flight worker through handles it started itself (never by name).
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, Protocol, TypeVar

from .fixtures import mkdir_private

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
    """One held host-wide case slot; ``release`` is idempotent and process exit frees it.

    The slot fd is passed to the case worker so the lock outlives a killed runner:
    the kernel frees the flock only when the last fd (parent's and worker's copies)
    is closed, so ``release`` must close but never explicitly unlock.
    """

    def __init__(self, fd: int):
        self._fd: int | None = fd

    @property
    def fd(self) -> int | None:
        """The lease's open file description; the case worker inherits a copy."""
        return self._fd

    def release(self) -> None:
        """Close this copy of the slot fd; an inheriting worker keeps the slot held."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
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
    a slot forever. The pool size lives in ``capacity`` under the slot directory:
    every new requester overwrites it, so the most recently requested count wins
    and holders of slots above a lowered cap simply finish their cases.
    """

    def __init__(self, directory: Path, count: int):
        """Create the private slot directory and publish the shared slot inventory."""
        if os.name != "posix":
            raise ValueError("host slots require a POSIX host")
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_SLOTS:
            raise ValueError(f"host slot count must be an integer from 1 to {MAX_SLOTS}")
        mkdir_private(directory)
        self.directory = directory
        self.count = count
        staging = directory / f".capacity-{os.getpid()}.tmp"
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, f"{count}\n".encode("ascii"))
        finally:
            os.close(fd)
        try:
            os.replace(staging, directory / "capacity")
        except BaseException:
            with suppress(OSError):
                staging.unlink()
            raise

    def _capacity(self) -> int:
        """The most recently requested pool size, or this instance's own count."""
        try:
            value = int((self.directory / "capacity").read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            value = self.count
        return max(1, min(MAX_SLOTS, value))

    def try_acquire(self) -> Lease | None:
        """Take the first free slot below the current capacity, or return None."""
        for index in range(self._capacity()):
            fd = os.open(self.directory / f"slot-{index}.lock", os.O_RDWR | os.O_CREAT, 0o600)
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


class LoadGate:
    """Admit new work only while the host's one-minute load average is within budget.

    Waiting is itself bounded: after ``max_wait`` cumulative seconds spent blocked
    the gate admits unconditionally for the rest of its life, so a persistently
    busy host cannot starve a run forever.
    """

    def __init__(
        self,
        max_load: float,
        *,
        max_wait: float = 180.0,
        clock: Callable[[], float] = time.monotonic,
        load: Callable[[], tuple[float, float, float]] | None = None,
        notify: Callable[[str], None] | None = None,
    ):
        self.max_load = max_load
        self.max_wait = max_wait
        self._clock = clock
        self._load = load or os.getloadavg
        self._notify = notify or (lambda line: print(line, file=sys.stderr, flush=True))
        self._waiting = False
        self._blocked_since: float | None = None
        self._spent = 0.0
        self._exhausted = False

    def __call__(self) -> bool:
        """One notify line per wait episode: when it starts, ends, or hits the budget."""
        if self._exhausted:
            return True
        now = self._clock()
        current = self._load()[0]
        if current <= self.max_load:
            if self._waiting:
                self._spent += now - (self._blocked_since if self._blocked_since is not None else now)
                self._waiting = False
                self._notify(f"gauntlet: host load {current:g} <= {self.max_load:g}; resuming")
            return True
        if not self._waiting:
            self._waiting = True
            self._blocked_since = now
            if self._spent < self.max_wait:
                self._notify(f"gauntlet: waiting for host load {current:g} <= {self.max_load:g}")
        waited = self._spent + now - (self._blocked_since if self._blocked_since is not None else now)
        if waited >= self.max_wait:
            self._exhausted = True
            self._notify(f"gauntlet: host load still {current:g}; waited {waited:g}s, proceeding")
        return self._exhausted


def run_scheduled(
    items: Sequence[T],
    *,
    jobs: int,
    spawn: Callable[[T], CaseWorkerHandle],
    on_complete: Callable[[int, Any], None] | None = None,
    order: Sequence[int] | None = None,
    should_stop: Callable[[int, Any], bool] | None = None,
    admit: Callable[[], bool] | None = None,
    slots: HostSlots | None = None,
    poll_interval: float = 0.2,
    grace: float = CANCEL_GRACE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> list[Any]:
    """Run every item with at most ``jobs`` concurrent workers; results follow input order.

    ``order`` is the spawn order as item indices and must be a permutation of them.
    When ``admit`` is given a worker starts only while it returns true, and when
    ``slots`` is given a worker starts only while a host slot is held, without
    ever blocking the scheduling loop; in that case ``spawn`` is called as
    ``spawn(item, lease)`` so the worker process inherits the lease fd and the
    slot stays held until the child exits. A true ``should_stop`` result stops
    new spawns; in-flight workers finish normally and unrun items come back as
    ``None``.
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
                    if admit is not None and not admit():
                        break
                    lease = slots.try_acquire() if slots is not None else None
                    if slots is not None and lease is None:
                        # Every host slot is held; keep polling workers this tick.
                        break
                    index = pending.popleft()
                    try:
                        with deferred_signals():
                            running[index] = spawn(items[index], lease) if slots is not None else spawn(items[index])
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
                    # Drain: already-running workers finish their own cleanup and
                    # keep complete evidence; only never-started items are skipped.
                    pending.clear()
                if not finished:
                    sleep(poll_interval)
        finally:
            if running:
                cancel_all(list(running.values()), grace=grace, sleep=sleep, clock=clock)
            for lease in leases.values():
                lease.release()
    return [results.get(index) for index in range(len(items))]
