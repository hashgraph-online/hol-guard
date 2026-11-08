"""Leased Review jobs settle two at a time, in arrival order."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

import pytest

from codex_plugin_scanner.guard.runtime.command_queue_settle_slots import SettleSlots


def _wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.001)


def test_holders_are_admitted_in_arrival_order_two_at_a_time() -> None:
    slots = SettleSlots(2, max_wait_seconds=30)
    admitted: list[int] = []
    lock = threading.Lock()
    releases = [threading.Event() for _ in range(6)]

    def holder(index: int) -> None:
        with slots.hold():
            with lock:
                admitted.append(index)
            releases[index].wait(timeout=10)

    def admitted_count() -> int:
        with lock:
            return len(admitted)

    threads = []
    for index in range(6):
        thread = threading.Thread(target=holder, args=(index,), daemon=True)
        thread.start()
        threads.append(thread)
        # Each holder has its ticket before the next one asks for one.
        _wait_until(lambda index=index: slots._issued > index)

    try:
        _wait_until(lambda: admitted_count() == 2)
        # Both slots are taken; nobody else gets in until one frees.
        time.sleep(0.05)
        assert sorted(admitted) == [0, 1]
        releases[0].set()
        _wait_until(lambda: admitted_count() == 3)
        releases[1].set()
        _wait_until(lambda: admitted_count() == 4)
        time.sleep(0.05)
        assert admitted[2:] == [2, 3]
        releases[2].set()
        releases[3].set()
        _wait_until(lambda: admitted_count() == 6)
        assert sorted(admitted[4:]) == [4, 5]
    finally:
        for release in releases:
            release.set()
        for thread in threads:
            thread.join(timeout=5)


def test_a_stalled_holder_does_not_strand_the_jobs_behind_it() -> None:
    slots = SettleSlots(1, max_wait_seconds=0.1)
    release = threading.Event()
    held = threading.Event()

    def stalled() -> None:
        with slots.hold():
            held.set()
            release.wait(timeout=10)

    thread = threading.Thread(target=stalled)
    thread.start()
    assert held.wait(timeout=5)
    started = time.monotonic()
    with slots.hold():
        waited = time.monotonic() - started
    release.set()
    thread.join(timeout=5)

    assert 0.05 <= waited < 2


def test_slots_must_admit_someone() -> None:
    with pytest.raises(ValueError):
        SettleSlots(0)
