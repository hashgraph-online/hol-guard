"""Leased Review jobs settle two at a time, in arrival order."""

from __future__ import annotations

import threading
import time

import pytest

from codex_plugin_scanner.guard.runtime.command_queue_settle_slots import SettleSlots


def _run_holders(slots: SettleSlots, count: int, *, hold_seconds: float) -> tuple[list[int], int]:
    order: list[int] = []
    peak = 0
    active = 0
    lock = threading.Lock()

    def holder(index: int) -> None:
        nonlocal peak, active
        with slots.hold():
            with lock:
                order.append(index)
                active += 1
                peak = max(peak, active)
            time.sleep(hold_seconds)
            with lock:
                active -= 1

    threads = []
    for index in range(count):
        thread = threading.Thread(target=holder, args=(index,))
        thread.start()
        threads.append(thread)
        # Each holder reaches the slots before the next one starts.
        time.sleep(0.01)
    for thread in threads:
        thread.join(timeout=10)
    return order, peak


def test_holders_are_admitted_in_arrival_order_two_at_a_time() -> None:
    order, peak = _run_holders(SettleSlots(2, max_wait_seconds=10), 8, hold_seconds=0.05)

    assert order == list(range(8))
    assert peak == 2


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
