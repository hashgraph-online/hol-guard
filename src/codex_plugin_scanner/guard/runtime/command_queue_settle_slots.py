"""Settle leased Review jobs two at a time, in the order they reached a slot.

A bulk approval hands the main worker and every drain worker a job at once.
Settling one is mostly Python work against the store and the native resident,
so eight settles running together share one interpreter lock and all finish
late: the first approval releases about when the last does. Letting two run
at a time, first come first served, releases the earliest approvals first and
finishes the whole batch sooner, because the settles stop contending with
each other for the interpreter and the resident.

The cap is a scheduling measure, not a safety one. A job that has waited
``MAX_WAIT_SECONDS`` for a slot settles anyway, so a settle that stalls on an
unresponsive resident slows the jobs behind it without stranding them.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager

SETTLE_SLOTS = 2
MAX_WAIT_SECONDS = 5.0


class SettleSlots:
    """At most ``slots`` holders at a time, admitted in arrival order."""

    def __init__(self, slots: int = SETTLE_SLOTS, *, max_wait_seconds: float = MAX_WAIT_SECONDS) -> None:
        if slots < 1:
            raise ValueError("slots must be at least 1")
        self._slots = slots
        self._max_wait_seconds = max_wait_seconds
        self._reset()

    def _reset(self) -> None:
        self._condition = threading.Condition()
        self._waiting: deque[int] = deque()
        self._issued = 0
        self._active = 0

    @contextmanager
    def hold(self) -> Iterator[None]:
        with self._condition:
            ticket = self._issued
            self._issued += 1
            self._waiting.append(ticket)
            deadline = time.monotonic() + self._max_wait_seconds
            while self._active >= self._slots or self._waiting[0] != ticket:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(remaining)
            self._waiting.remove(ticket)
            self._active += 1
            # The next ticket may now be at the head with a slot free.
            self._condition.notify_all()
        try:
            yield
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()


settle_slots = SettleSlots()

if hasattr(os, "register_at_fork"):
    # A child inherits whatever the parent's threads held; none of them exist there.
    os.register_at_fork(after_in_child=settle_slots._reset)


__all__ = ["MAX_WAIT_SECONDS", "SETTLE_SLOTS", "SettleSlots", "settle_slots"]
