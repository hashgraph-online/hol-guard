"""Bounded retry for retiring the native resident before an update."""

from __future__ import annotations

import time
from collections.abc import Callable

NATIVE_RESIDENT_RETIREMENT_ATTEMPTS = 3
NATIVE_RESIDENT_RETIREMENT_TIMEOUT_SECONDS = 6.0
NATIVE_RESIDENT_RETIREMENT_RETRY_DELAY_SECONDS = 0.5


def retire_with_retry(
    retire: Callable[[float], bool],
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Run one retirement attempt per round until it succeeds or rounds run out.

    Other agent sessions keep using the resident during an update, so one
    attempt can meet a held lease lock, a lease that is still being written,
    or a resident that a hook just started. Retirement is authenticated and
    idempotent, so a short bounded retry is safe and still fails closed.
    Unexpected errors propagate to the caller on the first attempt.
    """

    for attempt in range(NATIVE_RESIDENT_RETIREMENT_ATTEMPTS):
        if attempt:
            sleep(NATIVE_RESIDENT_RETIREMENT_RETRY_DELAY_SECONDS)
        if retire(NATIVE_RESIDENT_RETIREMENT_TIMEOUT_SECONDS):
            return True
    return False
