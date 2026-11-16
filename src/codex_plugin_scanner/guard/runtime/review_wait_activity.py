"""Whether an agent in this process is waiting on a Cloud Review decision.

A hook waiting on a pending approval reads it again at least once a second, so
a read within the last few seconds means an agent is still paused. The command
queue worker uses this to retry quickly after a network failure: its error
backoff grows to thirty seconds, and a decision made while the device was
offline would otherwise reach the agent up to that long after the connection
returns, when the agent may already have stopped waiting.
"""

from __future__ import annotations

import time
from collections.abc import Callable

RECENT_REVIEW_WAIT_SECONDS = 5.0

_last_wait_at: float | None = None


def note_review_wait(*, monotonic: Callable[[], float] = time.monotonic) -> None:
    global _last_wait_at
    _last_wait_at = monotonic()


def review_wait_recent(*, monotonic: Callable[[], float] = time.monotonic) -> bool:
    last = _last_wait_at
    return last is not None and monotonic() - last <= RECENT_REVIEW_WAIT_SECONDS


__all__ = ["RECENT_REVIEW_WAIT_SECONDS", "note_review_wait", "review_wait_recent"]
