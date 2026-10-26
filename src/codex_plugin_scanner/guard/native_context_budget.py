"""The digest budget a one-shot lifecycle command runs under.

The steady-state budget keeps enforcement cheap because enforcement runs on
every tool call and can afford to degrade.  A lifecycle command cannot: it runs
once, at a keystroke, and a digest it cannot get aborts the install and leaves
the machine unprotected.  It is also the one call that pays for a
never-before-run binary — a first install on Windows faults in and scans a
20 MB executable that no later call pays for again, which is why a tester saw
an install fail on native identity and the identical second run succeed.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any

# Lifecycle commands bind this floor so that spawn has room; it stays under the
# resident's own 9 s ceiling so the retry still has a budget to carry.
_LIFECYCLE_TIMEOUT_SECONDS = 5.0
_BOUND_TIMEOUT_FLOOR: ContextVar[float | None] = ContextVar("guard_context_digest_timeout_floor", default=None)


def bind_context_digest_lifecycle_budget(active: bool = True) -> Any:
    """Bind the digest budget a one-shot lifecycle command runs under.

    The floor applies to every digest call made under it, including the ones
    that pin the steady-state constant themselves: a command that installs or
    reports protection has no hot path to protect, and no fallback when the
    answer does not arrive.  The returned token belongs to the caller, which
    resets it once that command is done; nothing else in the process may run
    enforcement on a lifecycle command's floor.
    """

    return _BOUND_TIMEOUT_FLOOR.set(_LIFECYCLE_TIMEOUT_SECONDS if active else None)


def reset_context_digest_budget(token: Any) -> None:
    _BOUND_TIMEOUT_FLOOR.reset(token)


def context_digest_timeout_floor() -> float | None:
    """The floor a bound lifecycle command put on every digest call under it."""

    return _BOUND_TIMEOUT_FLOOR.get()


__all__ = [
    "bind_context_digest_lifecycle_budget",
    "context_digest_timeout_floor",
    "reset_context_digest_budget",
]
