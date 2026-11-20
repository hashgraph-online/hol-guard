"""Prune dead native-resident state: stale ``resident-v3-*`` dirs and dead sockets.

The native runtime owns the proof and the removal (``resident-state-prune``):
an entry goes only when it is provably unowned, and any doubt keeps it.
"""

from __future__ import annotations

import os
from pathlib import Path

OWNER_LOCK_NAME = "managed-resident-owner.v1.lock"

_FEATURE = "native-resident-state-prune-v1"
_COMMAND = "resident-state-prune"
_SCHEMA = "resident-state-prune.v1"
_OUTPUT_LIMIT = 64 * 1024
# The runtime stops itself after 30 seconds of work.
_TIMEOUT_SECONDS = 45.0
_OUTCOMES = frozenset({"ok", "unsupported", "unavailable"})


def probe_owner_lock(directory: Path) -> bool | None:
    """True when the owner flock is free, False when held, None when unknowable.

    A missing lock file is "free": no resident ever took the lock in this dir.
    """

    try:
        import fcntl
    except ImportError:
        return None
    lock_path = directory / OWNER_LOCK_NAME
    try:
        descriptor = os.open(lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return True
    except OSError:
        return None
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError:
            return None
        return True
    finally:
        os.close(descriptor)


def prune_native_runtime(
    guard_home: Path, *, dry_run: bool = False, include_system_sockets: bool = True
) -> dict[str, object] | None:
    """The runtime's prune report, or ``None`` when no runtime answered.

    ``include_system_sockets`` also walks the ``<tmp>/hgr-*`` socket
    directories every Guard home on the account shares.
    """

    from .mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _FEATURE,
        _COMMAND,
        {
            "schema": _SCHEMA,
            "guard_home": str(guard_home.absolute()),
            "dry_run": dry_run,
            "include_system_sockets": include_system_sockets,
        },
        output_limit=_OUTPUT_LIMIT,
        timeout_seconds=_TIMEOUT_SECONDS,
    )
    return answer if answer is not None and _valid_report(answer) else None


def prune_runtime_offered() -> bool:
    """Whether an installed runtime offers the prune, so a missing answer is its failure."""

    from .mdm.runtime_request import runtime_offers

    return runtime_offers(_FEATURE)


def _valid_report(answer: dict[str, object]) -> bool:
    counts = (answer.get("stale_dirs"), answer.get("dead_sockets"))
    lists = (answer.get("removed_dirs"), answer.get("removed_sockets"), answer.get("errors"))
    kept = answer.get("kept")
    return (
        answer.get("outcome") in _OUTCOMES
        and type(answer.get("dry_run")) is bool
        and type(answer.get("budget_exhausted")) is bool
        and all(type(count) is int and count >= 0 for count in counts)
        and all(isinstance(items, list) and all(isinstance(item, str) for item in items) for items in lists)
        and isinstance(kept, dict)
        and all(isinstance(reason, str) and type(count) is int for reason, count in kept.items())
    )


__all__ = ["OWNER_LOCK_NAME", "probe_owner_lock", "prune_native_runtime", "prune_runtime_offered"]
