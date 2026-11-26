"""Keep the direct-lane ACK with the newest acknowledged publication.

More than one daemon process can hold a policy publisher for the same Guard
home, and they share one ACK file. The resident binds the newest generation
pushed to it and defers every direct hook whose ACK names another, so a
publisher that keeps renewing an older generation shuts the lane for every
harness each time its renewal lands. A publisher writes the ACK only after the
resident acknowledged its generation, so once the file names a newer one, the
older publisher stops renewing and leaves the file to the newer one.

Request and hook processes run publishers of their own beside the daemon's,
so each publisher withdraws only the ACK it wrote. While a POSIX publisher
keeps an ACK it holds a shared liveness lock; the kernel drops it when the
process exits, which lets a new publisher tell a leftover ACK from a live one.

This only decides whether to keep a lease alive. The resident still checks the
ACK's generation and digest against its own binding before any direct use.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

_MAX_ACK_BYTES = 4096


def renewable(ack_path: Path, target: tuple[int, str] | None) -> bool:
    """Whether the lease for `target` may be renewed.

    A missing or unreadable ACK keeps the lease renewing as before.
    """

    if target is None:
        return False
    try:
        descriptor = os.open(ack_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            text = handle.read(_MAX_ACK_BYTES + 1)
        ack = json.loads(text) if len(text) <= _MAX_ACK_BYTES else None
    except (OSError, ValueError):
        return True
    written = ack.get("generation") if isinstance(ack, dict) else None
    if isinstance(written, bool) or not isinstance(written, int):
        return True
    return written <= target[0]


def names_target(ack_path: Path, target: tuple[int, str]) -> bool:
    """Whether the ACK on disk is the one written for `target`.

    A publisher withdraws only its own ACK. A missing or malformed file names
    nothing. An unreadable one counts as this publisher's, so a failed read
    never leaves its ACK behind.
    """

    try:
        descriptor = os.open(ack_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            text = handle.read(_MAX_ACK_BYTES + 1)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    try:
        ack = json.loads(text) if len(text) <= _MAX_ACK_BYTES else None
    except ValueError:
        return False
    if not isinstance(ack, dict):
        return False
    generation = ack.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int):
        return False
    return (generation, ack.get("policy_digest")) == target


def _liveness_path(ack_path: Path) -> Path:
    return ack_path.with_name(f".{ack_path.name}.live")


def hold_liveness(ack_path: Path) -> int:
    """Take the shared liveness lock and return the descriptor that holds it."""

    import fcntl

    descriptor = os.open(
        _liveness_path(ack_path),
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def liveness_held(ack_path: Path) -> bool:
    """Whether a live publisher holds the liveness lock for `ack_path`."""

    import fcntl

    try:
        descriptor = os.open(
            _liveness_path(ack_path),
            os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(descriptor)
    return False
