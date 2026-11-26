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
keeps an ACK it holds a shared lock on a file named for that ACK's generation;
the kernel drops it when the process exits, which lets a new publisher tell an
ACK its writer left behind from a live one.

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


_LIVENESS_SUFFIX = ".live"


def _liveness_path(ack_path: Path, generation: int) -> Path:
    return ack_path.with_name(f".{ack_path.name}.{generation}{_LIVENESS_SUFFIX}")


def _written_generation(ack_path: Path) -> int | None:
    """The generation the ACK on disk names, or None when it names none."""

    descriptor = os.open(ack_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        text = handle.read(_MAX_ACK_BYTES + 1)
    try:
        ack = json.loads(text) if len(text) <= _MAX_ACK_BYTES else None
    except ValueError:
        return None
    generation = ack.get("generation") if isinstance(ack, dict) else None
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        return None
    return generation


def hold_liveness(ack_path: Path, generation: int) -> int:
    """Take the shared liveness lock for `generation` and return its descriptor.

    Each generation has its own lock file, so a publisher that keeps an older
    one alive says nothing about whether the writer of the current ACK is.
    """

    import fcntl

    descriptor = os.open(
        _liveness_path(ack_path, generation),
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _held(lock_path: Path) -> bool:
    import fcntl

    try:
        descriptor = os.open(lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(descriptor)
    return False


def writer_alive(ack_path: Path) -> bool:
    """Whether the process that wrote the ACK on disk still holds its lock.

    Raises FileNotFoundError when there is no ACK. One that names no
    generation has no writer to keep it.
    """

    generation = _written_generation(ack_path)
    return generation is not None and _held(_liveness_path(ack_path, generation))


def prune_liveness(ack_path: Path) -> None:
    """Remove the lock files no live publisher holds.

    Callers hold the ACK file lock, as every publisher does before it opens a
    lock file, so none can be removed between its open and its lock.
    """

    prefix = f".{ack_path.name}."
    for entry in ack_path.parent.iterdir():
        name = entry.name
        if not (name.startswith(prefix) and name.endswith(_LIVENESS_SUFFIX)):
            continue
        if not name[len(prefix) : -len(_LIVENESS_SUFFIX)].isdigit():
            continue
        try:
            if not _held(entry):
                entry.unlink()
        except FileNotFoundError:
            continue
