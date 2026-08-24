"""In-process wake notifications for the durable Review outbox."""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

_LOCK = threading.Lock()
_CALLBACKS: dict[int, Callable[[], None]] = {}
_SIGNAL_FILENAME = "review-outbox-wake"


def review_event_outbox_signal_token(store: object) -> tuple[int, int, int] | None:
    """Read the cross-process outbox generation without opening Guard storage."""

    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        return None
    try:
        metadata = (guard_home / _SIGNAL_FILENAME).lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode):
        return None
    return metadata.st_ino, metadata.st_size, metadata.st_mtime_ns


def _advance_cross_process_signal(store: object) -> None:
    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path):
        return
    signal_path = guard_home / _SIGNAL_FILENAME
    if review_event_outbox_signal_token(store) is not None:
        return
    descriptor: int | None = None
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(signal_path, flags, 0o600)
    except FileExistsError:
        return
    except OSError:
        return
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def consume_review_event_outbox_signal(store: object) -> bool:
    """Claim pending cross-process work before querying the durable outbox."""

    guard_home = getattr(store, "guard_home", None)
    if not isinstance(guard_home, Path) or review_event_outbox_signal_token(store) is None:
        return False
    try:
        (guard_home / _SIGNAL_FILENAME).unlink()
    except OSError:
        return False
    return True


def register_review_event_outbox_wake_callback(
    store: object,
    callback: Callable[[], None],
) -> Callable[[], None]:
    """Register one process-local callback and return its safe unsubscriber."""

    key = id(store)
    with _LOCK:
        _CALLBACKS[key] = callback

    def unregister() -> None:
        with _LOCK:
            if _CALLBACKS.get(key) is callback:
                _ = _CALLBACKS.pop(key, None)

    return unregister


def notify_review_event_outbox_wake(store: object) -> None:
    _advance_cross_process_signal(store)
    with _LOCK:
        callback = _CALLBACKS.get(id(store))
    if callback is not None:
        callback()
