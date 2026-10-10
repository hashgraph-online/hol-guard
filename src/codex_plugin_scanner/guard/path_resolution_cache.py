"""Short-lived canonical-path memo guarded by filesystem identity.

Hook admission canonicalizes the same few directories (workspace, Guard home,
state directory, temporary roots) on every request. Each canonicalization walks
every path component. A remembered spelling is reused only while the path still
stats to the same device and inode and is younger than the lifetime below, so
a swapped, replaced or removed directory is always resolved again.
"""

from __future__ import annotations

import os
import threading
import time

_RESOLUTION_LIFETIME_SECONDS = 1.0
_MAX_REMEMBERED_PATHS = 512
_lock = threading.Lock()
_remembered: dict[tuple[str, bool], tuple[int, int, float, str]] = {}


def cached_realpath(path: str, *, strict: bool = False) -> str:
    """``os.path.realpath`` that skips the component walk for a recently seen directory."""

    key = (path, strict)
    try:
        identity = os.stat(path)
    except (OSError, ValueError):
        return os.path.realpath(path, strict=strict)
    now = time.monotonic()
    with _lock:
        remembered = _remembered.get(key)
    if (
        remembered is not None
        and remembered[0] == identity.st_dev
        and remembered[1] == identity.st_ino
        and now - remembered[2] < _RESOLUTION_LIFETIME_SECONDS
    ):
        return remembered[3]
    resolved = os.path.realpath(path, strict=strict)
    with _lock:
        if len(_remembered) >= _MAX_REMEMBERED_PATHS:
            _remembered.clear()
        _remembered[key] = (identity.st_dev, identity.st_ino, now, resolved)
    return resolved


def clear_cached_realpaths() -> None:
    with _lock:
        _remembered.clear()
