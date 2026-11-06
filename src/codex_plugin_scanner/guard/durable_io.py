"""Portable durability primitives for atomic local-state updates."""

from __future__ import annotations

import errno
import os
from pathlib import Path

_UNSUPPORTED_DIRECTORY_SYNC_ERRORS = frozenset({errno.EINVAL, errno.ENOTSUP})


def fsync_directory(path: Path) -> None:
    """Flush a directory entry after an atomic rename when the platform supports it.

    Windows does not expose a portable directory descriptor through ``os.open``.
    Some POSIX filesystems reject directory opens or ``fsync`` with EINVAL or
    ENOTSUP; those cases mean the durability primitive is unavailable rather
    than that the update itself failed. All other errors remain visible.
    """

    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if exc.errno in _UNSUPPORTED_DIRECTORY_SYNC_ERRORS:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno not in _UNSUPPORTED_DIRECTORY_SYNC_ERRORS:
                raise
    finally:
        os.close(descriptor)


__all__ = ["fsync_directory"]
