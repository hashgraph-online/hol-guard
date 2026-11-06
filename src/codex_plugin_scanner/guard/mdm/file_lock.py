"""Cross-platform non-blocking file lock primitives for MDM state."""

from __future__ import annotations

import os
from typing import BinaryIO


def acquire_file_lock(handle: BinaryIO) -> None:
    """Acquire one byte-range lock on Windows or an exclusive flock on POSIX."""

    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        if not handle.read(1):
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def release_file_lock(handle: BinaryIO) -> None:
    """Release a lock acquired by :func:`acquire_file_lock`."""

    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


__all__ = ["acquire_file_lock", "release_file_lock"]
