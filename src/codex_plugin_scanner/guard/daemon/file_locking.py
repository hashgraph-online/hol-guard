"""Cross-platform file locking primitives for daemon lifecycle state."""

from __future__ import annotations

import os
import time
from typing import BinaryIO


def lock_daemon_file(handle: BinaryIO, *, poll_interval: float = 0.1) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                time.sleep(poll_interval)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def try_lock_daemon_file(handle: BinaryIO) -> bool:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


__all__ = ["lock_daemon_file", "try_lock_daemon_file"]
