"""Bounded cross-process lock for protected machine-state mutations."""

from __future__ import annotations

import os
import platform
import stat
import time
from collections.abc import Generator
from contextlib import contextmanager

from .contracts import MachinePaths

_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_RETRY_SECONDS = 0.05


def _lock_owner_is_trusted(metadata: os.stat_result) -> bool:
    return platform.system() == "Windows" or metadata.st_uid == 0


@contextmanager
def protected_machine_state_lock(paths: MachinePaths, name: str) -> Generator[None, None, None]:
    if not name or any(character not in "abcdefghijklmnopqrstuvwxyz-" for character in name):
        raise ValueError("machine_state_lock_name_invalid")
    paths.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_metadata = paths.state_root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise PermissionError("machine_state_root_invalid")
    paths.state_root.chmod(0o700)
    lock_path = paths.state_root / f".{name}.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    acquired = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (
            os.name != "nt" and (metadata.st_mode & 0o077 or not _lock_owner_is_trusted(metadata))
        ):
            raise PermissionError("machine_state_lock_invalid")
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while True:
            try:
                if platform.system() == "Windows":
                    import msvcrt

                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise TimeoutError("machine_state_lock_timeout") from exc
                time.sleep(_LOCK_RETRY_SECONDS)
        yield
    finally:
        if acquired:
            if platform.system() == "Windows":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


__all__ = ["protected_machine_state_lock"]
