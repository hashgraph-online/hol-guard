"""Serialize Guard-owned OpenCode config readers and writers.

OpenCode and external editors do not participate in this advisory protocol.
Byte comparisons detect their earlier edits, but cannot protect the final
comparison-to-replacement window against an uncooperative writer.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ..daemon.file_locking import try_lock_daemon_file
from ..mdm.file_lock import release_file_lock


@contextmanager
def opencode_config_lock(home_dir: Path, *, timeout: float = 5.0) -> Iterator[None]:
    """Use one home-scoped coordination point, independent of config locations.

    Lock before reading configs; retain the lock through writes and rollback.
    All Guard writers use this same path on every platform, including Windows.
    """
    path = home_dir / ".config" / "opencode" / ".hol-guard-config.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("OpenCode config lock must not be a symlink")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        info = os.fstat(handle.fileno())
        opened_path = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or not stat.S_ISREG(opened_path.st_mode)
            or getattr(opened_path, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or (info.st_dev, info.st_ino) != (opened_path.st_dev, opened_path.st_ino)
            or info.st_nlink != 1
        ):
            raise ValueError("OpenCode config lock path changed or is not a regular file without hard-link aliases")
        if os.name != "nt" and info.st_uid != os.geteuid():
            raise ValueError("OpenCode config lock must be owned by the current user on POSIX")
        deadline = time.monotonic() + timeout
        while not try_lock_daemon_file(handle):
            if time.monotonic() >= deadline:
                raise TimeoutError("Another Guard operation is updating OpenCode config; try again shortly")
            time.sleep(0.05)
        try:
            yield
        finally:
            release_file_lock(handle)
