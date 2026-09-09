"""Serialize local settings transactions and publish complete config snapshots."""

from __future__ import annotations

import errno
import os
import stat
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import BinaryIO, ParamSpec, TypeVar

from .durable_io import fsync_directory
from .mdm.file_lock import acquire_file_lock, release_file_lock

_P = ParamSpec("_P")
_T = TypeVar("_T")
_LOCK_TIMEOUT_SECONDS = 5.0
_LOCK_RETRY_SECONDS = 0.025


def _validate_lock_file(path: Path, descriptor: int) -> None:
    opened = os.fstat(descriptor)
    named = path.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        or (os.name != "nt" and (opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) & 0o077))
    ):
        raise ValueError("The local settings lock is not a private regular file.")


def _acquire_settings_lock(handle: BinaryIO) -> None:
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    while True:
        try:
            acquire_file_lock(handle)
            return
        except OSError as error:
            if error.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise
            if time.monotonic() >= deadline:
                raise ValueError("Another settings change is still saving. Reload settings and try again.") from error
            time.sleep(_LOCK_RETRY_SECONDS)


@contextmanager
def settings_write_lock(guard_home: Path) -> Iterator[None]:
    """Hold one stable lock inode across the complete read/validate/write transaction."""
    guard_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = guard_home / ".settings-write.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "r+b") as handle:
        _validate_lock_file(path, handle.fileno())
        _acquire_settings_lock(handle)
        try:
            # A replaced path must not let this writer use an orphaned lock inode.
            _validate_lock_file(path, handle.fileno())
            yield
        finally:
            release_file_lock(handle)
    # Keep this inode in place so existing waiters and new writers share the lock.


def serialize_guard_settings(
    operation: Callable[_P, _T],
) -> Callable[_P, _T]:
    """Apply one transaction boundary to each config read-modify-write entry point."""

    @wraps(operation)
    def serialized(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        guard_home = kwargs.get("guard_home", args[0] if args else None)
        if not isinstance(guard_home, Path):
            raise TypeError("Settings writes require a local Guard home path.")
        with settings_write_lock(guard_home):
            return operation(*args, **kwargs)

    return serialized


def atomic_write_settings(path: Path, content: str) -> None:
    """Readers see either the old complete config or the new complete config."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("The local settings file must not be a symbolic link.")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".config-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
        fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
