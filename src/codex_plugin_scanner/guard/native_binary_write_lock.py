"""Windows read handles that deny every writer of a hashed native binary.

Windows lets the owner of a file rewrite its timestamps, so size and times
cannot prove that a binary is unchanged since it was hashed. A handle opened
without ``FILE_SHARE_WRITE`` can: while it stays open the kernel refuses every
open that could change the file's data, and the open itself fails if any
writer (or writable mapping) already exists. Renames and deletes stay allowed
so updates are never blocked; they give the path a different file ID, which
the caller compares on every lookup.

A lock is returned only after a write open of the same path is refused with a
sharing violation, which proves that the filesystem enforces the share mode.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ENABLED = sys.platform == "win32"

_GENERIC_READ = 0x80000000
_FILE_WRITE_DATA = 0x0002
_FILE_SHARE_READ = 0x0001
_FILE_SHARE_WRITE = 0x0002
_FILE_SHARE_DELETE = 0x0004
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_ERROR_SHARING_VIOLATION = 32


if sys.platform == "win32":
    import _winapi
    import msvcrt

    def _create_file(path: Path, access: int, share: int, flags: int) -> int:
        return int(_winapi.CreateFile(str(path), access, share, 0, _OPEN_EXISTING, flags, 0))

    def _close_handle(handle: int) -> None:
        _winapi.CloseHandle(handle)

    def _descriptor_for_handle(handle: int) -> int:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)

else:

    def _create_file(path: Path, access: int, share: int, flags: int) -> int:
        raise OSError("native_binary_write_lock_unsupported")

    def _close_handle(handle: int) -> None:
        return None

    def _descriptor_for_handle(handle: int) -> int:
        raise OSError("native_binary_write_lock_unsupported")


def _writers_are_refused(path: Path) -> bool:
    """True only when a write open of ``path`` fails with a sharing violation."""

    try:
        handle = _create_file(
            path,
            _FILE_WRITE_DATA,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            _FILE_FLAG_OPEN_REPARSE_POINT,
        )
    except OSError as error:
        return getattr(error, "winerror", None) == _ERROR_SHARING_VIOLATION
    _close_handle(handle)
    return False


def open_write_locked(path: Path) -> int | None:
    """Open ``path`` for reading while no writer can exist; ``None`` otherwise.

    The returned descriptor must stay open for as long as the caller relies on
    the file being unchanged, and is closed with ``os.close``. Symlinks and
    other reparse points are opened as themselves, never followed.
    """

    if not _ENABLED:
        return None
    try:
        handle = _create_file(
            path,
            _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_DELETE,
            _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
        )
    except OSError:
        return None
    try:
        descriptor = _descriptor_for_handle(handle)
    except OSError:
        _close_handle(handle)
        return None
    if not _writers_are_refused(path):
        os.close(descriptor)
        return None
    return descriptor


__all__ = ("open_write_locked",)
