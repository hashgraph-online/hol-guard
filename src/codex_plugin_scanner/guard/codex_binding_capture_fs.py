"""Descriptor relative creation of the private v2 capture marker."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import cast

from .codex_binding_capture_crypto import (
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_RECORDS,
    CaptureSession,
    encode_marker,
    new_capture_session,
)

_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600


def _owner_uid() -> int | None:
    getuid = cast(Callable[[], int] | None, getattr(os, "getuid", None))
    if not callable(getuid):
        return None
    try:
        return int(getuid())
    except (OSError, TypeError, ValueError):
        return None


def _private_directory(fd: int) -> bool:
    try:
        metadata = os.fstat(fd)
    except OSError:
        return False
    uid = _owner_uid()
    return (
        uid is not None
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == uid
        and stat.S_IMODE(metadata.st_mode) == _PRIVATE_DIRECTORY_MODE
    )


def _private_regular(fd: int) -> bool:
    try:
        metadata = os.fstat(fd)
    except OSError:
        return False
    uid = _owner_uid()
    return (
        uid is not None
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == uid
        and stat.S_IMODE(metadata.st_mode) == _PRIVATE_FILE_MODE
        and metadata.st_nlink == 1
    )


def _open_private_guard_home(guard_home: Path) -> int | None:
    supports_dir_fd = cast(set[object], getattr(os, "supports_dir_fd", cast(set[object], set())))
    if (
        not guard_home.is_absolute()
        or ".." in guard_home.parts
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in supports_dir_fd
    ):
        return None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(guard_home.anchor, flags)
        for component in guard_home.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if not _private_directory(descriptor):
            os.close(descriptor)
            return None
        return descriptor
    except (OSError, TypeError):
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        return None


def _open_or_create_diagnostics(guard_descriptor: int, directory_name: str) -> int | None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            descriptor = os.open(directory_name, flags, dir_fd=guard_descriptor)
        except FileNotFoundError:
            os.mkdir(directory_name, _PRIVATE_DIRECTORY_MODE, dir_fd=guard_descriptor)
            descriptor = os.open(directory_name, flags, dir_fd=guard_descriptor)
    except (OSError, TypeError):
        return None
    if not _private_directory(descriptor):
        with suppress(OSError):
            os.close(descriptor)
        return None
    return descriptor


def initialize_private_capture_marker(
    guard_home: Path,
    *,
    directory_name: str,
    marker_name: str,
    run_id: str,
    expires_at: int,
    max_records: int = MAX_CAPTURE_RECORDS,
    max_bytes: int = MAX_CAPTURE_BYTES,
) -> CaptureSession | None:
    """Create one marker using already-existing, verified private directories."""

    session = new_capture_session(
        run_id,
        expires_at=expires_at,
        max_records=max_records,
        max_bytes=max_bytes,
    )
    if session is None:
        return None
    encoded = encode_marker(session)
    if encoded is None:
        return None
    guard_descriptor = _open_private_guard_home(guard_home)
    if guard_descriptor is None:
        return None
    diagnostics: int | None = None
    marker: int | None = None
    try:
        diagnostics = _open_or_create_diagnostics(guard_descriptor, directory_name)
        if diagnostics is None:
            return None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        marker = os.open(marker_name, flags, _PRIVATE_FILE_MODE, dir_fd=diagnostics)
        offset = 0
        while offset < len(encoded):
            written = os.write(marker, encoded[offset:])
            if written <= 0:
                raise OSError("capture marker write made no progress")
            offset += written
        if not _private_regular(marker):
            return None
        return session
    except (FileExistsError, OSError, TypeError, ValueError):
        return None
    finally:
        if marker is not None:
            with suppress(OSError):
                os.close(marker)
        if diagnostics is not None:
            with suppress(OSError):
                os.close(diagnostics)
        with suppress(OSError):
            os.close(guard_descriptor)


__all__ = ["initialize_private_capture_marker"]
