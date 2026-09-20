"""Bounded reads for owner-only local authority files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def private_regular_file_is_valid(
    path: Path,
    *,
    require_private_parent: bool = False,
) -> bool:
    """Return whether a path names an owner-only regular file.

    Parent validation is optional because some legacy authority files live in a
    user-owned directory whose privacy is established elsewhere.
    """

    try:
        parent_metadata = path.parent.lstat() if require_private_parent else None
        metadata = path.lstat()
    except OSError:
        return False
    if parent_metadata is not None and not _private_directory_metadata_is_valid(parent_metadata):
        return False
    return _private_file_metadata_is_valid(metadata)


def read_private_regular_bytes(
    path: Path,
    *,
    max_bytes: int,
    require_private_parent: bool = False,
) -> bytes | None:
    """Read a private regular file through one bounded, no-follow descriptor."""

    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    try:
        parent_before = path.parent.lstat() if require_private_parent else None
        path_before = path.lstat()
    except OSError:
        return None
    if parent_before is not None and not _private_directory_metadata_is_valid(parent_before):
        return None
    if not _private_file_metadata_is_valid(path_before):
        return None

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        if os.name == "nt":
            from .windows_replaceable_file import open_replaceable_read_descriptor

            descriptor = open_replaceable_read_descriptor(path, flags)
        else:
            descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if not _private_file_metadata_is_valid(opened) or not _same_file(
            path_before,
            opened,
        ):
            return None
        if opened.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        consumed = 0
        while consumed < max_bytes:
            chunk = os.read(
                descriptor,
                min(64 * 1024, max_bytes - consumed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
        closed_state = os.fstat(descriptor)
        if not _stable_file_metadata(opened, closed_state):
            return None
    finally:
        os.close(descriptor)

    if require_private_parent:
        try:
            parent_after = path.parent.lstat()
        except OSError:
            return None
        if parent_before is None or not _stable_directory_metadata(
            parent_before,
            parent_after,
        ):
            return None
    return b"".join(chunks)


def read_private_regular_text(
    path: Path,
    *,
    max_bytes: int,
    require_private_parent: bool = False,
) -> str | None:
    """Read bounded UTF-8 text from a private regular file."""

    payload = read_private_regular_bytes(
        path,
        max_bytes=max_bytes,
        require_private_parent=require_private_parent,
    )
    if payload is None:
        return None
    try:
        return payload.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None


def _private_file_metadata_is_valid(metadata: os.stat_result) -> bool:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return metadata.st_uid == os.getuid() and not stat.S_IMODE(metadata.st_mode) & 0o077


def _private_directory_metadata_is_valid(metadata: os.stat_result) -> bool:
    if not stat.S_ISDIR(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return metadata.st_uid == os.getuid() and not stat.S_IMODE(metadata.st_mode) & 0o077


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _stable_file_metadata(
    before: os.stat_result,
    after: os.stat_result,
) -> bool:
    return (
        _same_file(before, after)
        and before.st_mode == after.st_mode
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _stable_directory_metadata(
    before: os.stat_result,
    after: os.stat_result,
) -> bool:
    """Confirm the parent directory was not replaced or made non-private.

    Sibling writes update directory mtime/ctime, so those timestamps are not
    part of the identity check.
    """

    return _private_directory_metadata_is_valid(after) and _same_file(before, after) and before.st_mode == after.st_mode


__all__ = [
    "private_regular_file_is_valid",
    "read_private_regular_bytes",
    "read_private_regular_text",
]
