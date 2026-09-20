"""Descriptor-pinned extension admission and bounded runtime image identities."""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_IMAGE_BYTES = 64 * 1024 * 1024


def _read_identity(descriptor: int, *, owned: bool) -> dict[str, Any]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_IMAGE_BYTES:
        raise ValueError("runtime image must be a bounded regular file")
    if owned and (before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_mode & 0o022):
        raise ValueError("extension must be an exclusively owned, non-writable-by-others image")
    digest = hashlib.sha256()
    count = 0
    while block := os.read(descriptor, 65_536):
        count += len(block)
        if count > MAX_IMAGE_BYTES:
            raise ValueError("runtime image read bound exceeded")
        digest.update(block)
    after = os.fstat(descriptor)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_nlink")
    if count != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError("runtime image changed during descriptor read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return {
        "sha256": digest.hexdigest(),
        "bytes": count,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode),
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }


def image_identity(path: Path) -> dict[str, Any]:
    descriptor = os.open(path.resolve(strict=True), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return _read_identity(descriptor, owned=False)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def pinned_extension(path: Path, *, expected_sha256: str) -> Any:
    if re.fullmatch("[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("exact extension SHA256 is required")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        identity = _read_identity(descriptor, owned=True)
        if identity["bytes"] > 8 * 1024 * 1024:
            raise ValueError("extension exceeds the 8 MiB image bound")
        if identity["sha256"] != expected_sha256:
            raise ValueError("extension content does not match the admitted SHA256")
        yield descriptor, identity
        after = _read_identity(descriptor, owned=True)
        if after != identity:
            raise ValueError("extension identity changed during observation")
    finally:
        os.close(descriptor)


def code_mapping(address: str) -> dict[str, Any]:
    """Read only the exact executable mapping containing the reported C callback."""
    if re.fullmatch(r"0x[0-9a-f]{1,16}", address) is None:
        raise ValueError("invalid callback address")
    value = int(address, 16)
    maps = Path("/proc/self/maps").read_bytes()
    if len(maps) > 4 * 1024 * 1024:
        raise ValueError("process mapping metadata exceeds its observation bound")
    matches = []
    for raw in maps.decode("utf-8", errors="strict").splitlines():
        fields = raw.split(maxsplit=5)
        if len(fields) < 5:
            raise ValueError("invalid process mapping metadata")
        start, end = (int(part, 16) for part in fields[0].split("-"))
        if start <= value < end:
            major, minor = (int(part, 16) for part in fields[3].split(":"))
            matches.append(
                {
                    "device": os.makedev(major, minor),
                    "inode": int(fields[4]),
                    "permissions": fields[1],
                    "file_offset": int(fields[2], 16),
                }
            )
    if len(matches) != 1 or "x" not in matches[0]["permissions"] or "w" in matches[0]["permissions"]:
        raise ValueError("callback lacks one non-writable executable file mapping")
    if matches[0]["inode"] == 0:
        raise ValueError("anonymous callback mappings are outside observation admission")
    return matches[0]


def already_mapped(identity: dict[str, Any]) -> bool:
    maps = Path("/proc/self/maps").read_bytes()
    if len(maps) > 4 * 1024 * 1024:
        raise ValueError("process mapping metadata exceeds its observation bound")
    for raw in maps.decode("utf-8", errors="strict").splitlines():
        fields = raw.split(maxsplit=5)
        if len(fields) < 5:
            raise ValueError("invalid process mapping metadata")
        major, minor = (int(part, 16) for part in fields[3].split(":"))
        if os.makedev(major, minor) == identity["device"] and int(fields[4]) == identity["inode"]:
            return True
    return False
