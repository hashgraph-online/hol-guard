"""Low-level, side-effect-free helpers shared by contained execution paths."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

_ALLOWED_ENVIRONMENT_KEYS = ("LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM")
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mode,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def file_sha256(path: str) -> str:
    """Hash one non-symlinked regular file without following a replacement link."""

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    leaf_metadata = None
    if not no_follow:
        leaf_metadata = os.lstat(path)
        if not stat.S_ISREG(leaf_metadata.st_mode) or leaf_metadata.st_size > _MAX_EXECUTABLE_BYTES:
            raise ValueError("executable must be a bounded regular file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0) | no_follow
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_EXECUTABLE_BYTES:
            raise ValueError("executable must be a bounded regular file")
        before_identity = _file_identity(before)
        if leaf_metadata is not None and _file_identity(leaf_metadata) != before_identity:
            raise ValueError("executable identity changed before hashing")

        digest = hashlib.sha256()
        read_bytes = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            read_bytes += len(chunk)
            if read_bytes > _MAX_EXECUTABLE_BYTES:
                raise ValueError("executable must be a bounded regular file")
            digest.update(chunk)

        if read_bytes != before.st_size:
            raise ValueError("executable identity changed while hashing")
        after = os.fstat(descriptor)
        if _file_identity(after) != before_identity:
            raise ValueError("executable identity changed while hashing")
        final_path = os.lstat(path)
        if not stat.S_ISREG(final_path.st_mode) or _file_identity(final_path) != _file_identity(after):
            raise ValueError("executable identity changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def canonical_existing_directory(path: Path) -> Path:
    """Resolve one existing directory while rejecting symlinks and path aliases."""

    if path.is_symlink() or not path.is_dir():
        raise ValueError("workspace must be an existing canonical directory")
    canonical = path.resolve(strict=True)
    if canonical != Path(os.path.normpath(str(path))):
        raise ValueError("workspace cannot contain aliases")
    return canonical


def clean_containment_environment(environment: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Retain only non-sensitive presentation variables for a contained child."""

    return tuple(sorted((key, value) for key in _ALLOWED_ENVIRONMENT_KEYS if (value := environment.get(key))))


def containment_binding_digest(payload: dict[str, object]) -> str:
    """Hash one canonical payload with an explicit length prefix."""

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = [
    "canonical_existing_directory",
    "clean_containment_environment",
    "containment_binding_digest",
    "file_sha256",
]
