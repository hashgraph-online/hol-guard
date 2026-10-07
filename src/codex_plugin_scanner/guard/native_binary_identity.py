"""Race-checked native binary identities with bounded POSIX digest reuse."""

from __future__ import annotations

import hashlib
import os
import stat
import threading
import time
from collections import OrderedDict
from pathlib import Path

from .file_identity import full_stat_identity
from .native_runtime_values import NativeRuntimeIdentity

_MAX_IDENTITIES = 64
_MIN_CACHE_AGE_NS = 2_000_000_000
_CACHE_ENABLED = os.name == "posix" and hasattr(os, "O_NOFOLLOW")
_CACHE_LOCK = threading.Lock()
_IDENTITIES: OrderedDict[tuple[str, tuple[int, ...]], NativeRuntimeIdentity] = OrderedDict()


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    values = list(full_stat_identity(metadata))
    if os.name == "nt":
        # stat()/lstat() synthesize 0o111 for .exe/.bat/.cmd/.com by extension while
        # os.fstat() reports the raw filesystem mode (no exec bits). Zeroing all
        # permission bits keeps the tuple consistent across lstat, stat, and fstat —
        # Windows regular files have no user-meaningful POSIX permission semantics.
        values[2] = int(metadata.st_mode) & ~0o777
        # CPython 3.12 preserves creation time in path stat().st_ctime but
        # exposes change time from fstat(). Use explicit birth time to compare
        # a path with its opened handle; raw handle changes are checked below.
        values[6] = int(getattr(metadata, "st_birthtime_ns", metadata.st_ctime_ns))
    return (*values, int(getattr(metadata, "st_uid", -1)), int(getattr(metadata, "st_gid", -1)))


def _trusted_regular_file(metadata: os.stat_result) -> bool:
    if not stat.S_ISREG(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    current_uid = os.getuid() if hasattr(os, "getuid") else None
    owner = getattr(metadata, "st_uid", current_uid)
    return not stat.S_IMODE(metadata.st_mode) & 0o022 and (current_uid is None or owner in {0, current_uid})


def _cacheable(metadata: os.stat_result) -> bool:
    # A write and hash can share a filesystem clock tick. Never reuse a hash
    # until the recorded change time is outside that recent-write window.
    changed_at = int(metadata.st_ctime_ns)
    return _CACHE_ENABLED and changed_at > 0 and time.time_ns() - changed_at >= _MIN_CACHE_AGE_NS


def _stable_names(lexical: Path, resolved: Path, expected: tuple[int, ...]) -> bool:
    return _identity(lexical.lstat()) == expected and _identity(resolved.lstat()) == expected


def _read_digest(path: Path, expected: tuple[int, ...]) -> str | None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != expected or not _trusted_regular_file(opened):
            return None
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                return None
            digest.update(chunk)
            remaining -= len(chunk)
        closed = os.fstat(descriptor)
        if _identity(closed) != expected or full_stat_identity(closed) != full_stat_identity(opened):
            return None
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def validate_native_binary(path: Path) -> NativeRuntimeIdentity | None:
    """Validate every lookup; reuse a digest only for the same unchanged file.

    The cache key includes device, inode, change time, modification time, size,
    permissions, links and ownership. Windows retains uncached hashing. Opening
    and finishing a cold read must match both the descriptor and named file.
    """
    try:
        lexical = path.expanduser()
        metadata = lexical.lstat()
        if not _trusted_regular_file(metadata):
            return None
        resolved = lexical.resolve(strict=True)
        expected = _identity(metadata)
        if not _stable_names(lexical, resolved, expected):
            return None
        key = (str(resolved), expected)
        cacheable = _cacheable(metadata)
        if cacheable:
            with _CACHE_LOCK:
                cached = _IDENTITIES.get(key)
                if cached is not None:
                    _IDENTITIES.move_to_end(key)
            if cached is not None:
                return cached if _stable_names(lexical, resolved, expected) else None
        digest = _read_digest(resolved, expected)
        if digest is None or not _stable_names(lexical, resolved, expected):
            return None
        result = NativeRuntimeIdentity(
            path=resolved, size=metadata.st_size, mtime_ns=metadata.st_mtime_ns, sha256=digest
        )
        if cacheable:
            with _CACHE_LOCK:
                _IDENTITIES[key] = result
                _IDENTITIES.move_to_end(key)
                while len(_IDENTITIES) > _MAX_IDENTITIES:
                    _IDENTITIES.popitem(last=False)
        return result
    except (OSError, RuntimeError, ValueError):
        return None
