"""Race-checked native binary identities with bounded digest reuse."""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path

from .file_identity import full_stat_identity
from .group_write_trust import trusted_owner_and_mode
from .native_binary_write_lock import open_write_locked
from .native_runtime_values import NativeRuntimeIdentity

_MAX_IDENTITIES = 64
_MIN_CACHE_AGE_NS = 2_000_000_000
_CACHE_ENABLED = os.name == "posix" and hasattr(os, "O_NOFOLLOW")


def _write_lock_supported(os_name: str, version: tuple[int, ...]) -> bool:
    # Before 3.12, Windows os.stat fills st_ino from the 64-bit nFileIndex,
    # which truncates 128-bit ReFS file IDs. Every other identity field is
    # owner-forgeable on Windows, so a colliding file renamed over the binary
    # could inherit its digest. Older interpreters keep hashing every lookup.
    return os_name == "nt" and tuple(version[:2]) >= (3, 12)


_WRITE_LOCK_ENABLED = _write_lock_supported(os.name, (sys.version_info.major, sys.version_info.minor))
_CACHE_LOCK = threading.Lock()
_IDENTITIES: OrderedDict[tuple[str, tuple[int, ...]], NativeRuntimeIdentity] = OrderedDict()
# Windows reuses a digest only while it holds a handle that denies writers.
_WRITE_LOCKS: dict[tuple[str, tuple[int, ...]], int] = {}


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


def _trusted_regular_file(metadata: os.stat_result, path: Path) -> bool:
    if not stat.S_ISREG(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return trusted_owner_and_mode(metadata, path)


def _cacheable(metadata: os.stat_result) -> bool:
    # A write and hash can share a filesystem clock tick. Never reuse a hash
    # until the recorded change time is outside that recent-write window.
    changed_at = int(metadata.st_ctime_ns)
    return _CACHE_ENABLED and changed_at > 0 and time.time_ns() - changed_at >= _MIN_CACHE_AGE_NS


def _stable_names(lexical: Path, resolved: Path, expected: tuple[int, ...]) -> bool:
    return _identity(lexical.lstat()) == expected and _identity(resolved.lstat()) == expected


def _read_digest(path: Path, expected: tuple[int, ...], locked: int | None = None) -> str | None:
    if locked is None:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
    else:
        descriptor = locked
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != expected or not _trusted_regular_file(opened, path):
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
        if locked is None:
            os.close(descriptor)


def _forget_locked(key: tuple[str, tuple[int, ...]]) -> None:
    """Drop one entry and close its write lock. Caller holds ``_CACHE_LOCK``."""

    _IDENTITIES.pop(key, None)
    descriptor = _WRITE_LOCKS.pop(key, None)
    if descriptor is not None:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _locked_identity(
    key: tuple[str, tuple[int, ...]],
    lexical: Path,
    resolved: Path,
    expected: tuple[int, ...],
) -> NativeRuntimeIdentity | None:
    """Cached identity whose write-locked handle still names the same file.

    The path check belongs under the same lock as the handle check. The handle
    is the whole proof: it is what keeps every writer out of the file, and the
    cache is what keeps it open. Checking the paths after the lock is released
    leaves room for another thread to evict this entry and close the handle,
    and a Windows owner can then rewrite the bytes in place and restore the
    size and timestamps the path check reads, so the digest of the old bytes
    comes back for a file that no longer holds them.
    """

    with _CACHE_LOCK:
        cached = _IDENTITIES.get(key)
        descriptor = _WRITE_LOCKS.get(key)
        if cached is None or descriptor is None:
            return None
        try:
            unchanged = _identity(os.fstat(descriptor)) == key[1]
        except OSError:
            unchanged = False
        if not unchanged:
            _forget_locked(key)
            return None
        if not _stable_names(lexical, resolved, expected):
            return None
        _IDENTITIES.move_to_end(key)
        return cached


def _remember(key: tuple[str, tuple[int, ...]], result: NativeRuntimeIdentity, locked: int | None) -> None:
    with _CACHE_LOCK:
        for stale in [entry for entry in _WRITE_LOCKS if entry[0] == key[0] and entry != key]:
            # The path now names another file; release the old one.
            _forget_locked(stale)
        _forget_locked(key)
        _IDENTITIES[key] = result
        if locked is not None:
            _WRITE_LOCKS[key] = locked
        while len(_IDENTITIES) > _MAX_IDENTITIES:
            _forget_locked(next(iter(_IDENTITIES)))


def validate_native_binary(path: Path) -> NativeRuntimeIdentity | None:
    """Validate every lookup; reuse a digest only for the same unchanged file.

    The cache key includes device, inode, change time, modification time, size,
    permissions, links and ownership. POSIX also requires a change time older
    than the write window, because the owner cannot forge it. Windows owners can
    rewrite every timestamp, so a Windows digest is reused only while this
    process holds a handle that the kernel keeps every writer from opening, and
    only while the path still names that handle's file. Opening and finishing a
    cold read must match both the descriptor and named file.
    """
    try:
        lexical = path.expanduser()
        metadata = lexical.lstat()
        if not _trusted_regular_file(metadata, lexical):
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
        elif _WRITE_LOCK_ENABLED:
            cached = _locked_identity(key, lexical, resolved, expected)
            if cached is not None:
                return cached
        locked = open_write_locked(resolved) if _WRITE_LOCK_ENABLED and not cacheable else None
        try:
            digest = _read_digest(resolved, expected, locked)
            if digest is None or not _stable_names(lexical, resolved, expected):
                return None
            result = NativeRuntimeIdentity(
                path=resolved, size=metadata.st_size, mtime_ns=metadata.st_mtime_ns, sha256=digest
            )
            if cacheable or locked is not None:
                _remember(key, result, locked)
                locked = None
            return result
        finally:
            if locked is not None:
                os.close(locked)
    except (OSError, RuntimeError, ValueError):
        return None
