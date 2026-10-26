"""A durable copy of the frozen build's native runtime for installed hook commands.

A frozen Guard carries the native runtime as bundled data. A onefile build
extracts it under a per-launch ``_MEI*`` directory that disappears when the
process exits, and a Desktop app bundle can move between updates, so neither
path can be written into a harness hook command. The hook command instead
names a content-addressed copy under the Guard home, which is always
user-writable: ``<guard_home>/native-runtime/<sha256>/hol-guard-runtime``.

The copy is published only from bytes that hash to the validated runtime
identity, and is reused only while it is a regular, owner-owned, owner-executable
file with the same size and digest and no group or world write bit. Anything
else yields ``None`` so the caller keeps its fail-closed launcher. A copy whose
digest was verified is not hashed again in the same process until its file
metadata changes.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path

from .durable_io import fsync_directory
from .native_runtime_values import NativeRuntimeIdentity

DURABLE_RUNTIME_DIRECTORY = "native-runtime"
_CHUNK_BYTES = 1024 * 1024
_RUNTIME_MODE = 0o700
_DIRECTORY_MODE = 0o700
_HEX_DIGITS = frozenset("0123456789abcdef")
_verified_copies: dict[Path, tuple[object, ...]] = {}


def durable_runtime_path(identity: NativeRuntimeIdentity, guard_home: Path) -> Path:
    """Where the copy of ``identity`` lives under ``guard_home``."""

    return guard_home / DURABLE_RUNTIME_DIRECTORY / identity.sha256 / identity.path.name


def durable_hook_runtime(identity: NativeRuntimeIdentity, guard_home: Path) -> Path | None:
    """The verified durable copy of ``identity``, publishing it when absent."""

    if len(identity.sha256) != 64 or not set(identity.sha256) <= _HEX_DIGITS:
        return None
    target = durable_runtime_path(identity, guard_home)
    try:
        if _is_trusted_copy(target, identity):
            return target
        _ensure_private_directory(guard_home)
        _ensure_private_directory(target.parent.parent)
        _ensure_private_directory(target.parent)
        _publish(identity, target)
    except OSError:
        return None
    return target if _is_trusted_copy(target, identity) else None


def _is_trusted_copy(path: Path, identity: NativeRuntimeIdentity) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != identity.size:
        return False
    mode = stat.S_IMODE(metadata.st_mode)
    if os.name != "nt" and (metadata.st_uid != os.getuid() or mode & 0o022 or not mode & stat.S_IXUSR):
        return False
    verified = (
        identity.sha256,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_ino,
        metadata.st_dev,
    )
    if _verified_copies.get(path) == verified:
        return True
    try:
        trusted = _file_sha256(path) == identity.sha256
    except OSError:
        return False
    if trusted:
        _verified_copies[path] = verified
    return trusted


def _ensure_private_directory(path: Path) -> None:
    with suppress(FileExistsError):
        path.mkdir(mode=_DIRECTORY_MODE, parents=True)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"durable native runtime directory is not a regular directory: {path}")
    if os.name == "nt":
        return
    if metadata.st_uid != os.getuid():
        raise OSError(f"durable native runtime directory has an unexpected owner: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        os.chmod(path, stat.S_IMODE(metadata.st_mode) & ~0o022)


def _publish(identity: NativeRuntimeIdentity, target: Path) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "wb") as handle, identity.path.open("rb") as source:
            while chunk := source.read(_CHUNK_BYTES):
                digest.update(chunk)
                size += len(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        if size != identity.size or digest.hexdigest() != identity.sha256:
            raise OSError("bundled native runtime changed while it was copied")
        # The hook runtime only ever runs as its owner, so it is owner-only.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(temporary, _RUNTIME_MODE)
        os.replace(temporary, target)
        fsync_directory(target.parent)
    finally:
        with suppress(OSError):
            temporary.unlink()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = ["DURABLE_RUNTIME_DIRECTORY", "durable_hook_runtime", "durable_runtime_path"]
