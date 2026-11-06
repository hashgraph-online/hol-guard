"""Race-resistant ownership verification for privileged Linux artifacts."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, cast

_MAX_ARTIFACT_BYTES: Final = 128 * 1024 * 1024
_READ_BYTES: Final = 128 * 1024
_ROOT_TRUSTED_UIDS: Final = frozenset({0})
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")


class LinuxArtifactOwnershipError(ValueError):
    """Fail-closed trusted-artifact verification error."""


@dataclass(frozen=True, slots=True)
class LinuxArtifactMetadata:
    component_id: str
    version: str
    source: str
    license_id: str
    expected_sha256: str
    release_sequence: int = 0

    def __post_init__(self) -> None:
        for label, value in (
            ("component_id", self.component_id),
            ("version", self.version),
            ("source", self.source),
            ("license_id", self.license_id),
        ):
            if type(cast(object, value)) is not str or not value or value != value.strip():
                raise LinuxArtifactOwnershipError(f"invalid-metadata:{label}")
        if (
            type(cast(object, self.expected_sha256)) is not str
            or _SHA256_PATTERN.fullmatch(self.expected_sha256) is None
        ):
            raise LinuxArtifactOwnershipError("invalid-metadata:expected_sha256")
        if type(self.release_sequence) is not int or self.release_sequence < 0:
            raise LinuxArtifactOwnershipError("invalid-metadata:release_sequence")


@dataclass(frozen=True, slots=True)
class LinuxArtifactOwnershipReceipt:
    metadata: LinuxArtifactMetadata
    path: str
    device: int
    inode: int
    uid: int
    mode: int
    size: int
    sha256: str


def _require_uid(value: int, label: str) -> None:
    if type(value) is not int or value < 0:
        raise LinuxArtifactOwnershipError(f"invalid-{label}")


def _unsafe_mode(mode: int, uid: int) -> bool:
    writable = mode & 0o022
    sticky_root_directory = stat.S_ISDIR(mode) and uid == 0 and bool(mode & stat.S_ISVTX)
    return bool(writable) and not sticky_root_directory


def _security_state(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_state(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def _close_quietly(descriptor: int) -> None:
    with suppress(OSError):
        os.close(descriptor)


def verify_linux_artifact_ownership(
    path: str | os.PathLike[str],
    metadata: LinuxArtifactMetadata,
    *,
    expected_uid: int,
    trusted_ancestor_uids: frozenset[int] = _ROOT_TRUSTED_UIDS,
    max_bytes: int = _MAX_ARTIFACT_BYTES,
) -> LinuxArtifactOwnershipReceipt:
    """Verify and hash an artifact without reopening it by pathname."""
    if type(metadata) is not LinuxArtifactMetadata:
        raise LinuxArtifactOwnershipError("invalid-metadata:type")
    _require_uid(expected_uid, "expected-uid")
    if not trusted_ancestor_uids:
        raise LinuxArtifactOwnershipError("invalid-trusted-ancestor-uids")
    for uid in trusted_ancestor_uids:
        _require_uid(uid, "trusted-ancestor-uid")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise LinuxArtifactOwnershipError("invalid-max-bytes")
    try:
        raw_path = os.fspath(path)
    except (TypeError, ValueError) as error:
        raise LinuxArtifactOwnershipError("invalid-path") from error
    if not isinstance(cast(object, raw_path), str):
        raise LinuxArtifactOwnershipError("invalid-path")
    if not raw_path.startswith("/"):
        raise LinuxArtifactOwnershipError("path-not-absolute")
    if "\0" in raw_path:
        raise LinuxArtifactOwnershipError("invalid-path")
    if raw_path != os.path.normpath(raw_path) or PurePosixPath(raw_path).as_posix() != raw_path:
        raise LinuxArtifactOwnershipError("path-not-canonical")
    components = PurePosixPath(raw_path).parts[1:]
    if not components:
        raise LinuxArtifactOwnershipError("path-has-no-leaf")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if not isinstance(nofollow, int) or not isinstance(directory, int):
        raise LinuxArtifactOwnershipError("nofollow-unavailable")
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | cloexec | nofollow | directory
    leaf_flags = os.O_RDONLY | cloexec | nofollow | os.O_NONBLOCK
    opened: list[int] = []
    leaf_fd: int | None = None
    directory_bindings: list[tuple[str, tuple[int, ...]]] = []
    try:
        current_fd = os.open("/", directory_flags)
        opened.append(current_fd)
        root_info = os.fstat(current_fd)
        directory_bindings.append(("/", _directory_state(root_info)))
        if root_info.st_uid not in trusted_ancestor_uids or _unsafe_mode(root_info.st_mode, root_info.st_uid):
            raise LinuxArtifactOwnershipError("unsafe-ancestor")
        current_path = ""
        for component in components[:-1]:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise LinuxArtifactOwnershipError("unsafe-ancestor")
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            opened.append(next_fd)
            after = os.fstat(next_fd)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise LinuxArtifactOwnershipError("ancestor-raced")
            if after.st_uid not in trusted_ancestor_uids or _unsafe_mode(after.st_mode, after.st_uid):
                raise LinuxArtifactOwnershipError("unsafe-ancestor")
            current_path = f"{current_path}/{component}"
            directory_bindings.append((current_path, _directory_state(after)))
            current_fd = next_fd
        leaf_fd = os.open(components[-1], leaf_flags, dir_fd=current_fd)
        before_leaf = os.fstat(leaf_fd)
        if not stat.S_ISREG(before_leaf.st_mode):
            raise LinuxArtifactOwnershipError("artifact-not-regular")
        if before_leaf.st_nlink != 1:
            raise LinuxArtifactOwnershipError("artifact-multiple-links")
        if before_leaf.st_uid != expected_uid:
            raise LinuxArtifactOwnershipError("artifact-owner-mismatch")
        if _unsafe_mode(before_leaf.st_mode, before_leaf.st_uid):
            raise LinuxArtifactOwnershipError("artifact-writable-by-untrusted")
        if before_leaf.st_size > max_bytes:
            raise LinuxArtifactOwnershipError("artifact-too-large")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(leaf_fd, min(_READ_BYTES, max_bytes - total + 1)):
            total += len(chunk)
            if total > max_bytes:
                raise LinuxArtifactOwnershipError("artifact-too-large")
            digest.update(chunk)
        actual_sha256 = digest.hexdigest()
        after_leaf = os.fstat(leaf_fd)
        if _security_state(before_leaf) != _security_state(after_leaf):
            raise LinuxArtifactOwnershipError("artifact-mutated")
        current_leaf = os.stat(raw_path, follow_symlinks=False)
        if not stat.S_ISREG(current_leaf.st_mode) or _security_state(current_leaf) != _security_state(after_leaf):
            raise LinuxArtifactOwnershipError("artifact-path-replaced")
        for bound_path, bound_state in directory_bindings:
            current_directory = os.stat(bound_path, follow_symlinks=False)
            if not stat.S_ISDIR(current_directory.st_mode) or _directory_state(current_directory) != bound_state:
                raise LinuxArtifactOwnershipError("ancestor-path-replaced")
        final_leaf = os.fstat(leaf_fd)
        if _security_state(final_leaf) != _security_state(after_leaf):
            raise LinuxArtifactOwnershipError("artifact-mutated")
        if not hmac.compare_digest(actual_sha256, metadata.expected_sha256):
            raise LinuxArtifactOwnershipError("artifact-digest-mismatch")
        return LinuxArtifactOwnershipReceipt(
            metadata=metadata,
            path=raw_path,
            device=before_leaf.st_dev,
            inode=before_leaf.st_ino,
            uid=before_leaf.st_uid,
            mode=stat.S_IMODE(before_leaf.st_mode),
            size=total,
            sha256=actual_sha256,
        )
    except OSError as error:
        raise LinuxArtifactOwnershipError("artifact-open-failed") from error
    finally:
        if leaf_fd is not None:
            _close_quietly(leaf_fd)
        for descriptor in reversed(opened):
            _close_quietly(descriptor)


__all__ = [
    "LinuxArtifactMetadata",
    "LinuxArtifactOwnershipError",
    "LinuxArtifactOwnershipReceipt",
    "verify_linux_artifact_ownership",
]
