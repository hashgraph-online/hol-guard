"""Bounded Guard config reads bound to a directory and one regular-file handle."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Generator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..path_support import DEFAULT_SAFE_READ_LIMIT_BYTES
from .file_identity import full_stat_identity
from .windows_paths import open_windows_locked_regular_descriptor

GUARD_CONFIG_FILENAMES = frozenset({"config.toml", ".ai-plugin-scanner-guard.toml", ".hol-guard.toml"})
MAX_GUARD_CONFIG_BYTES = DEFAULT_SAFE_READ_LIMIT_BYTES
GuardConfigParentValidator = Callable[[Path, os.stat_result], None]


class GuardConfigSourceError(ValueError):
    """An existing config cannot be safely loaded; it is not an absent config."""


@dataclass(frozen=True)
class CapturedGuardConfig:
    content: bytes
    identity: tuple[int, ...] | None


GuardConfigCapture = Callable[[Path], CapturedGuardConfig]


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise GuardConfigSourceError("guard_config_parent_not_directory")
    # Sibling writes legitimately change directory times and link counts.
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid


def _cross_api_identity(metadata: os.stat_result) -> tuple[int, ...]:
    values = full_stat_identity(metadata)
    if os.name != "nt":
        return values
    # Windows lstat exposes creation time as ctime, while fstat may expose the
    # distinct change time. Keep same-API full comparisons around the read.
    return (*values[:6], int(getattr(metadata, "st_birthtime_ns", metadata.st_ctime_ns)), values[7])


def _validate_file(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or int(getattr(metadata, "st_file_attributes", 0)) & 0x400:
        raise GuardConfigSourceError("guard_config_not_regular")
    if metadata.st_nlink != 1:
        raise GuardConfigSourceError("guard_config_link_count")
    if not 0 <= metadata.st_size <= MAX_GUARD_CONFIG_BYTES:
        raise GuardConfigSourceError("guard_config_too_large")


@contextmanager
def _posix_parent_chain(parent: Path) -> Generator[int, None, None]:
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        raise GuardConfigSourceError("guard_config_descriptor_io_unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    with ExitStack() as resources:
        descriptor = os.open(parent.anchor, flags)
        _ = resources.callback(os.close, descriptor)
        bindings: list[tuple[int, str, int, tuple[int, ...]]] = []
        for name in parent.parts[1:]:
            child = os.open(name, flags, dir_fd=descriptor)
            _ = resources.callback(os.close, child)
            identity = _directory_identity(os.fstat(child))
            bindings.append((descriptor, name, child, identity))
            descriptor = child
        yield descriptor
        for parent_descriptor, name, child, identity in reversed(bindings):
            if (
                _directory_identity(os.fstat(child)) != identity
                or _directory_identity(os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)) != identity
            ):
                raise GuardConfigSourceError("guard_config_parent_changed")


@contextmanager
def _windows_parent_chain(parent: Path) -> Generator[None, None, None]:
    # Reuse the existing no-reparse directory handles, retaining the complete
    # chain with write/delete sharing denied. This path never creates anything.
    from ..safe_output_windows import _open_locked_directory, _WindowsApi

    api = _WindowsApi()
    with ExitStack() as resources:
        current = Path(parent.anchor)
        for name in ("", *parent.parts[1:]):
            if name:
                current /= name
            handle = _open_locked_directory(api, current)
            _ = resources.callback(api.close_handle, handle)
        yield


def _read_descriptor(descriptor: int, before: os.stat_result) -> bytes:
    opened = os.fstat(descriptor)
    _validate_file(opened)
    if _cross_api_identity(before) != _cross_api_identity(opened):
        raise GuardConfigSourceError("guard_config_changed")
    # One extra byte detects growth without allocating the whole ceiling for a
    # small config. No pathname is reopened, including after a short read.
    remaining = opened.st_size + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    if len(content) != opened.st_size or full_stat_identity(os.fstat(descriptor)) != full_stat_identity(opened):
        raise GuardConfigSourceError("guard_config_changed")
    return content


def _capture_in_parent(path: Path, directory: int | None) -> CapturedGuardConfig:
    def metadata() -> os.stat_result:
        return path.lstat() if directory is None else os.stat(path.name, dir_fd=directory, follow_symlinks=False)

    try:
        before = metadata()
    except FileNotFoundError:
        return CapturedGuardConfig(b"", None)
    _validate_file(before)
    descriptor = (
        open_windows_locked_regular_descriptor(path)
        if directory is None
        else os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory,
        )
    )
    try:
        content = _read_descriptor(descriptor, before)
        if full_stat_identity(metadata()) != full_stat_identity(before):
            raise GuardConfigSourceError("guard_config_changed")
        return CapturedGuardConfig(content, full_stat_identity(before))
    finally:
        os.close(descriptor)


def _verify_missing_parent(parent: Path) -> None:
    """Distinguish a missing directory from an existing but dangling alias."""

    absolute = parent.absolute()
    for prefix in reversed((absolute, *absolute.parents)):
        try:
            entry = prefix.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(entry.st_mode) or int(getattr(entry, "st_file_attributes", 0)) & 0x400:
            # A valid directory alias may precede a genuinely absent child.
            # An existing dangling/replaced alias cannot establish that scope.
            _directory_identity(prefix.stat())
        else:
            _directory_identity(entry)
    raise GuardConfigSourceError("guard_config_parent_changed")


def capture_guard_config(
    path: Path,
    *,
    parent_validator: GuardConfigParentValidator | None = None,
    expected_parent: Path | None = None,
) -> CapturedGuardConfig:
    """Capture a fixed config basename, preserving intentional directory aliases.

    Missing files/directories contribute no override. Unsafe, inaccessible,
    changing or oversized existing inputs raise instead of becoming defaults.
    Directory aliases are resolved once at the scope boundary, then the real
    directory chain and config leaf are held while reading and verifying bytes.
    A caller that has already admitted a canonical workspace supplies that path
    as expected_parent. It is compared without resolving it again. Additional
    caller authorization runs against the held parent before any leaf read.
    """

    if path.name not in GUARD_CONFIG_FILENAMES:
        raise GuardConfigSourceError("guard_config_name_invalid")
    try:
        try:
            parent_before = _directory_identity(path.parent.stat())
        except FileNotFoundError:
            _verify_missing_parent(path.parent)
            return CapturedGuardConfig(b"", None)
        parent = path.parent.resolve(strict=True)
        if expected_parent is not None and parent != expected_parent:
            raise GuardConfigSourceError("guard_config_scope_changed")
        if _directory_identity(parent.stat()) != parent_before:
            raise GuardConfigSourceError("guard_config_parent_changed")
        with ExitStack() as resources:
            if os.name == "nt":
                resources.enter_context(_windows_parent_chain(parent))
                directory = None
            elif os.name == "posix":
                directory = resources.enter_context(_posix_parent_chain(parent))
            else:
                raise GuardConfigSourceError("guard_config_descriptor_io_unavailable")
            held = parent.stat() if directory is None else os.fstat(directory)
            if _directory_identity(held) != parent_before:
                raise GuardConfigSourceError("guard_config_parent_changed")
            if parent_validator is not None:
                try:
                    parent_validator(parent, held)
                except GuardConfigSourceError:
                    raise
                except (OSError, RuntimeError, TypeError, ValueError) as error:
                    raise GuardConfigSourceError("guard_config_scope_rejected") from error
            captured = _capture_in_parent(parent / path.name, directory)
            if _directory_identity(path.parent.stat()) != parent_before or path.parent.resolve(strict=True) != parent:
                raise GuardConfigSourceError("guard_config_parent_changed")
        return captured
    except (OSError, RuntimeError) as error:
        raise GuardConfigSourceError("guard_config_source_unavailable") from error
