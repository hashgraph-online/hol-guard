"""No-follow output helpers for scanner-controlled artifacts."""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
import tempfile
from pathlib import Path


def _reject_untrusted_parent_symlinks(path: Path) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parent.parts[1:]:
        if part in {"", "."}:
            continue
        current = current / part
        if current.is_symlink():
            metadata = current.lstat()
            parent_metadata = current.parent.lstat()
            trusted_system_link = (
                hasattr(os, "geteuid")
                and metadata.st_uid == 0
                and parent_metadata.st_uid == 0
                and not parent_metadata.st_mode & 0o022
            )
            if not trusted_system_link:
                raise OSError(f"refusing symlinked output directory: {current}")
        if not current.exists():
            break


def _trusted_system_link(path: Path) -> bool:
    metadata = path.lstat()
    parent_metadata = path.parent.lstat()
    return (
        hasattr(os, "geteuid")
        and metadata.st_uid == 0
        and parent_metadata.st_uid == 0
        and not parent_metadata.st_mode & 0o022
    )


def _normalized_output_path(path: Path) -> Path:
    absolute = path if path.is_absolute() else Path.cwd() / path
    parent = absolute.parent
    current = Path(absolute.anchor)
    for index, part in enumerate(parent.parts[1:]):
        candidate = current / part
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            return candidate.joinpath(*parent.parts[index + 2 :], absolute.name)
        if stat.S_ISLNK(metadata.st_mode):
            if not _trusted_system_link(candidate):
                raise OSError(f"refusing symlinked output directory: {candidate}")
            current = candidate.resolve(strict=True)
        else:
            current = candidate
    return current / absolute.name


def _write_bytes_descriptor_relative(path: Path, payload: bytes) -> None:
    normalized = _normalized_output_path(path)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(normalized.anchor, directory_flags)
    try:
        for part in normalized.parent.parts[1:]:
            try:
                child = os.open(part, directory_flags, dir_fd=directory)
            except FileNotFoundError:
                os.mkdir(part, mode=0o755, dir_fd=directory)
                child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child

        temporary_name = f".{normalized.name}.{secrets.token_hex(16)}"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            descriptor = -1
            os.replace(
                temporary_name,
                normalized.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=directory)
    finally:
        os.close(directory)


def write_bytes_atomic_no_follow(path: Path, payload: bytes) -> None:
    """Atomically replace an output path without following its final symlink."""
    if os.name == "posix":
        _write_bytes_descriptor_relative(path, payload)
        return
    if os.name == "nt":
        from .safe_output_windows import write_bytes_atomic_no_follow_windows

        write_bytes_atomic_no_follow_windows(path, payload)
        return
    _reject_untrusted_parent_symlinks(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    target = parent / path.name
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_text_atomic_no_follow(path: Path, payload: str, *, encoding: str = "utf-8") -> None:
    write_bytes_atomic_no_follow(path, payload.encode(encoding))
