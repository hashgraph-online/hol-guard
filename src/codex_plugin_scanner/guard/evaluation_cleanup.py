"""Anchored cleanup for private, cooperatively contained evaluation setups.

The private parent must not be modified by an untrusted same-user process
during cleanup. POSIX name deletion is not atomic inode-bound deletion.
"""

# pyright: reportPrivateUsage=false, reportUnnecessaryContains=false

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path
from typing import cast

from .evaluation_contracts import EvaluationContractError
from .evaluation_scope import _safe_temp_parent

OWNED_ROOT_PREFIX = "hol-guard-eval-"
MARKER_NAME = ".hol-guard-evaluation-owned"
_DESCRIPTOR_CLEANUP_DIR_FD_OPERATIONS = (os.open, os.stat, os.unlink, os.rmdir)
_DESCRIPTOR_CLEANUP_SUPPORTED_DIR_FD = frozenset(getattr(os, "supports_dir_fd", ()))
_UNSAFE_PERMISSION_BITS = 0o077 | stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


def descriptor_cleanup_supported() -> bool:
    """Return whether this interpreter can perform anchored POSIX cleanup."""

    if (
        os.name != "posix"
        or not hasattr(os, "getuid")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "scandir")
    ):
        return False
    supported = cast(frozenset[object], _DESCRIPTOR_CLEANUP_SUPPORTED_DIR_FD)
    return all(
        operation in supported or getattr(operation, "__name__", None) in supported
        for operation in _DESCRIPTOR_CLEANUP_DIR_FD_OPERATIONS
    )


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _private_directory_details(
    descriptor: int,
    *,
    label: str,
    expected_identity: tuple[int, int] | None = None,
    require_private: bool = True,
    reject_special_bits: bool = False,
) -> os.stat_result:
    details = os.fstat(descriptor)
    if not stat.S_ISDIR(details.st_mode):
        raise EvaluationContractError(f"{label} is not a directory")
    identity = details.st_dev, details.st_ino
    if expected_identity is not None and identity != expected_identity:
        raise EvaluationContractError(f"{label} changed before cleanup")
    mode = stat.S_IMODE(details.st_mode)
    if details.st_uid != os.getuid():
        raise EvaluationContractError(f"{label} is not private to the current user")
    if reject_special_bits and mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise EvaluationContractError(f"{label} has unsafe permission bits (setuid/setgid/sticky)")
    if require_private and mode & 0o077:
        raise EvaluationContractError(f"{label} is not private to the current user")
    return details


def _validate_owned_marker(root_descriptor: int, marker_token: str) -> None:
    try:
        marker_details = os.stat(MARKER_NAME, dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise EvaluationContractError("evaluation setup ownership marker is missing") from exc
    if not stat.S_ISREG(marker_details.st_mode):
        raise EvaluationContractError("evaluation setup ownership marker is missing")
    if marker_details.st_uid != os.getuid() or stat.S_IMODE(marker_details.st_mode) & _UNSAFE_PERMISSION_BITS:
        raise EvaluationContractError("evaluation setup ownership marker is unsafe")

    marker_descriptor: int | None = None
    try:
        marker_descriptor = os.open(
            MARKER_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=root_descriptor,
        )
        opened_details = os.fstat(marker_descriptor)
        if not stat.S_ISREG(opened_details.st_mode) or (opened_details.st_dev, opened_details.st_ino) != (
            marker_details.st_dev,
            marker_details.st_ino,
        ):
            raise EvaluationContractError("evaluation setup ownership marker changed during cleanup")
        token_bytes = marker_token.encode("utf-8")
        if os.read(marker_descriptor, len(token_bytes) + 1) != token_bytes:
            raise EvaluationContractError("evaluation setup ownership marker does not match")
    except FileNotFoundError as exc:
        raise EvaluationContractError("evaluation setup ownership marker is missing") from exc
    finally:
        if marker_descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(marker_descriptor)


def _remove_descriptor_tree(directory_descriptor: int, entry_name: str) -> None:
    """Remove one directory entry relative to an already validated directory."""

    try:
        details = os.stat(entry_name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    identity = details.st_dev, details.st_ino
    if not stat.S_ISDIR(details.st_mode):
        os.unlink(entry_name, dir_fd=directory_descriptor)
        return

    child_descriptor = os.open(entry_name, _directory_open_flags(), dir_fd=directory_descriptor)
    try:
        opened_details = os.fstat(child_descriptor)
        if not stat.S_ISDIR(opened_details.st_mode) or (opened_details.st_dev, opened_details.st_ino) != identity:
            raise EvaluationContractError("evaluation setup entry changed during cleanup")
        with os.scandir(child_descriptor) as entries:
            child_names = [child.name for child in entries]
        for child_name in child_names:
            _remove_descriptor_tree(child_descriptor, child_name)
        try:
            current_details = os.stat(entry_name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise EvaluationContractError("evaluation setup entry changed during cleanup") from exc
        if (current_details.st_dev, current_details.st_ino) != identity:
            raise EvaluationContractError("evaluation setup entry changed during cleanup")
    finally:
        os.close(child_descriptor)
    os.rmdir(entry_name, dir_fd=directory_descriptor)


def remove_owned_root(
    root_path: Path,
    marker_token: str,
    *,
    expected_root_identity: tuple[int, int] | None = None,
) -> bool:
    """Validate and remove an owned root inside a cooperatively contained parent."""

    if not descriptor_cleanup_supported():
        raise EvaluationContractError("descriptor-bound evaluation cleanup is unavailable on this platform")

    try:
        if not root_path.name.startswith(OWNED_ROOT_PREFIX):
            raise EvaluationContractError("evaluation setup path has an invalid ownership name")
        if not _safe_temp_parent(root_path.parent):
            raise EvaluationContractError("evaluation setup path is outside a temporary root")
        if root_path.is_symlink():
            raise EvaluationContractError("evaluation setup path must not be a symlink")

        parent_descriptor = os.open(os.fspath(root_path.parent), _directory_open_flags())
        try:
            _ = _private_directory_details(parent_descriptor, label="evaluation setup parent")
            try:
                root_descriptor = os.open(root_path.name, _directory_open_flags(), dir_fd=parent_descriptor)
            except FileNotFoundError:
                return False
            try:
                root_details = _private_directory_details(
                    root_descriptor,
                    label="evaluation setup",
                    expected_identity=expected_root_identity,
                    require_private=False,
                    reject_special_bits=True,
                )
                root_identity = root_details.st_dev, root_details.st_ino
                _validate_owned_marker(root_descriptor, marker_token)
                with os.scandir(root_descriptor) as entries:
                    entry_names = [entry.name for entry in entries if entry.name != MARKER_NAME]
                for entry_name in entry_names:
                    _remove_descriptor_tree(root_descriptor, entry_name)
                _validate_owned_marker(root_descriptor, marker_token)
                os.unlink(MARKER_NAME, dir_fd=root_descriptor)
                try:
                    current_details = os.stat(root_path.name, dir_fd=parent_descriptor, follow_symlinks=False)
                except FileNotFoundError as exc:
                    raise EvaluationContractError("evaluation setup changed during cleanup") from exc
                if (current_details.st_dev, current_details.st_ino) != root_identity:
                    raise EvaluationContractError("evaluation setup changed during cleanup")
                os.rmdir(root_path.name, dir_fd=parent_descriptor)
                return True
            finally:
                os.close(root_descriptor)
        finally:
            os.close(parent_descriptor)
    except EvaluationContractError:
        raise
    except (OSError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise EvaluationContractError("unable to clean up evaluation setup") from exc


__all__ = ["MARKER_NAME", "OWNED_ROOT_PREFIX", "descriptor_cleanup_supported", "remove_owned_root"]
