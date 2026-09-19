"""Read fixed workspace configuration files without following file symlinks."""

from __future__ import annotations

import importlib
import os
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tomllib
else:  # pragma: no cover - runtime compatibility
    tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

from .file_identity import full_stat_identity
from .windows_paths import open_windows_locked_regular_descriptor

WORKSPACE_CONFIG_FILENAMES = (".ai-plugin-scanner-guard.toml", ".hol-guard.toml")


def read_workspace_toml(workspace: Path, filename: str) -> dict[str, object]:
    """Load an optional regular config through a checked, no-follow descriptor."""

    if filename not in WORKSPACE_CONFIG_FILENAMES:
        return {}
    try:
        supplied_root = workspace.absolute()
        supplied_before = supplied_root.lstat()
        if not _is_directory(supplied_before):
            return {}
        root = supplied_root.resolve(strict=True)
        # Admission already canonicalizes aliases; later redirects are unsafe.
        if root != Path(os.path.normpath(supplied_root)):
            return {}
        root_before = root.lstat()
    except (OSError, RuntimeError):
        return {}
    if not _same_directory(supplied_before, root_before):
        return {}
    try:
        if os.name == "nt":
            return _read_windows_config(root, root_before, filename)
        return _read_posix_config(root, root_before, filename)
    except OSError:
        return {}


def _read_posix_config(root: Path, root_before: os.stat_result, filename: str) -> dict[str, object]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        return {}
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    root_descriptor = os.open(root, os.O_RDONLY | directory | no_follow | close_on_exec)
    try:
        if not _same_directory(root_before, os.fstat(root_descriptor)):
            return {}
        before = os.stat(filename, dir_fd=root_descriptor, follow_symlinks=False)
        if not _is_regular(before):
            return {}
        descriptor = os.open(
            filename,
            os.O_RDONLY | no_follow | close_on_exec | getattr(os, "O_NONBLOCK", 0),
            dir_fd=root_descriptor,
        )
        try:
            payload = _read_descriptor(descriptor, before)
            after = os.stat(filename, dir_fd=root_descriptor, follow_symlinks=False)
            if not _is_regular(after) or full_stat_identity(before) != full_stat_identity(after):
                return {}
            if not _same_directory(root_before, root.lstat()):
                return {}
            return payload
        finally:
            os.close(descriptor)
    finally:
        os.close(root_descriptor)


def _read_windows_config(root: Path, root_before: os.stat_result, filename: str) -> dict[str, object]:
    candidate = root / filename
    before = candidate.lstat()
    if not _is_regular(before):
        return {}
    descriptor = open_windows_locked_regular_descriptor(candidate)
    try:
        if not _same_directory(root_before, root.lstat()):
            return {}
        payload = _read_descriptor(descriptor, before)
        after = candidate.lstat()
        if not _is_regular(after) or full_stat_identity(before) != full_stat_identity(after):
            return {}
        if not _same_directory(root_before, root.lstat()):
            return {}
        return payload
    finally:
        os.close(descriptor)


def _read_descriptor(descriptor: int, before: os.stat_result) -> dict[str, object]:
    opened = os.fstat(descriptor)
    if not _is_regular(opened) or full_stat_identity(before) != full_stat_identity(opened):
        return {}
    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        payload = tomllib.load(handle)
    if full_stat_identity(opened) != full_stat_identity(os.fstat(descriptor)):
        return {}
    return payload if isinstance(payload, dict) else {}


def _has_reparse_point(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _is_regular(metadata: os.stat_result) -> bool:
    return stat.S_ISREG(metadata.st_mode) and not _has_reparse_point(metadata)


def _is_directory(metadata: os.stat_result) -> bool:
    return stat.S_ISDIR(metadata.st_mode) and not _has_reparse_point(metadata)


def _same_directory(before: os.stat_result, after: os.stat_result) -> bool:
    # Sibling writes may update directory timestamps without replacing the directory.
    return _is_directory(after) and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
