"""Authorize request directories before reading local Guard configuration."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .runtime.local_temp_paths import trusted_temporary_root_for_path


class DirectoryPathTrustError(ValueError):
    """A request directory is outside its permitted local roots."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def trusted_guard_directory_roots(guard_home: Path) -> tuple[Path, ...]:
    current_home = Path.home().resolve()
    guard_home_root = guard_home.expanduser().resolve().parent
    roots = [current_home]
    if guard_home_root != current_home and not os.fspath(guard_home_root).startswith(
        os.fspath(current_home).rstrip(os.sep) + os.sep
    ):
        roots.append(guard_home_root)
    return tuple(roots)


def validate_guard_directory_path(
    value: str,
    roots: tuple[Path, ...],
    *,
    allow_owned_temporary: bool = False,
) -> Path:
    expanded = os.path.expanduser(value)
    if not os.path.isabs(expanded):
        raise DirectoryPathTrustError("relative_path")
    try:
        candidate = os.path.realpath(expanded)
    except OSError:
        raise DirectoryPathTrustError("path_resolve_failed") from None
    for root in roots:
        root_path = os.path.realpath(os.fspath(root))
        if candidate == root_path:
            return Path(root_path)
        if candidate.startswith(root_path.rstrip(os.sep) + os.sep):
            return Path(candidate)
    if allow_owned_temporary:
        temporary_workspace = validated_owned_temporary_workspace(candidate)
        if temporary_workspace is not None:
            return temporary_workspace
    raise DirectoryPathTrustError("unexpected_root")


def validated_owned_temporary_workspace(candidate: str) -> Path | None:
    try:
        canonical_candidate = os.path.realpath(candidate)
        temporary_root = trusted_temporary_root_for_path(Path(canonical_candidate))
    except OSError:
        return None
    if temporary_root is None:
        return None
    root_path = os.path.realpath(os.fspath(temporary_root))
    # Shared temp roots are not workspaces. Hook normalization already
    # treats an exact temporary-root argument as "no workspace".
    if not canonical_candidate.startswith(root_path.rstrip(os.sep) + os.sep):
        return None
    try:
        candidate_stat = os.stat(canonical_candidate)
    except OSError:
        return None
    if not stat.S_ISDIR(candidate_stat.st_mode):
        return None
    getuid = getattr(os, "getuid", None)
    if not callable(getuid):
        current_home = os.path.realpath(os.fspath(Path.home()))
        if root_path != current_home and not root_path.startswith(current_home.rstrip(os.sep) + os.sep):
            return None
    elif candidate_stat.st_uid != getuid():
        return None
    return Path(canonical_candidate)
