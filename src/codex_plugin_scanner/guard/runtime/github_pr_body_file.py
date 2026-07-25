"""Bounded local validation for GitHub pull-request body files."""

from __future__ import annotations

import os
import stat
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import cast

from .secret_sensitivity import classify_secret_content, classify_secret_path

_MAX_PR_BODY_BYTES = 128 * 1024
_MAX_PR_BODY_AGE_SECONDS = 24 * 60 * 60


def github_pr_body_file_is_safe(
    operand: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Validate locally authored PR text without retaining its contents."""

    if cwd is None or home_dir is None:
        return False
    candidate = _resolve_operand(operand, cwd=cwd, home_dir=home_dir)
    if candidate is None or classify_secret_path(str(candidate), cwd=cwd, home_dir=home_dir) is not None:
        return False
    if _path_looks_sensitive(candidate):
        return False
    if not _is_pr_body_markdown_name(candidate.name):
        return False
    authored_root = _authored_location_root(candidate, cwd=cwd)
    if authored_root is None or not _ancestor_chain_is_controlled(candidate, root=authored_root):
        return False
    try:
        path_metadata = candidate.stat(follow_symlinks=False)
    except OSError:
        return False
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError:
        return False
    try:
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino):
            return False
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return False
        if metadata.st_size <= 0 or metadata.st_size > _MAX_PR_BODY_BYTES:
            return False
        current_uid = _current_uid()
        if current_uid is not None:
            if metadata.st_uid != current_uid:
                return False
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        age_seconds = time.time() - metadata.st_mtime
        if age_seconds < -60 or age_seconds > _MAX_PR_BODY_AGE_SECONDS:
            return False
        payload = os.read(descriptor, _MAX_PR_BODY_BYTES + 1)
        if len(payload) != metadata.st_size:
            return False
    finally:
        os.close(descriptor)
    try:
        content = payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return not classify_secret_content(content, suppress_samples=False)


def _resolve_operand(operand: str, *, cwd: Path, home_dir: Path) -> Path | None:
    stripped = operand.strip().strip("'\"")
    if not stripped:
        return None
    if stripped == "~":
        candidate = home_dir
    elif stripped.startswith("~/"):
        candidate = home_dir / stripped[2:]
    else:
        candidate = Path(stripped)
        if not candidate.is_absolute():
            candidate = cwd / candidate
    if candidate.is_symlink():
        return None
    try:
        return candidate.resolve(strict=True)
    except OSError:
        return None


def _authored_location_root(candidate: Path, *, cwd: Path) -> Path | None:
    # A separate process running as this user already has the same GitHub CLI
    # authority. This boundary prevents accidental agent publication of files
    # outside the active workspace and current-user temporary locations.
    roots = sorted(
        {
            cwd.resolve(),
            Path(tempfile.gettempdir()).resolve(),
            Path("/tmp").resolve(),
            Path("/var/tmp").resolve(),
        },
        key=lambda path: len(path.parts),
        reverse=True,
    )
    return next(
        (root for root in roots if candidate == root or candidate.is_relative_to(root)),
        None,
    )


def _ancestor_chain_is_controlled(candidate: Path, *, root: Path) -> bool:
    current_uid = _current_uid()
    if current_uid is None:
        # Windows workspaces and per-user temporary directories are ACL-bound;
        # there is no portable stdlib UID or ACL-owner API to duplicate here.
        return True
    current = candidate.parent
    while current != root:
        if not _private_directory_owned_by_current_user(current, uid=current_uid):
            return False
        parent = current.parent
        if parent == current or not current.is_relative_to(root):
            return False
        current = parent
    try:
        metadata = root.stat()
    except OSError:
        return False
    if _private_directory_owned_by_current_user(root, uid=current_uid, metadata=metadata):
        return True
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid in {0, current_uid}
        and metadata.st_mode & stat.S_ISVTX
        and metadata.st_mode & stat.S_IWOTH
    )


def _current_uid() -> int | None:
    getuid = cast(Callable[[], int] | None, getattr(os, "getuid", None))
    return None if getuid is None else getuid()


def _private_directory_owned_by_current_user(
    path: Path,
    *,
    uid: int,
    metadata: os.stat_result | None = None,
) -> bool:
    try:
        resolved_metadata = path.stat() if metadata is None else metadata
    except OSError:
        return False
    return bool(
        stat.S_ISDIR(resolved_metadata.st_mode)
        and resolved_metadata.st_uid == uid
        and not resolved_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def _path_looks_sensitive(candidate: Path) -> bool:
    parts = {part.casefold() for part in candidate.parts}
    if parts.intersection({".aws", ".docker", ".gnupg", ".kube", ".ssh"}):
        return True
    name = candidate.name.casefold()
    return name.startswith((".env", "credentials", "id_rsa", "id_ed25519", "secrets", "token"))


def _is_pr_body_markdown_name(name: str) -> bool:
    normalized = name.casefold()
    return normalized in {"pr-body.md", "pr-body.markdown"} or normalized.endswith(("-pr-body.md", "-pr-body.markdown"))
