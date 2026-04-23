"""Shared path validation and normalization helpers."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

REMOTE_PREFIXES = ("https://", "git+", "github://")


def is_remote_reference(value: str) -> bool:
    return value.startswith(REMOTE_PREFIXES)


def is_dot_relative_path(value: str) -> bool:
    return value.startswith("./")


def resolves_within_root(root: Path, candidate: Path, *, require_exists: bool = False) -> bool:
    try:
        resolved_root = root.resolve()
        resolved_candidate = candidate.resolve()
    except (OSError, RuntimeError):
        return False
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError:
        return False
    return not (require_exists and not resolved_candidate.exists())


def is_safe_relative_path(
    root: Path,
    value: str,
    *,
    require_prefix: bool = False,
    require_exists: bool = False,
) -> bool:
    candidate = Path(value)
    if candidate.is_absolute():
        return False
    if require_prefix and not is_dot_relative_path(value):
        return False
    return resolves_within_root(root, root / candidate, require_exists=require_exists)


def iter_safe_matching_files(root: Path, base_dir: Path, pattern: str) -> tuple[Path, ...]:
    try:
        resolved_root = root.resolve()
    except OSError:
        return ()
    if not base_dir.is_dir() or not resolves_within_root(resolved_root, base_dir, require_exists=True):
        return ()
    return tuple(
        candidate
        for candidate in sorted(base_dir.glob(pattern))
        if candidate.is_file() and resolves_within_root(resolved_root, candidate, require_exists=True)
    )


def normalize_codex_relative_path(value: str) -> str:
    if not value or is_remote_reference(value):
        return value
    if urlparse(value).scheme or Path(value).is_absolute():
        return value
    if value.startswith("./") or value.startswith("../"):
        return value
    return f"./{value}"
