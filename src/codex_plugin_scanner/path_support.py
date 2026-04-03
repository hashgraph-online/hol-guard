"""Shared path validation and normalization helpers."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

REMOTE_PREFIXES = ("https://", "git+", "github://")


def is_remote_reference(value: str) -> bool:
    return value.startswith(REMOTE_PREFIXES)


def is_dot_relative_path(value: str) -> bool:
    return value.startswith("./")


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
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return False
    return not (require_exists and not resolved.exists())


def normalize_codex_relative_path(value: str) -> str:
    if not value or is_remote_reference(value):
        return value
    if urlparse(value).scheme or Path(value).is_absolute():
        return value
    if value.startswith("./") or value.startswith("../"):
        return value
    return f"./{value}"
