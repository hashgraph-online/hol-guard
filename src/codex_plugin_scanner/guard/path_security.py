"""Shared path-boundary and symlink checks."""

from __future__ import annotations

from pathlib import Path


def path_has_symlink_component(path: Path, *, allowed_root: Path) -> bool:
    """Return true when a path escapes the root or traverses a symlink component."""

    try:
        relative = path.relative_to(allowed_root)
    except ValueError:
        return True
    current = allowed_root
    if current.is_symlink():
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False
