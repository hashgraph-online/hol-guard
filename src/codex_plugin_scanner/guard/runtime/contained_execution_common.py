"""Low-level, side-effect-free helpers shared by contained execution paths."""

from __future__ import annotations

import os
from pathlib import Path

_ALLOWED_ENVIRONMENT_KEYS = ("LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM")
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024


def canonical_existing_directory(path: Path) -> Path:
    """Resolve one existing directory while rejecting symlinks and path aliases."""

    if path.is_symlink() or not path.is_dir():
        raise ValueError("workspace must be an existing canonical directory")
    canonical = path.resolve(strict=True)
    if canonical != Path(os.path.normpath(str(path))):
        raise ValueError("workspace cannot contain aliases")
    return canonical


def clean_containment_environment(environment: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Retain only non-sensitive presentation variables for a contained child."""

    return tuple(sorted((key, value) for key in _ALLOWED_ENVIRONMENT_KEYS if (value := environment.get(key))))


__all__ = [
    "canonical_existing_directory",
    "clean_containment_environment",
]
