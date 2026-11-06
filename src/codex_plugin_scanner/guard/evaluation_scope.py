"""Filesystem scope checks shared by evaluation setup and witnesses."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


def _safe_temp_parent(path: Path) -> bool:
    """Require a private owned directory below the process temporary root."""

    try:
        if "\x00" in str(path) or path.is_symlink() or not path.is_dir():
            return False
        candidate = os.path.realpath(os.fspath(path))
    except (OSError, RuntimeError):
        return False

    if os.name == "nt":
        if candidate.startswith("\\\\"):
            return False
        temp_root = os.path.normcase(os.path.normpath(os.path.realpath(tempfile.gettempdir())))
        candidate_normalized = os.path.normcase(os.path.normpath(candidate))
        try:
            return (
                candidate_normalized != temp_root and os.path.commonpath((candidate_normalized, temp_root)) == temp_root
            )
        except ValueError:
            return False

    root = os.path.realpath(tempfile.gettempdir())
    try:
        if os.path.commonpath((candidate, root)) != root or candidate == root:
            return False
        details = path.stat()
        return details.st_uid == os.getuid() and stat.S_IMODE(details.st_mode) & 0o077 == 0
    except (OSError, ValueError):
        return False
