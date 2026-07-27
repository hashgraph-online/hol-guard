from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


def trusted_temporary_root_for_path(candidate: Path) -> Path | None:
    if not _is_lexically_temporary_path(candidate):
        return None
    # codeql[py/path-injection] Candidate is absolute, traversal-free, and temp-contained.
    resolved_candidate = candidate.resolve(strict=True)
    roots = [Path(tempfile.gettempdir())]
    if os.name == "posix":
        roots.extend((Path("/tmp"), Path("/var/tmp")))
    if sys.platform == "darwin":
        roots.extend((Path("/private/tmp"), Path("/private/var/tmp")))
    for root in roots:
        try:
            resolved_root = root.resolve(strict=True)
        except OSError:
            continue
        if resolved_candidate.is_relative_to(resolved_root):
            return resolved_root

    darwin_root = _darwin_user_temporary_root(resolved_candidate)
    if darwin_root is None or not _owned_by_current_user(darwin_root):
        return None
    return darwin_root


def _is_lexically_temporary_path(candidate: Path) -> bool:
    if not candidate.is_absolute() or ".." in candidate.parts:
        return False

    roots = [Path(tempfile.gettempdir())]
    if os.name == "posix":
        roots.extend((Path("/tmp"), Path("/var/tmp")))
    if sys.platform == "darwin":
        roots.extend((Path("/private/tmp"), Path("/private/var/tmp")))
    if any(candidate.is_relative_to(root) for root in roots if root.is_absolute()):
        return True
    return _darwin_user_temporary_root(candidate) is not None


def _darwin_user_temporary_root(candidate: Path) -> Path | None:
    if sys.platform != "darwin":
        return None
    parts = candidate.parts
    for prefix in (("/", "var", "folders"), ("/", "private", "var", "folders")):
        prefix_length = len(prefix)
        root_length = prefix_length + 3
        if (
            parts[:prefix_length] == prefix
            and len(parts) >= root_length
            and len(parts[prefix_length]) == 2
            and parts[prefix_length + 1]
            and parts[prefix_length + 2] == "T"
        ):
            root = Path(*parts[:root_length])
            return root if root.is_dir() else None
    return None


def _owned_by_current_user(path: Path) -> bool:
    getuid = getattr(os, "getuid", None)
    if not callable(getuid):
        return False
    try:
        return path.stat().st_uid == getuid()
    except OSError:
        return False


__all__ = ["trusted_temporary_root_for_path"]
