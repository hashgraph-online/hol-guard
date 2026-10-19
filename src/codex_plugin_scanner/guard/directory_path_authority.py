"""Canonical spelling of a Guard home, for identity bindings and cache keys.

Whether a request may name a directory is a Guard verdict, and the native
runtime owns it; `native_directory_trust` asks for it. What stays here is
transport: the key a caller needs before it can reach the resident at all.
"""

from __future__ import annotations

import os
from pathlib import Path

from .path_resolution_cache import cached_realpath


def canonical_guard_home_path(guard_home: Path | str) -> str:
    """Canonical spelling of a Guard home for identity bindings and cache keys.

    Resolves ``~``, relative components, and symlinks so the same directory
    spelled differently cannot duplicate identity-scoped state.
    """
    expanded = Path(guard_home).expanduser()
    try:
        candidate = cached_realpath(os.fspath(expanded))
    except OSError:
        candidate = os.fspath(expanded)
    return os.path.normpath(candidate)
