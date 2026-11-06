"""Shared path anchoring for the native resident bridges."""

from __future__ import annotations

import os


def anchor_to_process_directory(path: str | os.PathLike[str]) -> str:
    """Anchor a relative path to this process's directory; no normalization.

    The resident resolves relative paths against its own directory, so callers
    anchor them here. Symlink and ``..`` resolution stays in Rust.
    """

    text = os.fspath(path)
    return text if os.path.isabs(text) else os.path.join(os.getcwd(), text)
