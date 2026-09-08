"""Atomic adapter writes beneath a caller-authorized parent directory."""

from __future__ import annotations

from pathlib import Path

from ...safe_output import write_text_atomic_no_follow


def write_text_at_authorized_path(path: Path, payload: str) -> None:
    """Resolve an authorized parent without following a final-path symlink."""

    target = path.parent.resolve(strict=True) / path.name
    write_text_atomic_no_follow(target, payload)
