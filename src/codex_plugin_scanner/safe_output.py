"""No-follow output helpers for scanner-controlled artifacts."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def _reject_untrusted_parent_symlinks(path: Path) -> None:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parent.parts[1:]:
        if part in {"", "."}:
            continue
        current = current / part
        if current.is_symlink():
            metadata = current.lstat()
            parent_metadata = current.parent.lstat()
            trusted_system_link = (
                hasattr(os, "geteuid")
                and metadata.st_uid == 0
                and parent_metadata.st_uid == 0
                and not parent_metadata.st_mode & 0o022
            )
            if not trusted_system_link:
                raise OSError(f"refusing symlinked output directory: {current}")
        if not current.exists():
            break


def write_bytes_atomic_no_follow(path: Path, payload: bytes) -> None:
    """Atomically replace an output path without following its final symlink."""
    _reject_untrusted_parent_symlinks(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    target = parent / path.name
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_text_atomic_no_follow(path: Path, payload: str, *, encoding: str = "utf-8") -> None:
    write_bytes_atomic_no_follow(path, payload.encode(encoding))
