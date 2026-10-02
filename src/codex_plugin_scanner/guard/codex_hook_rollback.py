"""Preserve observed competing configuration writes during Codex rollback."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def _conflict() -> RuntimeError:
    return RuntimeError(
        "codex_hook_rollback_conflict: Codex configuration changed during the failed transaction; "
        + "Guard preserved it and could not restore the previous hook state."
    )


def _state(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def rollback_file_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise _conflict()
    return _state(metadata)


def require_unchanged_config_for_rollback(
    path: Path,
    original: bytes | None,
    written: bytes,
    *,
    original_identity: tuple[int, int, int, int, int] | None,
    written_identity: tuple[int, int, int, int, int] | None,
) -> None:
    """Check under the lifecycle lock; this does not fence non-cooperating writers."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        if original is None and written_identity is None:
            return
        raise _conflict() from None
    except OSError as error:
        raise _conflict() from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise _conflict()
    limit = max(len(original or b""), len(written))
    if before.st_size > limit:
        raise _conflict()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                opened = os.fstat(handle.fileno())
                if _state(opened) != _state(before):
                    raise _conflict()
                current = handle.read(limit + 1)
                after = os.fstat(handle.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if _state(after) != _state(opened) or _state(path.lstat()) != _state(after):
            raise _conflict()
    except OSError as error:
        raise _conflict() from error
    identity = _state(after)
    if not (
        (original is not None and current == original and identity == original_identity)
        or (written_identity is not None and current == written and identity == written_identity)
    ):
        raise _conflict()
