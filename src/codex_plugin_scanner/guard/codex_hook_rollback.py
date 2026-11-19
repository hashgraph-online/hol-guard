"""Preserve observed competing configuration writes during Codex rollback.

The resident reads the identities and the bytes; see
``rust/crates/guard-runtime/src/transition_files/publication_io.rs``.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any


def _publication(op: str, path: Path, **fields: Any) -> object:
    from .native_transition_files import publication

    target = os.path.abspath(path.expanduser())
    return publication(op, Path(target), path=target, **fields)


def _identity(value: object) -> tuple[int, int, int, int, int] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) != 5 or not all(type(part) is int for part in value):
        from .codex_hook_file_integrity import CodexHookIntegrityError

        raise CodexHookIntegrityError("codex_hook_rollback_conflict", "codex_hook_rollback_conflict")
    return (value[0], value[1], value[2], value[3], value[4])


def rollback_file_identity(path: Path) -> tuple[int, int, int, int, int] | None:
    """``(st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)`` of a single-link regular file."""
    return _identity(_publication("identity", path))


def _encoded(value: bytes | None) -> str | None:
    return None if value is None else base64.b64encode(value).decode("ascii")


def require_unchanged_config_for_rollback(
    path: Path,
    original: bytes | None,
    written: bytes,
    *,
    original_identity: tuple[int, int, int, int, int] | None,
    written_identity: tuple[int, int, int, int, int] | None,
) -> None:
    """Check under the lifecycle lock; this does not fence non-cooperating writers."""
    _publication(
        "rollback_check",
        path,
        original=_encoded(original),
        written=_encoded(written),
        original_identity=list(original_identity) if original_identity is not None else None,
        written_identity=list(written_identity) if written_identity is not None else None,
    )
