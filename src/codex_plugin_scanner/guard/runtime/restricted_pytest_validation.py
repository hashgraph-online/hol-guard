"""Native restricted-launch validation and shared lexical path predicates."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..native_restricted_pytest import restricted_native


def _normalized_command(command: Sequence[str]) -> tuple[str, ...]:
    return tuple(restricted_native("normalized_command", {"command": [str(item) for item in command]}, list))


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        _ = path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        return False
    return True
