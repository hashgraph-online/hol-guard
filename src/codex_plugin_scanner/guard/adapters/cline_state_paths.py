"""Validated persisted-path and launcher handling for managed Cline hooks.

The native ``cline_paths`` kind binds recorded paths to their slots and removes
managed hooks; Python keeps the PowerShell lookup for the hook command.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..windows_paths import trusted_windows_system_executable
from .base import HarnessContext
from .cline_paths import ask_cline_paths


def _recorded(value: object) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    return {key: item for key, item in value.items() if isinstance(key, str) and isinstance(item, str)}


def _bound(value: object) -> dict[str, Path]:
    if not isinstance(value, dict):
        raise RuntimeError("HOL Guard native runtime returned malformed Cline hook paths")
    return {event: Path(path) for event, path in value.items() if isinstance(path, str)}


def bound_cline_state_paths(
    context: HarnessContext, state: Mapping[str, object]
) -> tuple[dict[str, Path], dict[str, Path]]:
    """The launcher and worker paths recorded at install that still bind to their slots."""

    paths, workers = _recorded(state.get("paths")), _recorded(state.get("workers"))
    if paths is None and workers is None:
        # Nothing was recorded, so nothing can bind.
        return {}, {}
    root = state.get("root")
    answer = ask_cline_paths(
        context, "state_paths", paths=paths, workers=workers, root=root if isinstance(root, str) else None
    )
    return _bound(answer.get("paths")), _bound(answer.get("workers"))


def cline_hook_command(path: Path) -> list[str]:
    """Build a hook command without resolving an interpreter from ambient PATH."""

    if path.suffix.lower() != ".ps1":
        return [str(path)]
    try:
        shell = trusted_windows_system_executable("WindowsPowerShell", "v1.0", "powershell.exe")
    except OSError:
        return []
    return [str(shell), "-NoProfile", "-File", str(path)]


def uninstall_persisted_cline_hooks(context: HarnessContext) -> dict[str, object]:
    """Remove only managed hooks still bound to their persisted canonical slots."""

    return ask_cline_paths(context, "uninstall")


__all__ = ["bound_cline_state_paths", "cline_hook_command", "uninstall_persisted_cline_hooks"]
