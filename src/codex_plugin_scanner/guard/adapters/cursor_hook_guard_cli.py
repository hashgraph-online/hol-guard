"""Stable Guard CLI resolution for Cursor frozen hooks."""

from __future__ import annotations

from ..stable_guard_cli import (
    CURRENT_HOL_GUARD_SHIM,
    MACOS_BUNDLED_HOL_GUARD,
    desktop_core_shim_for_executable,
    resolve_frozen_guard_cli,
    resolve_guard_cli_argv0,
    resolved_guard_cli,
    trusted_frozen_guard_cli_paths,
)

resolve_frozen_cursor_hook_launcher = resolve_frozen_guard_cli
resolve_cursor_hook_guard_cli_argv0 = resolve_guard_cli_argv0
resolved_cursor_hook_guard_cli = resolved_guard_cli

HOOK_SCRIPT_TEMPLATE_RESOLVER = """
_MACOS_BUNDLED_HOL_GUARD = Path("/Applications/HOL Guard.app/Contents/MacOS/hol-guard")
_CURRENT_HOL_GUARD_SHIM = "current-hol-guard"


def _desktop_core_shim_for_executable(executable: Path) -> Path | None:
    versions_dir = executable.parent.parent
    if versions_dir.name == "versions":
        parent = versions_dir.parent
    elif len(executable.parents) > 4 and executable.parents[3].name == "bundled":
        parent = executable.parents[4]
    else:
        return None
    unix = parent / _CURRENT_HOL_GUARD_SHIM
    windows = parent / f"{_CURRENT_HOL_GUARD_SHIM}.cmd"
    if os.name == "nt":
        if windows.is_file():
            return windows
        if unix.is_file():
            return unix
        return windows
    return unix


def _resolve_cursor_hook_guard_cli_argv0(baked_argv0: str) -> str:
    path = Path(baked_argv0)
    if path.is_file():
        return baked_argv0
    shim = _desktop_core_shim_for_executable(path)
    if shim is not None and shim.is_file():
        return str(shim)
    if shim is not None and sys.platform == "darwin" and _MACOS_BUNDLED_HOL_GUARD.is_file():
        return str(_MACOS_BUNDLED_HOL_GUARD)
    return baked_argv0


def _resolved_guard_cli() -> list[str]:
    if not GUARD_CLI:
        return GUARD_CLI
    argv0 = _resolve_cursor_hook_guard_cli_argv0(GUARD_CLI[0])
    if argv0 == GUARD_CLI[0]:
        return GUARD_CLI
    return [argv0, *GUARD_CLI[1:]]

"""

__all__ = [
    "CURRENT_HOL_GUARD_SHIM",
    "HOOK_SCRIPT_TEMPLATE_RESOLVER",
    "MACOS_BUNDLED_HOL_GUARD",
    "desktop_core_shim_for_executable",
    "resolve_cursor_hook_guard_cli_argv0",
    "resolve_frozen_cursor_hook_launcher",
    "resolved_cursor_hook_guard_cli",
    "trusted_frozen_guard_cli_paths",
]
