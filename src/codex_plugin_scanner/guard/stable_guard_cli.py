"""Stable Guard CLI resolution for Desktop-managed frozen runtimes.

Desktop Core lives under ``versions/<release>/`` and that directory is pruned
on update. Hooks and package-manager shims must not bake that ephemeral path.
"""

from __future__ import annotations

import sys
from pathlib import Path

MACOS_BUNDLED_HOL_GUARD = Path("/Applications/HOL Guard.app/Contents/MacOS/hol-guard")
CURRENT_HOL_GUARD_SHIM = "current-hol-guard"


def desktop_core_shim_for_executable(executable: Path) -> Path | None:
    """Return the stable ``current-hol-guard`` launcher next to a versioned Core."""

    versions_dir = executable.parent.parent
    if versions_dir.name != "versions":
        return None
    parent = versions_dir.parent
    unix = parent / CURRENT_HOL_GUARD_SHIM
    windows = parent / f"{CURRENT_HOL_GUARD_SHIM}.cmd"
    if sys.platform == "win32":
        if windows.is_file():
            return windows
        if unix.is_file():
            return unix
        return windows
    return unix


def resolve_frozen_guard_cli() -> str:
    """Return a prune-safe frozen launcher, then the process executable.

    The macOS app-bundle Core is only used when this process is a Desktop
    versioned runtime. Other frozen layouts keep ``sys.executable``.
    """

    executable = Path(sys.executable)
    shim = desktop_core_shim_for_executable(executable)
    if shim is not None and shim.is_file():
        return str(shim)
    versioned_desktop = shim is not None
    if versioned_desktop and sys.platform == "darwin" and MACOS_BUNDLED_HOL_GUARD.is_file():
        return str(MACOS_BUNDLED_HOL_GUARD)
    return sys.executable


def resolve_guard_cli_argv0(baked_argv0: str) -> str:
    """Resolve a baked Guard CLI argv0 to a currently executable path."""

    path = Path(baked_argv0)
    if path.is_file():
        return baked_argv0
    shim = desktop_core_shim_for_executable(path)
    if shim is not None and shim.is_file():
        return str(shim)
    if sys.platform == "darwin" and MACOS_BUNDLED_HOL_GUARD.is_file():
        return str(MACOS_BUNDLED_HOL_GUARD)
    return baked_argv0


def resolved_guard_cli(guard_cli: list[str]) -> list[str]:
    if not guard_cli:
        return guard_cli
    argv0 = resolve_guard_cli_argv0(guard_cli[0])
    if argv0 == guard_cli[0]:
        return guard_cli
    return [argv0, *guard_cli[1:]]


def trusted_frozen_guard_cli_paths() -> frozenset[str]:
    """Interpreters a frozen Core process may trust as a package-shim shebang."""

    trusted = {sys.executable, resolve_frozen_guard_cli()}
    shim = desktop_core_shim_for_executable(Path(sys.executable))
    if shim is not None:
        trusted.add(str(shim))
    if MACOS_BUNDLED_HOL_GUARD.is_file():
        trusted.add(str(MACOS_BUNDLED_HOL_GUARD))
    return frozenset(trusted)


__all__ = [
    "CURRENT_HOL_GUARD_SHIM",
    "MACOS_BUNDLED_HOL_GUARD",
    "desktop_core_shim_for_executable",
    "resolve_frozen_guard_cli",
    "resolve_guard_cli_argv0",
    "resolved_guard_cli",
    "trusted_frozen_guard_cli_paths",
]
