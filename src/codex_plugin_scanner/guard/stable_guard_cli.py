"""Stable Guard CLI resolution for Desktop-managed frozen runtimes.

Desktop Core lives under ``versions/<release>/`` or ``bundled/<release>/`` and
those directories can be replaced on update. Hooks and package-manager shims
must not bake either ephemeral path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

MACOS_BUNDLED_HOL_GUARD = Path("/Applications/HOL Guard.app/Contents/MacOS/hol-guard")
CURRENT_HOL_GUARD_SHIM = "current-hol-guard"


def desktop_core_shim_for_executable(executable: Path) -> Path | None:
    """Return the stable ``current-hol-guard`` launcher next to a versioned Core."""

    parent = _desktop_core_root(executable)
    if parent is None:
        return None
    unix = parent / CURRENT_HOL_GUARD_SHIM
    windows = parent / f"{CURRENT_HOL_GUARD_SHIM}.cmd"
    if sys.platform == "win32":
        if windows.is_file():
            return windows
        if unix.is_file():
            return unix
        return windows
    return unix


def _desktop_core_root(executable: Path) -> Path | None:
    executable_name = executable.name.lower()
    if executable_name not in {"hol-guard", "hol-guard.exe"}:
        return None
    for ancestor in executable.parents:
        ancestor_name = ancestor.name.lower()
        try:
            relative_parts = executable.relative_to(ancestor).parts
        except ValueError:
            continue
        if ancestor_name == "versions" and len(relative_parts) == 2:
            return ancestor.parent
        if ancestor_name != "bundled":
            continue
        if len(relative_parts) == 3 and relative_parts[1] == "bin":
            return ancestor.parent
        if len(relative_parts) == 4 and relative_parts[1:3] == ("lib", "hol-guard-core"):
            return ancestor.parent
    return None


def frozen_cli_path_is_runnable(path: Path) -> bool:
    """Return whether a frozen launcher can be executed as argv0."""

    if not path.is_file():
        return False
    if os.name == "nt":
        return True
    return os.access(path, os.X_OK)


def resolve_frozen_guard_cli() -> str:
    """Return a prune-safe frozen launcher, then the process executable.

    The macOS app-bundle Core is only used when this process is a Desktop
    versioned runtime. Other frozen layouts keep ``sys.executable``.
    """

    executable = Path(sys.executable)
    shim = desktop_core_shim_for_executable(executable)
    if shim is not None and frozen_cli_path_is_runnable(shim):
        return str(shim)
    versioned_desktop = shim is not None
    if versioned_desktop and sys.platform == "darwin" and frozen_cli_path_is_runnable(MACOS_BUNDLED_HOL_GUARD):
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


def uses_top_level_hook_command(guard_cli: list[str]) -> bool:
    """Return whether argv0 exposes `hook` without a `guard` prefix."""

    if not guard_cli:
        return False
    name = Path(guard_cli[0]).name.lower()
    return name in {
        "hol-guard",
        "hol-guard.exe",
        "plugin-guard",
        "plugin-guard.exe",
        CURRENT_HOL_GUARD_SHIM,
        f"{CURRENT_HOL_GUARD_SHIM}.cmd",
        f"{CURRENT_HOL_GUARD_SHIM}.exe",
    }


def argv0_is_ephemeral_desktop_cli(argv0: str) -> bool:
    """Return whether argv0 lives under a pruneable Desktop `versions/` path."""

    return desktop_core_shim_for_executable(Path(argv0)) is not None


def prune_safe_cli_executable(executable: str) -> str:
    """Prefer the Desktop current-hol-guard shim over a pruneable versions path."""

    shim = desktop_core_shim_for_executable(Path(executable))
    if shim is None or not frozen_cli_path_is_runnable(shim):
        return executable
    if sys.platform == "win32" and shim.suffix.lower() not in {".cmd", ".bat", ".exe"}:
        return executable
    return str(shim)


def frozen_launcher_is_prune_safe(launcher: str) -> bool:
    """Return whether a frozen launcher survives Desktop Core prune."""

    return desktop_core_shim_for_executable(Path(launcher)) is None


__all__ = [
    "CURRENT_HOL_GUARD_SHIM",
    "MACOS_BUNDLED_HOL_GUARD",
    "argv0_is_ephemeral_desktop_cli",
    "desktop_core_shim_for_executable",
    "frozen_cli_path_is_runnable",
    "frozen_launcher_is_prune_safe",
    "prune_safe_cli_executable",
    "resolve_frozen_guard_cli",
    "resolve_guard_cli_argv0",
    "resolved_guard_cli",
    "trusted_frozen_guard_cli_paths",
    "uses_top_level_hook_command",
]
