"""Stable Guard CLI resolution for Cursor frozen hooks."""

from __future__ import annotations

import sys

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

__all__ = [
    "CURRENT_HOL_GUARD_SHIM",
    "MACOS_BUNDLED_HOL_GUARD",
    "desktop_core_shim_for_executable",
    "resolve_cursor_hook_guard_cli_argv0",
    "resolve_frozen_cursor_hook_launcher",
    "resolved_cursor_hook_guard_cli",
    "trusted_frozen_guard_cli_paths",
]
