"""Frozen previous Pi managed extension source, rendered natively."""

from __future__ import annotations

from pathlib import Path

from ..codex_hook_windows_job import windows_system_executable_path
from .pi_extension_source import render_pi_extension_source


def previous_managed_extension_source(
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str = "pi",
    display_name: str = "Pi",
) -> str:
    return render_pi_extension_source(
        "previous",
        guard_home=guard_home,
        home_dir=home_dir,
        settings_path=settings_path,
        harness=harness,
        display_name=display_name,
        package_source=Path(__file__),
        taskkill_lookup=windows_system_executable_path,
    )
