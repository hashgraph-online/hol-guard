"""Pi-family extension sources the native runtime renders, for tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.native_extension import extension_source


def _render(variant: str, *, guard_home: Path, home_dir: Path, settings_path: Path, harness: str) -> str:
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)
    return extension_source(harness, context, variant=variant, config_path=settings_path)


def managed_extension_source(
    *, guard_home: Path, home_dir: Path, settings_path: Path, harness: str = "pi", display_name: str = "Pi"
) -> str:
    """The active extension source; ``display_name`` follows ``harness``."""
    del display_name
    return _render("active", guard_home=guard_home, home_dir=home_dir, settings_path=settings_path, harness=harness)


def previous_managed_extension_source(
    *, guard_home: Path, home_dir: Path, settings_path: Path, harness: str = "pi", display_name: str = "Pi"
) -> str:
    """The frozen previous extension source."""
    del display_name
    return _render("previous", guard_home=guard_home, home_dir=home_dir, settings_path=settings_path, harness=harness)


__all__ = ["managed_extension_source", "previous_managed_extension_source"]
