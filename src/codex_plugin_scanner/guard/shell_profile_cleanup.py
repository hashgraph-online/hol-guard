"""Helpers for removing Guard-managed shell profile blocks."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Protocol


class HarnessContextLike(Protocol):
    @property
    def home_dir(self) -> Path: ...


def remove_guard_profile_blocks(
    context: HarnessContextLike,
    *,
    strip_managed_marker_blocks: Callable[[str, str], str],
    guard_profile_marker: str,
    package_profile_marker: str,
) -> dict[str, object]:
    if os.name == "nt":
        return {
            "changed": False,
            "changed_paths": [],
            "removed_paths": [],
            "markers_removed": [guard_profile_marker, package_profile_marker],
        }
    changed_paths: list[str] = []
    removed_paths: list[str] = []
    for profile_path in _managed_shell_profile_paths(context.home_dir):
        if not profile_path.exists():
            continue
        existing = profile_path.read_text(encoding="utf-8")
        if guard_profile_marker not in existing and package_profile_marker not in existing:
            continue
        cleaned = existing
        if guard_profile_marker in cleaned:
            cleaned = strip_managed_marker_blocks(cleaned, guard_profile_marker)
        if package_profile_marker in cleaned:
            cleaned = strip_managed_marker_blocks(cleaned, package_profile_marker)
        if cleaned == existing:
            continue
        if cleaned:
            profile_path.write_text(cleaned, encoding="utf-8")
        else:
            profile_path.unlink()
            removed_paths.append(str(profile_path))
        changed_paths.append(str(profile_path))
    return {
        "changed": bool(changed_paths),
        "changed_paths": changed_paths,
        "removed_paths": removed_paths,
        "markers_removed": [guard_profile_marker, package_profile_marker],
    }


def _managed_shell_profile_paths(home_dir: Path) -> tuple[Path, ...]:
    return (
        home_dir / ".bashrc",
        home_dir / ".zshrc",
        home_dir / ".config" / "fish" / "config.fish",
    )


__all__ = ["remove_guard_profile_blocks"]
