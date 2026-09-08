"""Filesystem cleanup helpers for deprecated project-local Cursor hooks."""

from __future__ import annotations

from pathlib import Path


def prune_empty_project_cursor_dir(workspace_dir: Path) -> None:
    hooks_dir = workspace_dir / ".cursor" / "hooks"
    cursor_dir = workspace_dir / ".cursor"
    if hooks_dir.is_dir():
        try:
            if not any(hooks_dir.iterdir()):
                hooks_dir.rmdir()
        except OSError:
            return
    if not cursor_dir.is_dir():
        return
    try:
        remaining = list(cursor_dir.iterdir())
    except OSError:
        return
    if not remaining:
        try:
            cursor_dir.rmdir()
        except OSError:
            return
