"""Git directory helpers for Guard CLI workspace and patch handling."""

from __future__ import annotations

from pathlib import Path


def _git_repo_root(cwd: Path) -> Path | None:
    current = cwd.absolute()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


__all__ = ["_git_repo_root"]
