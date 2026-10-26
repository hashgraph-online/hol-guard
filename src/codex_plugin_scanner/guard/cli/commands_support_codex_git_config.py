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


def _git_dir_from_file(git_file: Path) -> Path | None:
    try:
        content = git_file.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None
    prefix = "gitdir:"
    if not content.lower().startswith(prefix):
        return None
    raw_path = content[len(prefix) :].strip()
    git_dir = Path(raw_path)
    if not git_dir.is_absolute():
        git_dir = (git_file.parent / git_dir).resolve()
    return git_dir


def _git_common_dir(git_dir: Path) -> Path:
    common_dir_file = git_dir / "commondir"
    if not common_dir_file.is_file():
        return git_dir
    try:
        raw_path = common_dir_file.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return git_dir
    common_dir = Path(raw_path)
    if not common_dir.is_absolute():
        common_dir = (git_dir / common_dir).resolve()
    return common_dir


git_dir_from_file = _git_dir_from_file


git_common_dir = _git_common_dir


__all__ = ["_git_repo_root", "git_common_dir", "git_dir_from_file"]
