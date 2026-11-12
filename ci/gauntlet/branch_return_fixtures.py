"""The branch a session returns to when it writes ``-`` instead of the name.

``git switch -`` and ``git checkout -`` name the branch Git left last. The
checkout the case runs in is a linked worktree on ``feature``, so the pair of
switches ends where it started, and the branch it opened on the way stays.
"""

from __future__ import annotations

from pathlib import Path

BRANCH_RETURN_CASE = "omp-native-git-switch-previous-branch"
BRANCH_RETURN_STARTING_BRANCH = "feature"
BRANCH_RETURN_OPENED_BRANCH = "fix/report-window-notes"


def _git_dir(worktree: Path) -> Path | None:
    """A linked worktree's ``.git`` is a file naming its directory; a plain one is the directory."""
    marker = worktree / ".git"
    if marker.is_dir():
        return marker
    try:
        pointer = marker.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None
    return Path(pointer.removeprefix("gitdir: ")) if pointer.startswith("gitdir: ") else None


def branch_return_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The worktree is back on its own branch, and the branch it opened is still there."""
    if scenario_id != BRANCH_RETURN_CASE:
        return {}
    git_dir = _git_dir(workspace)
    if git_dir is None:
        return {"git-switch-returned-to-previous-branch": False, "git-switch-opened-branch-kept": False}
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        head = ""
    # A linked worktree keeps its own HEAD under ``.git/worktrees/<name>``
    # while every worktree shares the branches in the main ``.git``.
    common = git_dir.parent.parent if git_dir.parent.name == "worktrees" else git_dir
    reference = f"refs/heads/{BRANCH_RETURN_OPENED_BRANCH}"
    opened = (common / reference).is_file()
    if not opened:
        try:
            packed = (common / "packed-refs").read_text(encoding="utf-8").split()
        except (OSError, UnicodeError):
            packed = []
        opened = reference in packed
    return {
        "git-switch-returned-to-previous-branch": head == f"ref: refs/heads/{BRANCH_RETURN_STARTING_BRANCH}",
        "git-switch-opened-branch-kept": opened,
    }
