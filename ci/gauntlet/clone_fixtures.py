"""A years-old clone: thousands of tracked branches and commits signed by default.

Real sessions in such a clone had ordinary branch work held for review. Every
``branch.<name>.remote`` and ``.merge`` pair stays in ``.git/config`` long after
the branch is gone, which pushes the configuration listing past a quarter
megabyte, and ``commit.gpgsign`` is common on maintainers' checkouts. Neither
runs code for a branch switch, an index update, a configuration read or a new
linked worktree.

A maintainer's checkout also keeps settings that point outside the work tree:
``core.hooksPath`` names an empty directory under home and
``credential.helper`` answers Git from a shell function. An ordinary edit in a
linked worktree of that checkout is contained exactly as in a plain clone.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

LONG_LIVED_CLONE_CASE = "omp-native-git-long-lived-clone-branch-work"
LONG_LIVED_BRANCH = "fix/report-notes"
LONG_LIVED_CONFIG_MIN_BYTES = 256 * 1024 + 4096
# The same clone, adding sibling worktrees for an existing branch and a new one.
LONG_LIVED_WORKTREE_CASE = "omp-native-git-long-lived-clone-worktree-add"
LONG_LIVED_EXISTING_BRANCH = "fix/report-export"
LONG_LIVED_NEW_BRANCH = "fix/report-followup"
LONG_LIVED_WORKTREES = {
    "project-report-fix": LONG_LIVED_EXISTING_BRANCH,
    "project-report-followup": LONG_LIVED_NEW_BRANCH,
    "reviews/pending/report": "fix/report-nested",
}
HOME_HOOKS_CASE = "omp-native-home-hooks-clone-notes-edit"
HOME_HOOKS_NOTES = "docs/release-notes.md"
HOME_HOOKS_HELPER = (
    '!f() { echo "username=x-access-token"; echo "password=$(gh auth token --hostname github.com)"; }; f'
)


def long_lived_clone_config() -> str:
    """Retired branch tracking plus default signing; no includes, programs or credentials."""
    parts = ["[commit]\n\tgpgsign = true\n"]
    size = len(parts[0])
    index = 0
    while size < LONG_LIVED_CONFIG_MIN_BYTES:
        name = f"retired/b{index:05d}"
        section = f'[branch "{name}"]\n\tremote = origin\n\tmerge = refs/heads/{name}\n'
        parts.append(section)
        size += len(section)
        index += 1
    return "".join(parts)


def add_long_lived_clone_config(main: Path, scenario_id: str | None, environment: dict[str, str]) -> None:
    """Append the shape to the main checkout's config, which its linked worktrees share."""
    if scenario_id == HOME_HOOKS_CASE:
        (main.parent / ".app-hooks/empty").mkdir(parents=True, exist_ok=True)
        for arguments in (
            ("config", "core.hooksPath", "~/.app-hooks/empty"),
            ("config", "credential.helper", HOME_HOOKS_HELPER),
        ):
            subprocess.run(["git", *arguments], cwd=main, env=environment, check=True, capture_output=True)
        notes = main.parent / "project-feature" / HOME_HOOKS_NOTES
        notes.write_text("Draft release notes.\n", encoding="utf-8", newline="\n")
        return
    if scenario_id not in {LONG_LIVED_CLONE_CASE, LONG_LIVED_WORKTREE_CASE}:
        return
    if scenario_id == LONG_LIVED_WORKTREE_CASE:
        # An existing local branch, and the upstream a new branch starts from.
        for arguments in (
            ("branch", LONG_LIVED_EXISTING_BRANCH),
            ("update-ref", "refs/remotes/origin/main", "HEAD"),
        ):
            subprocess.run(["git", *arguments], cwd=main, env=environment, check=True, capture_output=True)
    with (main / ".git/config").open("a", encoding="utf-8", newline="\n") as config:
        config.write(long_lived_clone_config())


def _linked_head(worktree: Path) -> str | None:
    try:
        pointer = (worktree / ".git").read_text(encoding="utf-8").strip()
        return (Path(pointer.removeprefix("gitdir: ")) / "HEAD").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def long_lived_clone_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The linked worktree ends on the new branch, or each new sibling worktree on its own."""
    if scenario_id == HOME_HOOKS_CASE:
        try:
            edited = (workspace / HOME_HOOKS_NOTES).read_text(encoding="utf-8") == "Final release notes.\n"
        except (OSError, UnicodeError):
            edited = False
        return {"home-hooks-notes-edited": edited}
    if scenario_id == LONG_LIVED_WORKTREE_CASE:
        home = workspace.parent
        return {
            "long-lived-worktrees-added": all(
                _linked_head(home / name) == f"ref: refs/heads/{branch}\n"
                for name, branch in LONG_LIVED_WORKTREES.items()
            )
        }
    if scenario_id != LONG_LIVED_CLONE_CASE:
        return {}
    head = _linked_head(workspace)
    return {"long-lived-branch-checked-out": head == f"ref: refs/heads/{LONG_LIVED_BRANCH}\n"}
