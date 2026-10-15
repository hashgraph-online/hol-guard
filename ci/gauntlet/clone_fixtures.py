"""A years-old clone: thousands of tracked branches and commits signed by default.

Real sessions in such a clone had ordinary branch work held for review. Every
``branch.<name>.remote`` and ``.merge`` pair stays in ``.git/config`` long after
the branch is gone, which pushes the configuration listing past a quarter
megabyte, and ``commit.gpgsign`` is common on maintainers' checkouts. Neither
runs code for a branch switch, an index update or a configuration read.
"""

from __future__ import annotations

from pathlib import Path

LONG_LIVED_CLONE_CASE = "omp-native-git-long-lived-clone-branch-work"
LONG_LIVED_BRANCH = "fix/report-notes"
LONG_LIVED_CONFIG_MIN_BYTES = 256 * 1024 + 4096


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


def add_long_lived_clone_config(main: Path, scenario_id: str | None) -> None:
    """Append the shape to the main checkout's config, which its linked worktrees share."""
    if scenario_id != LONG_LIVED_CLONE_CASE:
        return
    with (main / ".git/config").open("a", encoding="utf-8", newline="\n") as config:
        config.write(long_lived_clone_config())


def long_lived_clone_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The linked worktree ends on the new branch."""
    if scenario_id != LONG_LIVED_CLONE_CASE:
        return {}
    try:
        pointer = (workspace / ".git").read_text(encoding="utf-8").strip()
        head = (Path(pointer.removeprefix("gitdir: ")) / "HEAD").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return {"long-lived-branch-checked-out": False}
    return {"long-lived-branch-checked-out": head == f"ref: refs/heads/{LONG_LIVED_BRANCH}\n"}
