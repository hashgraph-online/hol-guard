from __future__ import annotations

from pathlib import Path

from tests.live_hook_review_support import LIVE_ALLOWS_RETIRED_REVIEW, live_shell_review, quietly_allowed


def _quiet(command: str, *, home: Path) -> bool:
    cwd = home / "projects" / "current"
    cwd.mkdir(parents=True, exist_ok=True)
    return quietly_allowed(live_shell_review(command, home_dir=home, cwd=cwd))


def test_leading_home_cd_and_github_read_has_no_runtime_artifact_without_workspace(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    (home / "projects" / "review-worktree").mkdir(parents=True)

    assert _quiet(
        "cd ~/projects/review-worktree && gh pr view 17 --json state,mergedAt,mergeCommit 2>&1",
        home=home,
    )


def test_leading_home_cd_does_not_hide_github_mutation_without_workspace(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    (home / "projects" / "review-worktree").mkdir(parents=True)

    assert not _quiet("cd ~/projects/review-worktree && gh pr merge 17 --admin", home=home)


def test_dynamic_cd_keeps_compound_github_read_fail_closed(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    home.mkdir()

    assert not _quiet("cd $TARGET && gh pr view 17 --json state", home=home)


@LIVE_ALLOWS_RETIRED_REVIEW
def test_execution_before_cd_keeps_compound_github_read_fail_closed(live_hook_root: Path) -> None:
    home = live_hook_root / "home"
    (home / "projects" / "review-worktree").mkdir(parents=True)

    assert not _quiet(
        "printf ready && cd ~/projects/review-worktree && gh pr view 17 --json state",
        home=home,
    )
