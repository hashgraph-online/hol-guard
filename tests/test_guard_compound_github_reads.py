from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact(command: str, *, home: Path) -> GuardArtifact | None:
    return _hook_runtime_artifact(
        harness="codex",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=None,
    )


def test_leading_home_cd_and_github_read_has_no_runtime_artifact_without_workspace(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "projects" / "review-worktree").mkdir(parents=True)

    artifact = _artifact(
        "cd ~/projects/review-worktree && gh pr view 17 --json state,mergedAt,mergeCommit 2>&1",
        home=home,
    )

    assert artifact is None


def test_leading_home_cd_does_not_hide_github_mutation_without_workspace(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "projects" / "review-worktree").mkdir(parents=True)

    artifact = _artifact("cd ~/projects/review-worktree && gh pr merge 17 --admin", home=home)

    assert artifact is not None


def test_dynamic_cd_keeps_compound_github_read_fail_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    artifact = _artifact("cd $TARGET && gh pr view 17 --json state", home=home)

    assert artifact is not None


def test_execution_before_cd_keeps_compound_github_read_fail_closed(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "projects" / "review-worktree").mkdir(parents=True)

    artifact = _artifact(
        "printf ready && cd ~/projects/review-worktree && gh pr view 17 --json state",
        home=home,
    )

    assert artifact is not None
