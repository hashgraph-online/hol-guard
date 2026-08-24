"""Everyday Git porcelain command catalog tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

GIT_PORCELAIN_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("git switch feature", "git workspace command", "command.git.switch"),
    ("git checkout feature", "git workspace command", "command.git.checkout"),
    ("git stash push -m wip", "git workspace command", "command.git.stash"),
    ("git add README.md", "git workspace command", "command.git.add"),
    ("git commit -m update", "git workspace command", "command.git.commit"),
    ("git rebase main", "git workspace command", "command.git.rebase"),
    ("git merge --no-ff feature", "git workspace command", "command.git.merge"),
    ("git pull --ff-only", "git workspace command", "command.git.pull"),
    ("git push origin main", "git workspace command", "command.git.push"),
    ("git fetch origin", "git workspace command", "command.git.fetch"),
    ("git reset HEAD~1", "git workspace command", "command.git.reset"),
    ("git cherry-pick abcdef1", "git workspace command", "command.git.cherry-pick"),
)


def test_git_porcelain_mutating_commands_are_reviewed(tmp_path: Path) -> None:
    assert_reviewed_command_cases(GIT_PORCELAIN_REVIEW_CASES, tmp_path)


GIT_PORCELAIN_SAFE_COMMANDS: tuple[str, ...] = (
    "git status --short",
    "git log --oneline -5",
    "git diff --stat",
    "git show HEAD",
    "git blame README.md",
    "git ls-files",
)


def test_git_read_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(GIT_PORCELAIN_SAFE_COMMANDS, tmp_path)


def test_git_catalog_lists_everyday_porcelain_commands() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.git")
    assert extension is not None
    examples = {permission.example_command for permission in extension.permissions}
    for expected in (
        "git switch",
        "git checkout",
        "git restore",
        "git stash",
        "git rebase",
        "git merge",
        "git commit",
        "git pull",
        "git push",
        "git status",
        "git reset --hard",
        "git branch -D stale-feature",
    ):
        assert expected in examples


def test_forced_git_push_still_uses_destructive_rule(tmp_path: Path) -> None:
    assert_reviewed_command_cases(
        (("git push origin main --force", "git destructive command", "command.git.force-push"),),
        tmp_path,
    )
