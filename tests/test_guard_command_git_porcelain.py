"""Everyday Git porcelain command catalog tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.github_command_capabilities import classify_github_cli
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

GIT_PORCELAIN_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("git switch feature", "git workspace command", "command.git.switch"),
    ("git checkout feature", "git workspace command", "command.git.checkout"),
    ("git stash push -m wip", "git workspace command", "command.git.stash"),
    ("git add README.md", "git workspace command", "command.git.add"),
    ("git commit -m update", "git workspace command", "command.git.commit"),
    ("git rebase main", "git workspace command", "command.git.rebase"),
    ("git merge --no-ff feature", "git workspace command", "command.git.merge"),
    ("git cherry-pick abcdef1", "git workspace command", "command.git.cherry-pick"),
    ("git -C repo switch feature", "git workspace command", "command.git.switch"),
    ("git -Crepo switch feature", "git workspace command", "command.git.switch"),
    ("git -c user.name=x switch feature", "git workspace command", "command.git.switch"),
    ("git -cuser.name=x switch feature", "git workspace command", "command.git.switch"),
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
    "git push --push-option +audit origin main",
    "git push --push-option=+audit origin main",
    "git push -o+audit origin main",
    "git push origin main",
)


def test_git_read_and_nonforce_push_remain_safe(tmp_path: Path) -> None:
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


def test_git_helper_and_output_reads_are_reviewed(tmp_path: Path) -> None:
    assert_reviewed_command_cases(
        (
            ("git diff --output=patch", "git workspace command", "command.git.unsafe-read"),
            ("git show --output patch HEAD", "git workspace command", "command.git.unsafe-read"),
            ("git diff --ext-diff", "git workspace command", "command.git.unsafe-read"),
            ("git show --textconv HEAD", "git workspace command", "command.git.unsafe-read"),
        ),
        tmp_path,
    )


def test_git_help_modes_are_not_reviewed(tmp_path: Path) -> None:
    assert_safe_command_cases(("git --help rm", "git switch --help", "git --version"), tmp_path)


def test_github_account_switch_is_reviewed(tmp_path: Path) -> None:
    assessment = classify_github_cli(("auth", "switch"))
    assert assessment.capability == "write_local"
    assert assessment.reason_code == "github.command.local-auth-write"
    assert_reviewed_command_cases(
        (("gh auth switch", "GitHub local configuration write", "command.github.local-write"),),
        tmp_path,
    )


def test_git_status_allow_floor_does_not_pause_inspection(tmp_path: Path) -> None:
    evaluation = evaluate_command("git status --short", cwd=tmp_path, home_dir=tmp_path)

    assert evaluation.minimum_action == "allow"
    assert {owned.match.rule.rule_id for owned in evaluation.matches} == {"command.git.status"}
