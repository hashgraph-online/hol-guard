"""An explicit Git checkout permission never settles a checkout into a protected location.

Enabling `worktree` or `clone` on the Git extension allows those commands by
default. Without a floor, that same Allow also let a checkout land somewhere
the host loads code from on its own (a launch agent folder, an agent's config
folder, `.git/hooks`, `.github/workflows`), which default mode sends to review.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.native_command_test_support import real_native_review_fixtures

CHECKOUT_PERMISSIONS = (
    ("permission", "command.git.permission.clone", "enabled"),
    ("permission", "command.git.permission.worktree", "enabled"),
)


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    workspace = home / "projects" / "service-api"
    for directory in (
        workspace / ".git" / "hooks",
        workspace / ".github" / "workflows",
        home / "Library" / "LaunchAgents",
        home / ".claude",
        tmp_path / "scratch",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    (workspace / ".git" / "config").write_text("[core]\n\tbare = false\n", encoding="utf-8")
    return home.resolve(), workspace.resolve()


def _review(tmp_path: Path, commands: tuple[str, ...]) -> dict[str, dict[str, object]]:
    home, workspace = _layout(tmp_path)
    spelled = tuple(
        command.replace("HOME", str(home)).replace("SCRATCH", str((tmp_path / "scratch").resolve()))
        for command in commands
    )
    fixtures = real_native_review_fixtures(spelled, cwd=workspace, home_dir=home, controls=CHECKOUT_PERMISSIONS)
    return {command: fixture.payload for command, fixture in zip(commands, fixtures, strict=True)}


@pytest.mark.parametrize(
    "command",
    (
        "git worktree add HOME/Library/LaunchAgents/wt origin/main",
        "git worktree add HOME/.claude/agents origin/main",
        "git worktree add .git/hooks/wt origin/main",
        "git worktree add .github/workflows/wt origin/main",
        "git worktree move ../svc HOME/Library/LaunchAgents/wt",
        "git fetch origin main && git worktree add HOME/.claude/agents origin/main",
        "git clone https://github.com/example-org/x.git HOME/Library/LaunchAgents/x",
        # No directory given: Git names the checkout `.claude` in the cwd.
        "git clone https://github.com/example-org/.claude.git",
    ),
)
def test_checkout_permission_does_not_allow_a_protected_destination(tmp_path: Path, command: str) -> None:
    payload = _review(tmp_path, (command,))[command]

    assert payload["minimum_action"] != "allow", payload


def test_checkout_permission_still_allows_ordinary_checkouts(tmp_path: Path) -> None:
    commands = (
        "git worktree add ../sibling -b br origin/main",
        "git worktree add -b br ../sibling origin/main",
        "git worktree add SCRATCH/contrast --detach origin/main",
        # A checkout named after the project is the user's work, not Guard's files.
        "git worktree add --detach SCRATCH/hol-guard-contrast origin/main",
        "git worktree add HOME/projects/svc-p -b br-p origin/main",
    )

    reviewed = _review(tmp_path, commands)

    assert {command: payload["minimum_action"] for command, payload in reviewed.items()} == dict.fromkeys(
        commands, "allow"
    )
