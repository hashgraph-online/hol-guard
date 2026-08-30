"""Structured repo2nb command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import (
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

REPO2NB_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "repo2nb reverse notebook.ipynb --force",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb --output ./dest --force",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb reverse notebook.ipynb -o ./dest --force",
        "repo2nb forced directory overwrite command",
        "command.repo2nb.reverse-force",
    ),
    (
        "repo2nb sync ./my-repo",
        "repo2nb notebook sync command",
        "command.repo2nb.sync",
    ),
    (
        "repo2nb sync ./my-repo --notebook project.ipynb",
        "repo2nb notebook sync command",
        "command.repo2nb.sync",
    ),
)


def test_repo2nb_module_invocation_reaches_review(tmp_path: Path) -> None:
    """`python -m repo2nb` is floored by shell-mutations and still attributed to the repo2nb rules."""

    for command, expected_rule in REPO2NB_MODULE_REVIEW_COMMANDS:
        payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
        matched = {rule.get("rule_id") for rule in payload.get("rules", []) if isinstance(rule, dict)}
        assert payload["status"] == "review", command
        assert "command.shell-mutations.destructive-shell" in matched, command
        assert expected_rule in matched, command


REPO2NB_MODULE_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("python -m repo2nb reverse notebook.ipynb --force", "command.repo2nb.reverse-force"),
    ("python3 -m repo2nb reverse notebook.ipynb --output ./dest --force", "command.repo2nb.reverse-force"),
    ("python -m repo2nb sync ./my-repo", "command.repo2nb.sync"),
    ("python3 -m repo2nb sync ./my-repo", "command.repo2nb.sync"),
)


def test_repo2nb_rules_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(REPO2NB_REVIEW_CASES, tmp_path)


REPO2NB_SAFE_COMMANDS: tuple[str, ...] = (
    "repo2nb reverse notebook.ipynb",  # no --force: never reviewed, by design
    "repo2nb reverse notebook.ipynb --output ./dest",
    "repo2nb sync ./my-repo --dry-run",
    "repo2nb sync --dry-run",
    "repo2nb --help",
    "repo2nb reverse --help",
    "repo2nb sync --help",
)


def test_repo2nb_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(REPO2NB_SAFE_COMMANDS, tmp_path)


def test_repo2nb_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.repo2nb")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
