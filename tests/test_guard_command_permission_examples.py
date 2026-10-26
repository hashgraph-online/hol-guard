"""Command permission example and family metadata contracts."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandPermissionSpec,
)


def _all_permissions() -> list[CommandPermissionSpec]:
    return [
        permission
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        for permission in extension.permissions
    ]


def test_every_configurable_permission_has_a_single_line_example() -> None:
    configurable = [permission for permission in _all_permissions() if permission.configurable]
    assert len(configurable) >= 90
    for permission in configurable:
        example = permission.example_command
        assert isinstance(example, str) and example.strip(), permission.permission_id
        assert "\n" not in example and "\r" not in example, permission.permission_id
        assert len(example) <= 120, permission.permission_id


def test_examples_are_deterministic_across_serialization() -> None:
    for permission in _all_permissions():
        payload = permission.to_dict()
        assert payload["example_command"] == permission.example_command
        assert payload["family"] == permission.family


def test_matcher_derived_examples_use_the_canonical_executable_form() -> None:
    permissions = {permission.permission_id: permission for permission in _all_permissions()}
    assert permissions["command.git.permission.force-push"].example_command == "git push --force"
    assert permissions["command.git.permission.hard-reset"].example_command == "git reset --hard"
    assert permissions["command.git.permission.force-clean"].example_command == "git clean -f"
    assert permissions["command.filesystem.permission.recursive-delete"].example_command == "rm -r build/"


def test_explicit_rule_examples_override_matcher_derivation() -> None:
    permissions = {permission.permission_id: permission for permission in _all_permissions()}
    assert permissions["command.git.permission.local-branch-delete"].example_command == "git branch -D stale-feature"
    assert permissions["command.git.permission.unverified-fetch"].example_command == "git fetch origin"
    assert permissions["command.git.permission.index-inspection"].example_command == "git diff --cached --output=patch"


def test_git_destructive_family_groups_exactly_the_five_git_rules() -> None:
    git = next(
        extension
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id == "command.git"
    )
    family_members = sorted(
        permission.permission_id for permission in git.permissions if permission.family == "git-destructive"
    )
    assert family_members == [
        "command.git.permission.force-clean",
        "command.git.permission.force-push",
        "command.git.permission.hard-reset",
        "command.git.permission.local-branch-delete",
        "command.git.permission.remote-branch-delete",
    ]


def test_github_merge_family_groups_the_three_merge_variants() -> None:
    github = next(
        extension
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id == "command.github"
    )
    family_members = sorted(
        permission.permission_id for permission in github.permissions if permission.family == "gh-pr-merge"
    )
    assert family_members == [
        "command.github.permission.merge-admin",
        "command.github.permission.merge-remote",
        "command.github.permission.routine-merge-remote",
    ]
    examples = {
        permission.permission_id: permission.example_command
        for permission in github.permissions
        if permission.family == "gh-pr-merge"
    }
    assert examples["command.github.permission.routine-merge-remote"] == "gh pr merge 123 --squash"
    assert examples["command.github.permission.merge-remote"] == "gh pr merge 123 --merge"
    assert examples["command.github.permission.merge-admin"] == "gh pr merge 123 --admin"
