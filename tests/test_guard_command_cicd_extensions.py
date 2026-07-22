"""Structured CI/CD command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "action_class", "rule_id"),
    [
        ("gh run cancel 123", "GitHub Actions administrative command", "command.cicd.github.run-administration"),
        ("gh run delete 123", "GitHub Actions administrative command", "command.cicd.github.run-administration"),
        (
            "gh --repo owner/project workflow disable release.yml",
            "GitHub Actions administrative command",
            "command.cicd.github.workflow-disable",
        ),
        (
            "glab ci cancel pipeline 1504182795",
            "GitLab pipeline administrative command",
            "command.cicd.gitlab.pipeline-cancel",
        ),
        (
            "circleci --host https://ci.example.test pipeline run org-id project-id",
            "CircleCI pipeline execution command",
            "command.cicd.circleci.pipeline-run",
        ),
        (
            "gh.exe run --repo owner/project delete 123",
            "GitHub Actions administrative command",
            "command.cicd.github.run-administration",
        ),
        (
            "glab.cmd ci cancel --repo group/project pipeline 1504182795",
            "GitLab pipeline administrative command",
            "command.cicd.gitlab.pipeline-cancel",
        ),
    ],
)
def test_cicd_rules_feed_inspection_and_runtime_hooks(
    command: str,
    action_class: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == action_class
    assert payload["controlling_rule_id"] == rule_id
    runtime_match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert runtime_match is not None
    assert runtime_match.action_class == action_class


@pytest.mark.parametrize(
    "command",
    [
        "gh workflow view release.yml",
        "gh run view 123",
        "glab ci cancel pipeline 1504182795 --dry-run",
        "glab ci cancel pipeline --help",
        "circleci pipeline run --help",
        "circleci config validate .circleci/config.yml",
        "grep 'gh run delete|glab ci cancel' scripts/checks.sh",
        "printf '%s\\n' 'circleci pipeline run org project'",
    ],
)
def test_cicd_help_preview_and_read_commands_remain_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


def test_github_workflow_mutation_trailing_help_does_not_suppress_review(tmp_path: Path) -> None:
    payload = inspect_command("gh run cancel --help", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == "GitHub workflow mutation command"
    runtime_match = extract_sensitive_tool_action_request(
        "Shell",
        {"command": "gh run cancel --help"},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert runtime_match is not None
    assert runtime_match.action_class == "GitHub workflow mutation command"


def test_cicd_safe_variant_does_not_hide_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "glab ci cancel pipeline 10 --dry-run && gh workflow disable release.yml",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert [rule["rule_id"] for rule in payload["rules"]] == ["command.cicd.github.workflow-disable"]


def test_cicd_extensions_publish_primary_references() -> None:
    for extension_id in ("command.cicd.github", "command.cicd.gitlab", "command.cicd.circleci"):
        extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(extension_id)

        assert extension is not None
        assert extension.reference_urls
        assert all(url.startswith("https://") for url in extension.reference_urls)
