from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


@pytest.fixture(autouse=True)
def _isolate_user_git_config(  # pyright: ignore[reportUnusedFunction]
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "git-config-home"
    config = home / ".config"
    config.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config))
    for variable in (
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_NAMESPACE",
        "GIT_WORK_TREE",
    ):
        monkeypatch.delenv(variable, raising=False)


def _repository(tmp_path: Path, *, origin: str = "https://github.com/example/project.git") -> tuple[Path, Path]:
    home = tmp_path / "home"
    repository = home / "projects" / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
    _ = subprocess.run(["git", "-C", str(repository), "remote", "add", "origin", origin], check=True)
    return home, repository


def _is_benign(command: str, *, home: Path, repository: Path) -> bool:
    return is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=repository,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "command",
    (
        "git fetch origin",
        "git fetch origin --quiet",
        "git fetch --quiet origin",
        "git fetch origin -q",
        "git fetch -q origin",
        "git fetch origin --no-tags",
        "git fetch origin main",
        "git fetch origin main release/3.0",
        "git fetch origin -q main release/3.0",
    ),
)
def test_repo_bound_origin_fetch_variants_are_benign(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)

    assert _is_benign(command, home=home, repository=repository)
    assert (
        extract_sensitive_tool_action_request(
            "Bash",
            {"command": command},
            cwd=repository,
            home_dir=home,
        )
        is None
    )


@pytest.mark.parametrize(
    "origin",
    (
        "git@github.com:example/project.git",
        "ssh://git@github.com/example/project.git",
    ),
)
def test_repo_bound_github_ssh_origin_fetch_stays_owned(tmp_path: Path, origin: str) -> None:
    home, repository = _repository(tmp_path, origin=origin)

    assert not _is_benign("git fetch origin", home=home, repository=repository)
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "git fetch origin --quiet"},
        cwd=repository,
        home_dir=home,
    )
    assert request is not None
    assert request.action_class == "git origin refresh"


def test_github_ssh_origin_fetch_rejects_configured_ssh_command(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path, origin="git@github.com:example/project.git")
    _ = subprocess.run(
        ["git", "-C", str(repository), "config", "core.sshCommand", "payload"],
        check=True,
    )

    assert not _is_benign("git fetch origin", home=home, repository=repository)
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "git fetch origin"},
        cwd=repository,
        home_dir=home,
    )
    assert request is not None
    assert request.action_class == "git origin refresh"


def test_unverified_fetch_is_owned_by_git_extension(tmp_path: Path) -> None:
    payload = inspect_command("git fetch origin", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == "git origin refresh"
    assert payload["controlling_rule_id"] == "command.git.unverified-fetch"
    assert payload["extensions"][0]["extension_id"] == "command.git"
    assert payload["rules"][0]["rule_id"] == "command.git.unverified-fetch"
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class("git origin refresh") is not None
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.rule_for_action_class("git origin refresh") is not None
    git = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.git")
    assert git is not None
    assert any(permission.permission_id == "command.git.permission.unverified-fetch" for permission in git.permissions)


@pytest.mark.parametrize(
    "command",
    (
        "git -c core.sshCommand=payload fetch origin",
        "git --config-env credential.helper=HELPER fetch origin",
        "git --exec-path=/tmp fetch origin",
    ),
)
def test_execution_config_fetch_stays_unowned(tmp_path: Path, command: str) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == "unverified Git remote refresh"
    assert payload["controlling_rule_id"] is None
    assert payload["extensions"] == []


def test_url_remote_fetch_stays_unowned(tmp_path: Path) -> None:
    payload = inspect_command("git fetch https://example.invalid/project.git", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == "unverified Git remote refresh"
    assert payload["controlling_rule_id"] is None
    assert payload["extensions"] == []


def test_verified_origin_fetch_stays_unmatched_in_inspection(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    payload = inspect_command("git fetch origin", cwd=repository, home_dir=home)

    assert payload["classification"]["explicitly_benign"] is True
    assert payload["status"] == "no_match"
    assert payload["extensions"] == []
