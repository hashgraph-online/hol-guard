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

_INDEX_SCAN = """git diff --cached --check; echo "CHECK_EXIT=$?"

echo "==== PATH SCAN ===="
if git diff --cached -- . ':!pnpm-lock.yaml' ':!package-lock.json' \\
  | rg -n 'unique-token-alpha'; then
  echo "PATH_SCAN=FAIL"
else
  echo "PATH_SCAN=PASS"
fi"""


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


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    repository = home / "projects" / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
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
        "git diff --cached --check",
        "git diff --staged --check",
        'git diff --cached --check; echo "CHECK_EXIT=$?"',
        "git diff --cached -- . ':!pnpm-lock.yaml' ':!package-lock.json'",
        "git diff --cached -- . ':!pnpm-lock.yaml' ':!package-lock.json' | rg -n unique-token-alpha",
        "if git diff --cached --check; then echo FAIL; else echo PASS; fi",
        (
            "if git diff --cached -- . ':!pnpm-lock.yaml' ':!package-lock.json' "
            "| rg -n unique-token-alpha; then echo FAIL; else echo PASS; fi"
        ),
        _INDEX_SCAN,
    ),
)
def test_repo_bound_cached_diff_variants_are_benign(tmp_path: Path, command: str) -> None:
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


def test_unverified_cached_diff_is_owned_by_git_extension(tmp_path: Path) -> None:
    payload = inspect_command("git diff --cached --output=patch", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["classification"]["action_class"] == "git index inspection"
    assert payload["controlling_rule_id"] == "command.git.index-inspection"
    assert payload["extensions"][0]["extension_id"] == "command.git"
    assert payload["rules"][0]["rule_id"] == "command.git.index-inspection"
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.for_action_class("git index inspection") is not None
    assert BUILT_IN_COMMAND_EXTENSION_REGISTRY.rule_for_action_class("git index inspection") is not None
    git = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.git")
    assert git is not None
    assert any(permission.permission_id == "command.git.permission.index-inspection" for permission in git.permissions)


def test_execution_config_cached_diff_stays_unowned(tmp_path: Path) -> None:
    payload = inspect_command("git -c diff.external=payload diff --cached", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert payload["classification"]["action_class"] is None
    assert payload["controlling_rule_id"] is None
    assert payload["extensions"] == []


def test_echo_redirection_is_not_benign(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    command = "git diff --cached --check; echo data > output"

    assert not _is_benign(command, home=home, repository=repository)
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=repository,
        home_dir=home,
    )
    assert request is not None
    assert request.action_class == "git index inspection"


def test_attached_config_override_stays_unowned(tmp_path: Path) -> None:
    payload = inspect_command("git -cdiff.external=payload diff --cached", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert payload["classification"]["action_class"] is None
    assert payload["extensions"] == []


def test_verified_cached_check_stays_unmatched_in_inspection(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    payload = inspect_command("git diff --cached --check", cwd=repository, home_dir=home)

    assert payload["classification"]["explicitly_benign"] is True
    assert payload["status"] == "no_match"
    assert payload["extensions"] == []


@pytest.mark.parametrize(
    "command",
    (
        "git --git-dir=other-repo diff --cached --check",
        "git --work-tree=other-repo diff --cached --check",
        "git --bare diff --cached --check",
        "git --paginate diff --cached --check",
        "git -Cother-repo diff --cached --check",
        "git --no-pager -C other-repo diff --cached --check",
        "git -C other-repo --bare diff --cached --check",
        "git diff --cached --output=fetch.patch",
        "git diff --cached -- . ':!pnpm-lock.yaml' ':!package-lock.json' | rg -n $FLAGS",
    ),
)
def test_unproven_cached_diff_variants_are_owned(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)

    assert not _is_benign(command, home=home, repository=repository)
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=repository,
        home_dir=home,
    )
    assert request is not None
    assert request.action_class == "git index inspection"


@pytest.mark.parametrize("command", ("git diff -- --cached", "git diff -- --staged"))
def test_pathspec_index_flag_names_are_not_owned(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)
    payload = inspect_command(command, cwd=repository, home_dir=home)

    assert payload["status"] == "no_match"
    assert payload["classification"]["action_class"] is None
    assert (
        extract_sensitive_tool_action_request(
            "Bash",
            {"command": command},
            cwd=repository,
            home_dir=home,
        )
        is None
    )


def test_ripgrep_config_path_is_owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, repository = _repository(tmp_path)
    monkeypatch.setenv("RIPGREP_CONFIG_PATH", "other-config")
    command = "git diff --cached -- . ':!pnpm-lock.yaml' ':!package-lock.json' | rg -n unique-token-alpha"

    assert not _is_benign(command, home=home, repository=repository)
    request = extract_sensitive_tool_action_request(
        "Bash",
        {"command": command},
        cwd=repository,
        home_dir=home,
    )
    assert request is not None
    assert request.action_class == "git index inspection"
