from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from tests.native_command_test_support import inspect_command_native_test as inspect_command

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


def test_execution_config_cached_diff_keeps_native_uncertainty(tmp_path: Path) -> None:
    payload = inspect_command("git -c diff.external=payload diff --cached", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["explicitly_benign"] is False
    assert payload["controlling_rule_id"] == "command.git.index-inspection"


def test_attached_config_override_keeps_native_uncertainty(tmp_path: Path) -> None:
    payload = inspect_command("git -cdiff.external=payload diff --cached", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["explicitly_benign"] is False
    assert payload["controlling_rule_id"] == "command.git.index-inspection"


@pytest.mark.parametrize(
    "command",
    ("git diff -- --cached", "git diff -- --staged"),
)
def test_pathspec_index_flag_names_are_not_owned(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)
    payload = inspect_command(command, cwd=repository, home_dir=home)

    # The terminator makes these paths, not index flags. A host that can prove
    # Git helpers are inert reports no_match; every other host keeps review.
    assert payload["status"] in {"review", "no_match"}
    assert all(rule["rule_id"] != "command.git.index-inspection" for rule in payload["rules"])
    if payload["status"] == "no_match":
        return
    # The native generic diff owner still requires proof that Git helpers cannot execute.
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["action_class"] == "git read command"
    assert payload["controlling_rule_id"] == "command.git.diff"
    assert all(rule["rule_id"] != "command.git.index-inspection" for rule in payload["rules"])
