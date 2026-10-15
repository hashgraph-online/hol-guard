from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_codex_tool_output import codex_tool_output_native


def _codex_command_is_read_only_git_metadata(command_text: str, *, cwd: Path | None = None) -> bool:
    return codex_tool_output_native("git_metadata", command=command_text, cwd=cwd).allowed


def _init_repository(path: Path) -> None:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet", str(path)], check=True, capture_output=True)


@pytest.mark.parametrize(
    "command",
    (
        "git status --short --branch",
        "git worktree list --porcelain",
        "git branch --list feature/*",
    ),
)
def test_git_metadata_accepts_trusted_read_only_commands(tmp_path: Path, command: str) -> None:
    repository = tmp_path / "repository"
    _init_repository(repository)

    assert _codex_command_is_read_only_git_metadata(command, cwd=repository)


def test_git_metadata_accepts_separate_contained_git_c_target(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repository = workspace / "repository"
    _init_repository(repository)

    assert _codex_command_is_read_only_git_metadata("git -C repository status --short", cwd=workspace)
    assert _codex_command_is_read_only_git_metadata(f"git -C {repository} status --short", cwd=workspace)


@pytest.mark.parametrize(
    "command",
    (
        "git -c alias.status='!sh payload.sh' status",
        "git --config-env=alias.status=PAYLOAD status",
        "git --git-dir=.git status",
        "git --work-tree=. status",
        "git --no-pager status",
        "git -Crepository status",
    ),
)
def test_git_metadata_rejects_global_option_routing(tmp_path: Path, command: str) -> None:
    repository = tmp_path / "repository"
    _init_repository(repository)

    assert not _codex_command_is_read_only_git_metadata(command, cwd=repository)


def test_git_metadata_rejects_git_c_target_outside_execution_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    _init_repository(outside)

    assert not _codex_command_is_read_only_git_metadata("git -C ../outside status", cwd=workspace)
    assert not _codex_command_is_read_only_git_metadata(f"git -C {outside} status", cwd=workspace)


def test_git_metadata_rejects_path_shadowed_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    shadow_bin = repository / "bin"
    _init_repository(repository)
    shadow_bin.mkdir()
    shadow_git = shadow_bin / "git"
    shadow_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shadow_bin}{os.pathsep}{os.environ.get('PATH', '')}")

    assert not _codex_command_is_read_only_git_metadata("git status --short", cwd=repository)


def test_git_metadata_rejects_executable_fsmonitor(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _init_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "config", "core.fsmonitor", "./payload"],
        check=True,
        capture_output=True,
    )

    assert not _codex_command_is_read_only_git_metadata("git status --short", cwd=repository)


def test_git_metadata_accepts_explicitly_disabled_fsmonitor(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    _init_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "config", "core.fsmonitor", "false"],
        check=True,
        capture_output=True,
    )

    assert _codex_command_is_read_only_git_metadata("git status --short", cwd=repository)


@pytest.mark.parametrize(
    "key",
    (
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
    ),
)
def test_git_metadata_rejects_config_routing_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
) -> None:
    repository = tmp_path / "repository"
    _init_repository(repository)
    monkeypatch.setenv(key, "1")

    assert not _codex_command_is_read_only_git_metadata("git status --short", cwd=repository)
