from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime.git_execution_safety import (
    git_fetch_origin_has_execution_free_config,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
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


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "home"
    repository = home / "projects" / "example"
    repository.mkdir(parents=True)
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/project.git",
        ],
        check=True,
    )
    return home, repository


def _is_benign(command: str, *, home: Path, repository: Path) -> bool:
    return is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=repository,
        home_dir=home,
    )


def test_standalone_origin_ref_refresh_and_resolution_are_explicitly_benign(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)

    assert _is_benign("git fetch origin release/2.2", home=home, repository=repository)
    assert _is_benign("git rev-parse origin/release/2.2", home=home, repository=repository)
    for command in ("git fetch origin release/2.2", "git rev-parse origin/release/2.2"):
        assert (
            _hook_runtime_artifact(
                harness="codex",
                payload={
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                },
                action_envelope=None,
                home_dir=home,
                guard_home=home / ".guard",
                workspace=repository,
            )
            is None
        )


def test_standalone_verified_origin_reads_are_explicitly_benign(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)

    assert _is_benign("git ls-remote --heads origin main release/3.0", home=home, repository=repository)
    assert _is_benign(
        "git branch -r --list origin/main origin/release/3.0",
        home=home,
        repository=repository,
    )
    command = " && ".join(
        (
            "git status --short --branch",
            "git worktree list --porcelain",
            "git branch -r --list origin/main origin/release/3.0",
        )
    )
    assert _is_benign(command, home=home, repository=repository)


@pytest.mark.parametrize(
    "command",
    (
        "git ls-remote origin main",
        "git ls-remote --heads https://github.com/example/project.git main",
        "git ls-remote --upload-pack=payload origin main",
        "git ls-remote --heads origin 'refs/heads/*'",
        "git ls-remote --heads origin main | cat",
        "git branch -a --list origin/main",
        "git branch -r --contains origin/main",
    ),
)
def test_standalone_verified_origin_reads_reject_widening_syntax(tmp_path: Path, command: str) -> None:
    home, repository = _repository(tmp_path)

    assert not _is_benign(command, home=home, repository=repository)


def test_remote_branch_listing_rejects_executable_pager(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    _ = subprocess.run(["git", "-C", str(repository), "config", "pager.branch", "!payload"], check=True)

    assert not _is_benign("git branch -r --list origin/main", home=home, repository=repository)


def test_standalone_git_routine_requires_explicit_execution_directory(tmp_path: Path) -> None:
    home, _repository_path = _repository(tmp_path)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": "git rev-parse origin/release/2.2"},
        cwd=None,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "command",
    (
        "git fetch origin release/2.2:refs/heads/release/2.2",
        "git fetch --force origin release/2.2",
        "git fetch --prune origin release/2.2",
        "git fetch --tags origin release/2.2",
        "git fetch https://github.com/example/project.git release/2.2",
        "git fetch origin release/2.2 | cat",
        "git fetch origin release/2.2; id",
        "git rev-parse --exec-path",
        "git rev-parse --git-path hooks/post-checkout",
        "git rev-parse 'origin/release/2.2^{/payload}'",
        "git rev-parse $(payload)",
    ),
)
def test_standalone_git_routine_rejects_widening_or_execution_syntax(
    tmp_path: Path,
    command: str,
) -> None:
    home, repository = _repository(tmp_path)

    assert not _is_benign(command, home=home, repository=repository)


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("remote.origin.uploadpack", "./payload"),
        ("url.ext::payload.insteadOf", "https://github.com/"),
        ("credential.helper", "!payload"),
        ("credential.https://github.com.helper", "!payload"),
        ("core.askPass", "./payload"),
        ("fetch.recurseSubmodules", "true"),
        ("remote.origin.prune", "true"),
        ("remote.origin.fetch", "+refs/heads/*:refs/heads/deploy"),
    ),
)
def test_standalone_fetch_rejects_execution_routing_or_widening_config(
    tmp_path: Path,
    key: str,
    value: str,
) -> None:
    home, repository = _repository(tmp_path)
    _ = subprocess.run(["git", "-C", str(repository), "config", key, value], check=True)

    assert not _is_benign("git fetch origin release/2.2", home=home, repository=repository)
    assert _is_benign("git rev-parse origin/release/2.2", home=home, repository=repository)


@pytest.mark.parametrize(
    "remote_url",
    (
        "ext::payload",
        "file:///tmp/project.git",
        "ssh://github.com/example/project.git",
        "https://example.invalid/example/project.git",
        "https://github.com/../project.git",
    ),
)
def test_standalone_fetch_rejects_non_github_https_origin(tmp_path: Path, remote_url: str) -> None:
    home, repository = _repository(tmp_path)
    _ = subprocess.run(["git", "-C", str(repository), "remote", "set-url", "origin", remote_url], check=True)

    assert not _is_benign("git fetch origin release/2.2", home=home, repository=repository)


def test_standalone_fetch_accepts_github_https_origin_with_userinfo(tmp_path: Path) -> None:
    home, repository = _repository(tmp_path)
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "set-url",
            "origin",
            "https://account:credential@github.com/example/project.git",
        ],
        check=True,
    )

    assert _is_benign("git fetch origin release/2.2", home=home, repository=repository)


@pytest.mark.parametrize("variable", ("GIT_EXEC_PATH", "GIT_SSH_COMMAND", "GIT_ASKPASS"))
def test_standalone_fetch_rejects_transport_execution_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    home, repository = _repository(tmp_path)
    monkeypatch.setenv(variable, "/tmp/payload")

    assert not _is_benign("git fetch origin release/2.2", home=home, repository=repository)


@pytest.mark.parametrize("hook_name", ("pre-auto-gc", "reference-transaction"))
def test_standalone_fetch_rejects_executable_maintenance_hook(tmp_path: Path, hook_name: str) -> None:
    home, repository = _repository(tmp_path)
    _ = subprocess.run(
        ["git", "-C", str(repository), "config", "core.hooksPath", ".git/hooks"],
        check=True,
    )
    hook = repository / ".git" / "hooks" / hook_name
    _ = hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = hook.chmod(hook.stat().st_mode | stat.S_IXUSR)

    assert not git_fetch_origin_has_execution_free_config(repository)
    assert not _is_benign("git fetch origin release/2.2", home=home, repository=repository)


def test_standalone_git_routine_rejects_path_shadowing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, repository = _repository(tmp_path)
    shadow_bin = repository / "bin"
    shadow_bin.mkdir()
    shadow_git = shadow_bin / "git"
    _ = shadow_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = shadow_git.chmod(shadow_git.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{shadow_bin}{os.pathsep}{os.environ.get('PATH', '')}")

    assert not _is_benign("git fetch origin release/2.2", home=home, repository=repository)
    assert not _is_benign("git rev-parse origin/release/2.2", home=home, repository=repository)


def test_standalone_fetch_rejects_relative_path_credential_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home, repository = _repository(tmp_path)
    _ = subprocess.run(
        ["git", "-C", str(repository), "config", "credential.helper", "!gh auth git-credential"],
        check=True,
    )
    helper_directory = repository / "bin"
    helper_directory.mkdir()
    helper = helper_directory / "gh"
    _ = helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _ = helper.chmod(helper.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"bin{os.pathsep}{os.environ.get('PATH', '')}")

    assert not _is_benign("git fetch origin release/2.2", home=home, repository=repository)
