"""P37 regressions for bounded Git pathspec resolution."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _codex_git_pathspec_identity_for_command,
    _codex_post_tool_output_artifact,
)
from codex_plugin_scanner.guard.runtime import git_pathspecs as git_pathspecs_module
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def git_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is unavailable")
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Guard Fixture")
    _git(repository, "config", "user.email", "guard@example.invalid")
    _write(repository / "src" / "app.py", "print('safe')\n")
    _write(repository / "src" / "nested" / "worker.py", "print('safe')\n")
    _write(repository / "src" / "nested" / "MODEL.PY", "print('safe')\n")
    _write(repository / ".env", "TOKEN=fixture\n")
    _write(repository / "notes with spaces.md", "safe\n")
    _write(repository / "line\nbreak.py", "print('safe')\n")
    _write(repository / "-leading.py", "print('safe')\n")
    _git(repository, "add", "--all")
    _git(repository, "commit", "--quiet", "-m", "initial fixture")
    _write(repository / "src" / "app.py", "print('updated')\n")
    _git(repository, "add", "src/app.py")
    _git(repository, "commit", "--quiet", "-m", "update fixture")
    monkeypatch.delenv("GIT_EXTERNAL_DIFF", raising=False)
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    monkeypatch.delenv("GIT_CONFIG_PARAMETERS", raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    return repository


@pytest.mark.parametrize(
    "pathspec",
    (
        "src/app.py",
        ":(top)src/app.py",
        ":(literal)notes with spaces.md",
        ":(glob)src/**/*.py",
        ":(top,glob,icase)SRC/**/*.PY",
        ":(exclude,glob)**/*.env",
        ":!*.env",
        ":^*.env",
        ":/src/app.py",
    ),
)
def test_supported_git_pathspec_magic_is_explicit(pathspec: str) -> None:
    assert git_pathspecs_module.git_pathspec_is_supported(pathspec)


@pytest.mark.parametrize(
    "pathspec",
    (
        "",
        "bad\x00path",
        ":(attr:guard)src/app.py",
        ":(glob,literal)src/*.py",
        ":(unknown)src/app.py",
        ":(globsrc/*.py",
    ),
)
def test_ambiguous_or_attribute_git_pathspec_magic_is_incomplete(pathspec: str) -> None:
    assert not git_pathspecs_module.git_pathspec_is_supported(pathspec)


def test_git_pathspec_resolution_handles_glob_icase_exclude_and_unusual_names(git_repository: Path) -> None:
    globbed = git_pathspecs_module.resolve_git_pathspecs(
        (":(top,glob,icase)SRC/**/*.PY",),
        cwd=git_repository,
    )
    excluded = git_pathspecs_module.resolve_git_pathspecs(
        (":(top,glob)**/*", ":(top,exclude,glob)**/*.env"),
        cwd=git_repository,
    )
    unusual = git_pathspecs_module.resolve_git_pathspecs(
        (":(top,literal)notes with spaces.md", ":(top,literal)line\nbreak.py", ":(top,literal)-leading.py"),
        cwd=git_repository,
    )

    assert globbed.complete
    assert {path.name for path in globbed.resolved_paths} == {"app.py", "worker.py", "MODEL.PY"}
    assert excluded.complete
    assert git_repository / ".env" not in excluded.resolved_paths
    assert git_repository / "src" / "app.py" in excluded.resolved_paths
    assert unusual.complete
    assert {path.name for path in unusual.resolved_paths} == {
        "notes with spaces.md",
        "line\nbreak.py",
        "-leading.py",
    }
    assert globbed.selection_identity
    assert globbed.selection_identity != excluded.selection_identity


def test_git_pathspec_no_match_is_complete_but_unsupported_magic_is_not(git_repository: Path) -> None:
    no_match = git_pathspecs_module.resolve_git_pathspecs(
        (":(glob)missing/**/*.py",),
        cwd=git_repository,
    )
    unsupported = git_pathspecs_module.resolve_git_pathspecs(
        (":(attr:guard)src/**",),
        cwd=git_repository,
    )

    assert no_match.complete
    assert no_match.reason_code == "git_pathspec_no_match"
    assert no_match.resolved_paths == ()
    assert not unsupported.complete
    assert unsupported.reason_code == "git_pathspec_unsupported_magic"


def test_git_pathspec_resolution_supports_linked_worktrees(git_repository: Path) -> None:
    worktree = git_repository.parent / "linked-worktree"
    _git(git_repository, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")

    resolution = git_pathspecs_module.resolve_git_pathspecs((":(top,glob)src/**/*.py",), cwd=worktree)

    assert resolution.complete
    assert resolution.repository_root == worktree.resolve()
    assert worktree / "src" / "app.py" in resolution.resolved_paths


def test_git_pathspec_resolution_rejects_non_repository_and_gitlink_directory(
    git_repository: Path,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "not-a-repository"
    outside.mkdir()
    unavailable = git_pathspecs_module.resolve_git_pathspecs(("src",), cwd=outside)
    head = _git(git_repository, "rev-parse", "HEAD").stdout.strip()
    _git(git_repository, "update-index", "--add", "--cacheinfo", f"160000,{head},vendor")
    (git_repository / "vendor").mkdir()
    gitlink = git_pathspecs_module.resolve_git_pathspecs(("vendor",), cwd=git_repository)

    assert not unavailable.complete
    assert unavailable.reason_code == "git_pathspec_command_failed"
    assert not gitlink.complete
    assert gitlink.reason_code == "git_pathspec_non_regular_path"


def test_git_diff_pathspec_applies_the_same_policy_as_explicit_files(git_repository: Path) -> None:
    allowed_magic = "git diff -- ':(top,glob)src/**/*.py' | sed -n '1,40p'"
    protected_magic = "git diff -- ':(top,glob)**/*.env' | sed -n '1,40p'"
    protected_explicit = "git diff -- .env | sed -n '1,40p'"
    protected_without_terminator = "git diff .env | sed -n '1,40p'"

    assert guard_commands_module._codex_command_is_read_only_source_inspection(
        allowed_magic,
        cwd=git_repository,
    )
    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        protected_magic,
        cwd=git_repository,
    )
    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        protected_explicit,
        cwd=git_repository,
    )
    assert not guard_commands_module._codex_command_is_read_only_source_inspection(
        protected_without_terminator,
        cwd=git_repository,
    )


def test_git_pathspec_selection_changes_post_tool_approval_identity(git_repository: Path) -> None:
    command = "git diff -- ':(top,glob)**/*.env' | sed -n '1,40p'"
    credential_fixture = "ghp_" + "1" * 36
    payload: dict[str, object] = {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"stdout": f"TOKEN={credential_fixture}\n"},
    }
    first = _codex_post_tool_output_artifact(
        payload=payload,
        config_path=str(git_repository / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=git_repository,
    )
    _write(git_repository / "nested" / ".env", "SECOND=fixture\n")
    _git(git_repository, "add", "nested/.env")
    second = _codex_post_tool_output_artifact(
        payload=payload,
        config_path=str(git_repository / ".codex" / "config.toml"),
        source_scope="workspace",
        cwd=git_repository,
    )

    assert first is not None
    assert second is not None
    assert first.artifact_id != second.artifact_id
    assert first.metadata["git_pathspec_selection_identity"] != second.metadata["git_pathspec_selection_identity"]


def test_git_pathspec_identity_binds_index_and_worktree_state(git_repository: Path) -> None:
    pathspecs = (":(top,glob)**/*.env",)
    first = git_pathspecs_module.resolve_git_pathspecs(pathspecs, cwd=git_repository)
    _write(git_repository / ".env", "TOKEN=changed-fixture\n")
    _git(git_repository, "add", ".env")
    second = git_pathspecs_module.resolve_git_pathspecs(pathspecs, cwd=git_repository)

    assert first.complete
    assert second.complete
    assert first.resolved_paths == second.resolved_paths
    assert first.index_state_identity != second.index_state_identity
    assert first.selection_identity != second.selection_identity


def test_git_pathspec_identity_uses_modeled_directory_change(git_repository: Path) -> None:
    command = "cd src && git diff -- ':(top,glob)**/*.env' | sed -n '1,40p'"
    contextual = _codex_git_pathspec_identity_for_command(command, cwd=git_repository)
    direct = guard_commands_module._codex_git_diff_selection_identity(
        ["diff", "--", ":(top,glob)**/*.env"],
        cwd=git_repository / "src",
    )

    assert contextual is not None
    assert contextual == direct


def test_git_diff_default_revision_and_staged_forms_resolve_all_tracked_files(git_repository: Path) -> None:
    for args in (["diff"], ["diff", "--staged"], ["diff", "HEAD~1"]):
        invocation = guard_commands_module._git_diff_invocation(args, cwd=git_repository)
        assert invocation is not None
        diff_args, effective_cwd, modes = invocation
        pathspecs = guard_commands_module._git_diff_pathspecs(diff_args, cwd=effective_cwd)
        assert pathspecs == ()
        resolution = git_pathspecs_module.resolve_git_pathspecs(
            pathspecs,
            cwd=effective_cwd,
            global_modes=modes,
        )
        assert resolution.complete
        assert git_repository / ".env" in resolution.resolved_paths


@pytest.mark.parametrize(
    "command",
    (
        "git status",
        "git diff",
        "git diff --staged",
        "git diff HEAD~1",
        "git diff -- src/",
        'git diff -- ":(glob)src/**/*.py"',
        "git log --oneline",
        "git show HEAD",
        "git add src/app.py",
        'git commit -m "Fix validation"',
    ),
)
def test_normal_git_workflows_receive_no_new_preflight_review(
    command: str,
    git_repository: Path,
) -> None:
    payload = inspect_command(command, cwd=git_repository, home_dir=git_repository.parent)

    assert payload["status"] == "no_match"
    classification = payload["classification"]
    assert isinstance(classification, dict)
    assert classification["matched"] is False


def test_git_pathspec_query_does_not_execute_aliases_hooks_or_diff_helpers(git_repository: Path) -> None:
    marker = git_repository.parent / "executed"
    _git(git_repository, "config", "alias.ls-files", f"!touch {marker}")
    _git(git_repository, "config", "diff.external", f"touch {marker}")
    hook = git_repository / ".git" / "hooks" / "post-checkout"
    _write(hook, f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)

    resolution = git_pathspecs_module.resolve_git_pathspecs((":(glob)src/**/*.py",), cwd=git_repository)

    assert resolution.complete
    assert not marker.exists()


def test_git_pathspec_timeout_and_output_limits_are_fail_closed(
    git_repository: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_run = git_pathspecs_module.subprocess.run

    def _timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr(git_pathspecs_module.subprocess, "run", _timeout)
    timeout = git_pathspecs_module.resolve_git_pathspecs(("src",), cwd=git_repository)
    assert not timeout.complete
    assert timeout.reason_code == "git_pathspec_timeout"

    monkeypatch.setattr(git_pathspecs_module.subprocess, "run", original_run)
    monkeypatch.setattr(git_pathspecs_module, "_GIT_PATHSPEC_OUTPUT_LIMIT", 1)
    limited = git_pathspecs_module.resolve_git_pathspecs(("src",), cwd=git_repository)
    assert not limited.complete
    assert limited.reason_code == "git_pathspec_output_limit_exceeded"


def test_git_pathspec_symlink_selection_is_incomplete(git_repository: Path) -> None:
    target = git_repository / "src" / "app.py"
    symlink = git_repository / "linked.py"
    try:
        symlink.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    _git(git_repository, "add", "linked.py")

    resolution = git_pathspecs_module.resolve_git_pathspecs(("linked.py",), cwd=git_repository)

    assert not resolution.complete
    assert resolution.reason_code == "git_pathspec_symlink_unresolved"
