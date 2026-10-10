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
from tests.native_command_test_support import inspect_command_native_test as inspect_command

# Windows rejects ASCII newlines in filenames; keep an unusual Unicode separator
# there while POSIX continues to exercise Git's NUL-delimited newline handling.
_LINE_BREAK_FILENAME = "line\u2028break.py" if os.name == "nt" else "line\nbreak.py"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    return subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )


@pytest.fixture
def git_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is unavailable")
    # This positive fixture describes a clean Git caller, not the CI runner's
    # loader settings, pager programs, or global configuration.
    for name in tuple(os.environ):
        upper = name.upper()
        if upper.startswith(("GIT_", "LD_", "DYLD_")) or upper in {"PAGER", "XDG_CONFIG_HOME"}:
            monkeypatch.delenv(name, raising=False)
    # Setup and native review must inspect the same clean Git configuration.
    # Use supported caller fields rather than an unattested config override.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.name", "Guard Fixture")
    _git(repository, "config", "user.email", "guard@example.invalid")
    _git(repository, "config", "commit.gpgsign", "false")
    _write(repository / "src" / "app.py", "print('safe')\n")
    _write(repository / "src" / "nested" / "worker.py", "print('safe')\n")
    _write(repository / "src" / "nested" / "MODEL.PY", "print('safe')\n")
    _write(repository / ".env", "TOKEN=fixture\n")
    _write(repository / "notes with spaces.md", "safe\n")
    _write(repository / _LINE_BREAK_FILENAME, "print('safe')\n")
    _write(repository / "-leading.py", "print('safe')\n")
    _git(repository, "add", "--all")
    _git(repository, "commit", "--quiet", "-m", "initial fixture")
    _write(repository / "src" / "app.py", "print('updated')\n")
    _git(repository, "add", "src/app.py")
    _git(repository, "commit", "--quiet", "-m", "update fixture")
    return repository


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


_DIFF_ENV_COMMAND = "git diff -- ':(top,glob)**/*.env' | sed -n '1,40p'"


def test_git_pathspec_identity_binds_index_and_worktree_state(git_repository: Path) -> None:
    first = _codex_git_pathspec_identity_for_command(_DIFF_ENV_COMMAND, cwd=git_repository)
    _write(git_repository / ".env", "TOKEN=changed-fixture\n")
    _git(git_repository, "add", ".env")
    second = _codex_git_pathspec_identity_for_command(_DIFF_ENV_COMMAND, cwd=git_repository)

    assert first is not None
    assert second is not None
    assert first != second


def test_git_pathspec_identity_uses_modeled_directory_change(git_repository: Path) -> None:
    contextual = _codex_git_pathspec_identity_for_command(
        "cd src && git diff -- ':(top,glob)**/*.env' | sed -n '1,40p'", cwd=git_repository
    )
    direct = _codex_git_pathspec_identity_for_command(
        "git diff -- ':(top,glob)**/*.env' | sed -n '1,40p'", cwd=git_repository / "src"
    )

    assert contextual is not None
    assert contextual == direct


def test_git_pathspec_identity_distinguishes_selections(git_repository: Path) -> None:
    env_files = _codex_git_pathspec_identity_for_command(_DIFF_ENV_COMMAND, cwd=git_repository)
    python_files = _codex_git_pathspec_identity_for_command(
        "git diff -- ':(top,glob)src/**/*.py' | sed -n '1,40p'", cwd=git_repository
    )

    assert env_files is not None
    assert python_files is not None
    assert env_files != python_files


def test_git_diff_default_revision_and_staged_forms_resolve_all_tracked_files(git_repository: Path) -> None:
    for command in ("git diff", "git diff --staged", "git diff HEAD~1"):
        assert _codex_git_pathspec_identity_for_command(command, cwd=git_repository) is not None


def test_git_pathspec_identity_for_non_repository_differs_from_repository(git_repository: Path, tmp_path: Path) -> None:
    outside = tmp_path / "not-a-repository"
    outside.mkdir()
    inside = _codex_git_pathspec_identity_for_command("git diff -- src", cwd=git_repository)
    unavailable = _codex_git_pathspec_identity_for_command("git diff -- src", cwd=outside)

    assert inside is not None
    assert unavailable != inside


@pytest.mark.parametrize(
    ("command", "rule_id", "minimum_action"),
    (
        ("git status", "command.git.status", "allow"),
        ("git diff", "command.git.diff", "review"),
        ("git diff --staged", "command.git.index-inspection", "review"),
        ("git diff HEAD~1", "command.git.diff", "review"),
        ("git diff -- src/", "command.git.diff", "review"),
        ('git diff -- ":(glob)src/**/*.py"', "command.git.diff", "review"),
        ("git log --oneline", "command.git.log", "review"),
        ("git show HEAD", "command.git.show", "review"),
    ),
)
def test_normal_git_workflows_preserve_native_ownership_and_proof_requirements(
    command: str,
    rule_id: str,
    minimum_action: str,
    git_repository: Path,
) -> None:
    payload = inspect_command(command, cwd=git_repository, home_dir=git_repository.parent)

    # Native Git reads retain their helper/configuration proof floors. A clean
    # host can prove this repository has no diff helper and allow plain git diff.
    # These pathspec forms must not invent a more specific owner merely from a token.
    assert payload["controlling_rule_id"] == rule_id
    action = payload["minimum_action"]
    if rule_id in {"command.git.diff", "command.git.log", "command.git.show"}:
        # A clean host proves this repository has no diff helper and allows the read.
        assert action in {"allow", "review"}
    else:
        assert action == minimum_action
    assert payload["status"] == ("no_match" if action == "allow" else "review")
    classification = payload["classification"]
    assert isinstance(classification, dict)
    assert classification["matched"] is (action != "allow")


def test_git_pathspec_query_does_not_execute_aliases_hooks_or_diff_helpers(git_repository: Path) -> None:
    marker = git_repository.parent / "executed"
    _git(git_repository, "config", "alias.ls-files", f"!touch {marker}")
    _git(git_repository, "config", "diff.external", f"touch {marker}")
    hook = git_repository / ".git" / "hooks" / "post-checkout"
    _write(hook, f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)

    _codex_git_pathspec_identity_for_command("git diff -- ':(glob)src/**/*.py'", cwd=git_repository)

    assert not marker.exists()


def test_git_pathspec_symlink_selection_is_incomplete(git_repository: Path) -> None:
    target = git_repository / "src" / "app.py"
    symlink = git_repository / "linked.py"
    try:
        symlink.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    _git(git_repository, "add", "linked.py")

    linked = _codex_git_pathspec_identity_for_command("git diff -- linked.py", cwd=git_repository)
    regular = _codex_git_pathspec_identity_for_command("git diff -- src/app.py", cwd=git_repository)

    assert linked != regular
