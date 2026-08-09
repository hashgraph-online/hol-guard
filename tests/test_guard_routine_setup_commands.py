from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import git_execution_safety, routine_setup_commands


def _git(repository: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "6068672+kantorcodes@users.noreply.github.com")
    _git(repository, "config", "user.name", "Michael Kantor")
    _git(repository, "config", "commit.gpgsign", "false")
    _git(repository, "remote", "add", "origin", "https://github.com/example/project.git")
    tracked = repository / "tracked.txt"
    tracked.write_text("tracked\n")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-qm", "test")
    _git(repository, "update-ref", "refs/remotes/origin/release/2.2", "HEAD")
    return repository


def test_safe_git_worktree_add_requires_new_bounded_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path)
    destination = tmp_path / "new-worktree"
    monkeypatch.setattr(
        routine_setup_commands,
        "_safe_worktree_parent",
        lambda _destination, *, home_dir: home_dir == tmp_path,
    )
    monkeypatch.setattr(
        routine_setup_commands,
        "trusted_git_binary_for_cwd",
        lambda _cwd: Path("/usr/bin/git"),
    )
    monkeypatch.setattr(
        routine_setup_commands,
        "git_worktree_add_has_execution_free_config",
        lambda _cwd, *, git_binary, ref: git_binary == Path("/usr/bin/git") and ref == "origin/release/2.2",
    )
    monkeypatch.setattr(routine_setup_commands, "_git_ref_exists", lambda *_args: True)
    monkeypatch.setattr(routine_setup_commands, "_git_branch_exists", lambda *_args: False)

    assert routine_setup_commands.is_safe_git_worktree_add(
        f"git worktree add -b fix/routine {destination} origin/release/2.2",
        cwd=repository,
        home_dir=tmp_path,
    )
    assert not routine_setup_commands.is_safe_git_worktree_add(
        f"git worktree add -b fix/routine {destination} origin/release/2.2 && sh payload.sh",
        cwd=repository,
        home_dir=tmp_path,
    )


def test_safe_git_worktree_add_accepts_detached_full_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path)
    destination = tmp_path / "detached-worktree"
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setattr(
        routine_setup_commands,
        "_safe_worktree_parent",
        lambda _destination, *, home_dir: home_dir == tmp_path,
    )

    assert routine_setup_commands.is_safe_git_worktree_add(
        f"git worktree add --detach {destination} {commit}",
        cwd=repository,
        home_dir=tmp_path,
    )


@pytest.mark.parametrize(
    "command_template",
    (
        "git worktree add --detach {destination} HEAD",
        "git worktree add --detach {destination} {short_commit}",
        "git worktree add --detach --force {destination} {commit}",
        "git worktree add --detach --force {commit}",
        "git worktree add --detach --lock {commit}",
        "git worktree add --detach --guess-remote {commit}",
        "git worktree add --lock --detach {destination} {commit}",
        "git worktree add --detach {destination} {commit} && sh payload.sh",
    ),
)
def test_safe_git_worktree_add_rejects_widened_detached_forms(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_template: str,
) -> None:
    repository = _repository(tmp_path)
    destination = tmp_path / "detached-worktree"
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setattr(
        routine_setup_commands,
        "_safe_worktree_parent",
        lambda _destination, *, home_dir: home_dir == tmp_path,
    )

    assert not routine_setup_commands.is_safe_git_worktree_add(
        command_template.format(
            destination=destination,
            commit=commit,
            short_commit=commit[:12],
        ),
        cwd=repository,
        home_dir=tmp_path,
    )


def test_safe_git_worktree_add_rejects_checkout_hooks(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    _git(repository, "config", "core.hooksPath", str(hooks))
    hook = hooks / "post-checkout"
    hook.write_text("#!/bin/sh\nexit 0\n")
    hook.chmod(0o755)

    assert not routine_setup_commands.git_worktree_add_has_execution_free_config(
        repository,
        git_binary=Path("/usr/bin/git"),
    )


def test_safe_git_worktree_add_rejects_executable_fsmonitor(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    marker = tmp_path / "fsmonitor-ran"
    helper = tmp_path / "fsmonitor.sh"
    helper.write_text(f"#!/bin/sh\ntouch {marker}\n")
    helper.chmod(0o755)
    _git(repository, "config", "core.fsmonitor", str(helper))

    assert not routine_setup_commands.git_worktree_add_has_execution_free_config(repository)
    assert not marker.exists()


def test_worktree_filter_check_is_scoped_to_selected_ref(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    git_binary_text = shutil.which("git")
    assert git_binary_text is not None
    git_binary = Path(git_binary_text).resolve()
    assert not git_execution_safety._git_ref_uses_checkout_filter(
        git_binary,
        repository,
        "HEAD",
    )
    (repository / ".gitattributes").write_text("*.txt filter=guard-test\n")
    _git(repository, "add", ".gitattributes")
    _git(repository, "commit", "-qm", "add filter")

    assert git_execution_safety._git_ref_uses_checkout_filter(
        git_binary,
        repository,
        "HEAD",
    )
    assert git_execution_safety._git_ref_uses_checkout_filter(
        git_binary,
        repository,
        "--help",
    )


def test_codex_memory_registry_search_is_exact_and_nonexecuting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = tmp_path / ".codex" / "memories" / "MEMORY.md"
    registry.parent.mkdir(parents=True)
    registry.write_text("guard release notes\n")
    trusted_rg = Path("/usr/bin/rg")
    monkeypatch.setattr(
        routine_setup_commands,
        "_trusted_path_command",
        lambda command, *, cwd: trusted_rg if command == "rg" and cwd == tmp_path else None,
    )

    assert routine_setup_commands.is_safe_codex_memory_registry_search(
        "rg -n guard ~/.codex/memories/MEMORY.md",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert not routine_setup_commands.is_safe_codex_memory_registry_search(
        "rg -n guard ~/.codex/memories/MEMORY.md | sh",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert not routine_setup_commands.is_safe_codex_memory_registry_search(
        "rg -n guard ~/.codex/config.toml",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    monkeypatch.setenv("RIPGREP_CONFIG_PATH", str(tmp_path / "rg.conf"))
    assert not routine_setup_commands.is_safe_codex_memory_registry_search(
        "rg -n guard ~/.codex/memories/MEMORY.md",
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_codex_memory_registry_search_rejects_symlinked_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirected = tmp_path / "redirected" / "memories"
    redirected.mkdir(parents=True)
    (redirected / "MEMORY.md").write_text("redirected\n")
    (tmp_path / ".codex").symlink_to(tmp_path / "redirected", target_is_directory=True)
    monkeypatch.setattr(
        routine_setup_commands,
        "_trusted_path_command",
        lambda command, *, cwd: Path("/usr/bin/rg"),
    )

    assert not routine_setup_commands.is_safe_codex_memory_registry_search(
        "rg guard ~/.codex/memories/MEMORY.md",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
