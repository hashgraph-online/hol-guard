from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_git_execution_safety import git_execution_safety_native
from codex_plugin_scanner.guard.runtime import git_execution_safety, routine_setup_commands
from codex_plugin_scanner.guard.runtime.secret_file_request_services.benign_requests import (
    is_explicitly_benign_tool_action_request,
)


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
    _git(repository, "config", "core.hooksPath", ".git/no-hooks")
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

    for command in (
        f"git worktree add -b fix/routine {destination} origin/release/2.2",
        f"git worktree add {destination} -b fix/routine origin/release/2.2",
    ):
        assert routine_setup_commands.is_safe_git_worktree_add(
            command,
            cwd=repository,
            home_dir=tmp_path,
        )
    assert not routine_setup_commands.is_safe_git_worktree_add(
        f"git worktree add -b fix/routine {destination} origin/release/2.2 && sh payload.sh",
        cwd=repository,
        home_dir=tmp_path,
    )


def test_post_destination_worktree_add_with_bounded_output_is_explicitly_benign(
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

    assert is_explicitly_benign_tool_action_request(
        "Bash",
        {
            "command": (
                f"cd {repository} && git worktree add {destination} -b fix/routine origin/release/2.2 2>&1 | tail -3"
            )
        },
        cwd=repository,
        home_dir=tmp_path,
    )


@pytest.mark.parametrize(
    "suffix",
    (
        "2>&1 | tail -0",
        "2>&1 | head -3",
        "2>&1 | tee output.txt",
        "2>&1 | tail -3 && sh payload.sh",
    ),
)
def test_worktree_add_rejects_widened_output_consumers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
) -> None:
    repository = _repository(tmp_path)
    destination = tmp_path / "new-worktree"
    monkeypatch.setattr(
        routine_setup_commands,
        "_safe_worktree_parent",
        lambda _destination, *, home_dir: home_dir == tmp_path,
    )

    assert not routine_setup_commands.is_safe_git_worktree_add(
        f"cd {repository} && git worktree add {destination} -b fix/routine origin/release/2.2 {suffix}",
        cwd=tmp_path,
        home_dir=tmp_path,
    )


@pytest.mark.parametrize("directory", ("-", "--", "~other/repository", "~//tmp/repository", "repo*"))
def test_worktree_add_rejects_shell_expanding_cd_operands(
    tmp_path: Path,
    directory: str,
) -> None:
    destination = tmp_path / "new-worktree"

    assert not routine_setup_commands.is_safe_git_worktree_add(
        f"cd {directory} && git worktree add {destination} -b fix/routine origin/release/2.2",
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_worktree_add_rejects_path_shadowed_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repository(tmp_path)
    destination = tmp_path / "new-worktree"
    shadow_bin = repository / "bin"
    shadow_bin.mkdir()
    shadow_tail = shadow_bin / "tail"
    shadow_tail.write_text("#!/bin/sh\nexit 0\n")
    shadow_tail.chmod(0o755)
    monkeypatch.setenv("PATH", str(shadow_bin))

    assert not routine_setup_commands.is_safe_git_worktree_add(
        f"git worktree add {destination} -b fix/routine origin/release/2.2 2>&1 | tail -3",
        cwd=repository,
        home_dir=tmp_path,
    )


@pytest.mark.parametrize(
    "command_template",
    (
        "git worktree add {destination} --force -b fix/routine origin/release/2.2",
        "git worktree add {destination} -b fix/routine --force origin/release/2.2",
        "git worktree add $DESTINATION -b fix/routine origin/release/2.2",
        "git worktree add ~other/new-worktree -b fix/routine origin/release/2.2",
        "git worktree add ~//tmp/new-worktree -b fix/routine origin/release/2.2",
        "git worktree add {destination}* -b fix/routine origin/release/2.2",
        "git worktree add {destination} -b fix/routine origin/release/2.2 && sh payload.sh",
    ),
)
def test_safe_git_worktree_add_rejects_widened_post_destination_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command_template: str,
) -> None:
    repository = _repository(tmp_path)
    destination = tmp_path / "new-worktree"
    monkeypatch.setattr(
        routine_setup_commands,
        "_safe_worktree_parent",
        lambda _destination, *, home_dir: home_dir == tmp_path,
    )

    assert not routine_setup_commands.is_safe_git_worktree_add(
        command_template.format(destination=destination),
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


def test_safe_git_worktree_add_ignores_network_credential_helpers(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _git(repository, "config", "credential.helper", "!false")

    assert git_execution_safety.git_worktree_add_has_execution_free_config(repository)


@pytest.mark.parametrize(
    ("config_key", "config_value"),
    (
        ("extensions.partialClone", "origin"),
        ("extensions.partialClone", "false"),
        ("extensions.partialClone", " "),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialCloneFilter", "blob:none"),
        ("remote.origin.partialCloneFilter", "false"),
    ),
)
def test_safe_git_worktree_add_rejects_partial_clone_configuration(
    tmp_path: Path,
    config_key: str,
    config_value: str,
) -> None:
    repository = _repository(tmp_path)
    _git(repository, "config", config_key, config_value)

    assert not git_execution_safety.git_worktree_add_has_execution_free_config(repository)


@pytest.mark.parametrize(
    ("environment_key", "environment_value"),
    (
        ("GIT_EXEC_PATH", "helpers"),
        ("GIT_OBJECT_DIRECTORY", " "),
    ),
)
def test_safe_git_worktree_add_rejects_local_checkout_execution_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    environment_key: str,
    environment_value: str,
) -> None:
    repository = _repository(tmp_path)
    monkeypatch.setenv(environment_key, environment_value)

    assert not git_execution_safety.git_worktree_add_has_execution_free_config(repository)


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


def test_worktree_add_is_refused_when_the_selected_ref_uses_a_filter(tmp_path: Path) -> None:
    # Positive and ref-scoping vectors live in the Rust real-git tests, where host
    # filter drivers are accounted for. This pins the refusal through the bridge.
    repository = _repository(tmp_path)
    (repository / "a.txt").write_text("data\n")
    (repository / ".gitattributes").write_text("*.txt filter=guard-test\n")
    _git(repository, "add", ".gitattributes", "a.txt")
    _git(repository, "commit", "-qm", "add filter")

    _git(repository, "config", "filter.guard-test.clean", "cat")

    answer = git_execution_safety_native("worktree_add", cwd=repository, reference="HEAD")
    if answer is None:
        if os.environ.get("HOL_GUARD_NATIVE_REGRESSION", "").strip().lower() in {"1", "true", "yes"}:
            pytest.fail("the native resident did not answer the worktree filter check")
        pytest.skip("the native resident is unavailable, so a refusal would not show filter detection")
    assert answer.allowed is False
    assert not routine_setup_commands.git_worktree_add_has_execution_free_config(repository)
    assert not routine_setup_commands.git_worktree_add_has_execution_free_config(repository, ref="--help")


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
