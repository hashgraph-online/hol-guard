"""Protected Git performs real inspections without executing configured helpers."""

import shutil
import subprocess
import sys

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_git as git
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.parametrize(
    "command",
    [
        ["git", "reset", "--hard"],
        ["git", "diff", "--ext-diff"],
        ["git", "diff", "--output=x"],
        ["git", "show", ";", "sh"],
    ],
)
def test_mutation_helpers_and_shell_effects_rejected(command, tmp_path):
    with pytest.raises(RestrictedPytestError):
        git.prepare_restricted_git(command, workspace=tmp_path)


def test_fresh_native_deny_prevents_execution(monkeypatch, tmp_path):
    executed = []
    monkeypatch.setattr(git, "prepare_restricted_git", lambda *args, **kwargs: object())
    monkeypatch.setattr(git, "run_restricted_git", lambda *args, **kwargs: executed.append(True))
    with pytest.raises(RestrictedPytestError):
        sink.run_authorized_contained_test(
            {"tool_input": {"command": "git diff --stat"}},
            workspace=tmp_path,
            timeout_seconds=10,
            authorize=lambda payload: {"decision": "deny", "policy_action": "block"},
        )
    assert not executed


def test_linux_git_uses_the_filtered_readonly_profile(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    executable = tmp_path / "git"
    executable.write_text("synthetic image")
    monkeypatch.setattr(git, "_select_backend", lambda **kwargs: ("linux-bubblewrap", tmp_path / "bwrap"))
    monkeypatch.setattr(git, "_resolve_executable", lambda *args, **kwargs: executable)
    monkeypatch.setattr(git, "git_binary_path_is_trusted", lambda *args, **kwargs: True)
    plan = git.prepare_restricted_git(["git", "diff", "--stat"], workspace=tmp_path)
    assert plan.backend == "linux-bubblewrap"
    assert plan.profile_version == "git-readonly-v1"
    assert plan.allowed_executables == (executable,)
    assert "--no-ext-diff" in plan.command and "--no-textconv" in plan.command
    assert plan.command[plan.command.index("-c") + 1] == "core.fsmonitor=false"


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"), reason="macOS OS boundary")
@pytest.mark.parametrize("linked", [False, True])
def test_actual_git_inspection_does_not_invoke_helpers(tmp_path, capfd, linked):
    workspace = tmp_path / "project"
    workspace.mkdir()
    executable = shutil.which("git")

    def invoke(*args):
        return subprocess.run([executable, *args], cwd=workspace, check=True, capture_output=True, text=True)

    invoke("init", "--initial-branch=main")
    source = workspace / "example.txt"
    source.write_text("old\n")
    invoke("add", "example.txt")
    invoke(
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    repository = workspace
    if linked:
        linked_workspace = tmp_path / "linked"
        invoke("worktree", "add", "-b", "fixture-linked", str(linked_workspace))
        workspace = linked_workspace
        source = workspace / "example.txt"
    source.write_text("new\n")
    marker = workspace / "unexpected-helper"
    helper = workspace / "helper.sh"
    helper.write_text(f"#!/bin/sh\nprintf unexpected > '{marker}'\nexit 1\n")
    helper.chmod(0o700)
    invoke("config", "diff.external", str(helper))
    invoke("config", "core.fsmonitor", str(helper))
    for operation in (("diff", "--stat"), ("diff", "--check"), ("log", "--oneline", "-1")):
        plan = git.prepare_restricted_git(["git", *operation], workspace=workspace)
        if linked:
            assert repository not in plan.read_only_roots
            assert (repository / ".git").resolve() in plan.read_only_roots
        assert git.run_restricted_git(plan, timeout_seconds=20) == 0
    output = capfd.readouterr().out
    assert "example.txt" in output and "fixture" in output
    assert source.read_text() == "new\n"
    assert not marker.exists()


@pytest.mark.parametrize("pointer", ["gitdir: /\n", "gitdir: /tmp\n", "not a git pointer\n"])
def test_metadata_pointer_cannot_grant_arbitrary_host_root(tmp_path, pointer):
    (tmp_path / ".git").write_text(pointer)
    with pytest.raises(RestrictedPytestError):
        git._repository_read_roots(tmp_path, tmp_path)


def test_symlinked_metadata_pointer_is_not_a_read_grant(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".git").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RestrictedPytestError):
        git._repository_read_roots(tmp_path, tmp_path)
