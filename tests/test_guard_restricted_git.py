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


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"), reason="macOS OS boundary")
def test_actual_git_inspection_does_not_invoke_helpers(tmp_path, capfd):
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
    source.write_text("new\n")
    marker = workspace / "unexpected-helper"
    helper = workspace / "helper.sh"
    helper.write_text(f"#!/bin/sh\nprintf unexpected > '{marker}'\nexit 1\n")
    helper.chmod(0o700)
    invoke("config", "diff.external", str(helper))
    invoke("config", "core.fsmonitor", str(helper))
    for operation in (("diff", "--stat"), ("diff", "--check"), ("log", "--oneline", "-1")):
        plan = git.prepare_restricted_git(["git", *operation], workspace=workspace)
        assert git.run_restricted_git(plan, timeout_seconds=20) == 0
    output = capfd.readouterr().out
    assert "example.txt" in output and "fixture" in output
    assert source.read_text() == "new\n"
    assert not marker.exists()
