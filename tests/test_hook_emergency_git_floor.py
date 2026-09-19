"""Git configuration is not executable-safety proof for emergency inspection."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_failure import failure_payload
from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    availability_harness_response,
    hook_action_is_emergency_safe,
)
from codex_plugin_scanner.guard.daemon.hook_worker_responses import prepare_native_hook_policy


def _payload(command: str) -> dict[str, object]:
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}}


@pytest.mark.parametrize(
    "command", ["git version", "git --version", "git   --version", 'git "version"', "git\t--version"]
)
def test_only_exact_git_version_argv_is_emergency_safe(command: str) -> None:
    assert hook_action_is_emergency_safe(_payload(command))


@pytest.mark.parametrize(
    "command",
    [
        "git",
        "git status",
        "git status --porcelain=v1",
        "git diff",
        "git diff --no-ext-diff --no-textconv",
        "git log",
        "git log --oneline",
        "git show HEAD",
        "git rev-parse --show-toplevel",
        "git describe",
        "git shortlog",
        "git blame app.py",
        "git ls-files",
        "git ls-tree HEAD",
        "git cat-file --filters HEAD:app.py",
        "git grep pattern",
        "git stash list",
        "git stash show --output=review.txt",
        "git help",
        "git --help",
        "git --help status",
        "git version --build-options",
        "git --version --help",
        "git version --",
        "git -C . version",
        "git -c core.pager=helper version",
        "git --config-env=core.pager=HELPER version",
        "git --exec-path=local version",
        "git --no-pager log",
        "git --no-pager version",
        "env git --version",
        "command git version",
        "GIT version",
        "git.exe version",
        "./git --version",
        "/usr/bin/git --version",
        "/tmp/git version",
        "git version > version.txt",
        "git version && true",
        "git version; true",
        "git version\ntrue",
        'git "$(echo version)"',
    ],
)
def test_unproved_git_commands_do_not_receive_emergency_exemption(command: str) -> None:
    assert not hook_action_is_emergency_safe(_payload(command))


def test_emergency_git_classification_does_not_read_config_or_spawn_git(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("mechanical emergency classification must not perform configuration I/O")

    with monkeypatch.context() as isolated:
        isolated.setattr(Path, "read_text", unexpected)
        isolated.setattr(Path, "read_bytes", unexpected)
        isolated.setattr(subprocess, "run", unexpected)
        assert hook_action_is_emergency_safe(_payload("git version"))
        assert not hook_action_is_emergency_safe(_payload("git diff --no-ext-diff --no-textconv"))


@dataclass(frozen=True)
class GitFixture:
    repository: Path
    binary: str
    environment: dict[str, str]
    helper: Path
    marker: Path

    def run(self, *args: str, terminal: bool = False) -> None:
        if terminal:
            import pty

            master, slave = pty.openpty()
            try:
                subprocess.run(
                    [self.binary, *args],
                    cwd=self.repository,
                    env=self.environment,
                    stdout=slave,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=True,
                )
            finally:
                os.close(slave)
                os.close(master)
        else:
            subprocess.run(
                [self.binary, *args],
                cwd=self.repository,
                env=self.environment,
                capture_output=True,
                timeout=10,
                check=True,
            )

    def configure(self, key: str, mode: str) -> None:
        self.run("config", key, shlex.join([sys.executable, str(self.helper), mode]))


@pytest.fixture
def configured_git(tmp_path: Path) -> GitFixture:
    binary = shutil.which("git")
    if binary is None:
        pytest.skip("Git is required for the local helper execution witness")
    repository = tmp_path / "repository"
    repository.mkdir()
    helper = tmp_path / "helper.py"
    marker = tmp_path / "executed"
    helper.write_text(
        "from pathlib import Path\nimport sys\n"
        f"Path({str(marker)!r}).write_text('fixture helper executed\\n')\n"
        "if sys.argv[1] == 'pager': sys.stdin.buffer.read()\n"
        "elif sys.argv[1] == 'fsmonitor': sys.stdout.buffer.write(b'fixture-token\\0')\n"
        "else: print('fixture driver output')\n",
        encoding="utf-8",
    )
    # Exclude ambient Git configuration, helpers, hooks, and network prompts.
    environment = {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "TERM": "dumb",
    }
    fixture = GitFixture(repository, str(Path(binary).resolve()), environment, helper, marker)
    fixture.run("init", "--quiet", "--template=", ".")
    fixture.run("config", "user.name", "Fixture")
    fixture.run("config", "user.email", "fixture@example.invalid")
    (repository / "tracked.txt").write_text("before\n", encoding="utf-8")
    (repository / ".gitattributes").write_text("*.txt diff=fixture\n", encoding="utf-8")
    fixture.run("add", "tracked.txt", ".gitattributes")
    fixture.run("commit", "--quiet", "-m", "fixture")
    (repository / "tracked.txt").write_text("after\n", encoding="utf-8")
    return fixture


@pytest.mark.skipif(os.name == "nt", reason="POSIX local helper and pager execution witness")
@pytest.mark.parametrize(
    "key,args,mode,terminal",
    [
        ("diff.external", ("diff",), "diff", False),
        ("diff.fixture.textconv", ("diff",), "textconv", False),
        ("diff.fixture.textconv", ("show",), "textconv", False),
        ("diff.fixture.textconv", ("log", "-p"), "textconv", False),
        ("core.fsmonitor", ("status",), "fsmonitor", False),
        ("core.pager", ("log",), "pager", True),
    ],
)
def test_configured_git_helpers_execute_without_explicit_execution_flags(
    configured_git: GitFixture,
    key: str,
    args: tuple[str, ...],
    mode: str,
    terminal: bool,
) -> None:
    configured_git.configure(key, mode)

    configured_git.run(*args, terminal=terminal)

    assert configured_git.marker.read_text(encoding="utf-8") == "fixture helper executed\n"
    assert not hook_action_is_emergency_safe(_payload(shlex.join(["git", *args])), workspace=configured_git.repository)


@pytest.mark.skipif(os.name == "nt", reason="POSIX local helper and pager execution witness")
@pytest.mark.parametrize("argument", ["version", "--version"])
def test_exact_version_query_does_not_execute_configured_helpers(configured_git: GitFixture, argument: str) -> None:
    for key, mode in (
        ("core.pager", "pager"),
        ("core.fsmonitor", "fsmonitor"),
        ("diff.external", "diff"),
        ("diff.fixture.textconv", "textconv"),
    ):
        configured_git.configure(key, mode)
    configured_git.run("config", "pager.version", "true")

    configured_git.run(argument, terminal=True)

    assert not configured_git.marker.exists()
    assert hook_action_is_emergency_safe(_payload(f"git {argument}"), workspace=configured_git.repository)


@pytest.mark.parametrize("command", ["git diff", "git log", "git show", "git status"])
def test_git_reclassification_preserves_ordinary_unavailability_and_watch(command: str) -> None:
    payload = _payload(command)
    unavailable = availability_harness_response(
        payload,
        harness="cursor",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="fixture unavailable",
    )
    assert unavailable["policy_action"] == "warn"
    assert unavailable["reason_code"] == "native_pre_tool_unavailable"
    hook_specific = unavailable["hookSpecificOutput"]
    assert isinstance(hook_specific, dict)
    assert hook_specific["permissionDecision"] == "allow"
    for recording_only, continue_session in ((True, False), (False, True)):
        response, code = failure_payload(
            harness="grok",
            event_name="PreToolUse",
            reason="fixture unavailable",
            payload=payload,
            recording_only=recording_only,
            continue_session=continue_session,
        )
        assert (response["decision"], code) == ("allow", 0)


@pytest.mark.parametrize("command,expected", [("git status", "deny"), ("git diff", "deny"), ("git --version", "allow")])
def test_bounded_cli_emergency_branch_requires_the_narrow_git_proof(command: str, expected: str) -> None:
    response, code = failure_payload(
        harness="grok",
        event_name="PreToolUse",
        reason="fixture failure",
        payload=_payload(command),
        recording_only=False,
        continue_session=False,
    )
    assert (response["decision"], code) == (expected, 0)


@pytest.mark.parametrize("prepared", [None, object()])
@pytest.mark.parametrize("command", ["git diff", "git status", "git --version"])
def test_native_policy_barrier_preserves_ready_policy_and_narrows_only_emergency_admission(
    prepared: object,
    command: str,
    tmp_path: Path,
) -> None:
    worker = SimpleNamespace(
        prepare_workspace_policy=Mock(return_value=prepared), metrics=SimpleNamespace(record_route=Mock())
    )
    server = SimpleNamespace(hook_worker=worker)
    response = {"policy_action": "warn", "reason_code": "native_policy_not_ready"}
    handler = SimpleNamespace(_write_json=Mock(), _runtime_hook_fail_safe_response=Mock(return_value=response))

    admitted = prepare_native_hook_policy(handler, server, _payload(command), {}, "cursor", str(tmp_path), 1.0)

    expected = prepared is not None or command == "git --version"
    assert admitted is expected
    if expected:
        handler._write_json.assert_not_called()
        worker.metrics.record_route.assert_not_called()
    else:
        handler._write_json.assert_called_once_with(response)
        worker.metrics.record_route.assert_called_once_with("native_fail_safe")
        assert handler._runtime_hook_fail_safe_response.call_args.kwargs["reason_code"] == "native_policy_not_ready"
