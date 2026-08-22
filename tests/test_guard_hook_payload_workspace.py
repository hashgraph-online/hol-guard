from __future__ import annotations

import argparse
import io
import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok_hooks import prepare_grok_hook_payload
from codex_plugin_scanner.guard.adapters.zcode_hooks import prepare_zcode_hook_payload
from codex_plugin_scanner.guard.cli import commands_hook
from codex_plugin_scanner.guard.cli.commands_support_workspace import _workspace_from_hook_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def _isolate_git_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "git-config-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    for variable in ("GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_EXTERNAL_DIFF"):
        monkeypatch.delenv(variable, raising=False)


def _repository(root: Path) -> Path:
    repository = root / "project"
    repository.mkdir()
    _ = subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)], check=True)
    return repository


def test_hook_payload_cwd_resolves_workspace(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    other = tmp_path / "other"
    other.mkdir()

    assert _workspace_from_hook_payload({"cwd": str(repository)}) == repository.resolve()
    assert _workspace_from_hook_payload({"workspaceRoot": str(repository)}) == repository.resolve()
    assert _workspace_from_hook_payload({}) is None
    assert _workspace_from_hook_payload({"workspaceRoot": str(repository), "cwd": str(other)}) == repository.resolve()
    assert _workspace_from_hook_payload({"cwd": str(other)}, repository) == repository.resolve()


def test_cached_check_is_benign_only_with_payload_cwd(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    repository = _repository(tmp_path)
    command = {"command": "git diff --cached --check"}

    assert not is_explicitly_benign_tool_action_request("Bash", command, cwd=None, home_dir=home)
    assert is_explicitly_benign_tool_action_request("Bash", command, cwd=repository, home_dir=home)


def test_grok_and_zcode_payloads_keep_workspace_root_when_cwd_differs(tmp_path: Path) -> None:
    root = tmp_path / "root"
    cwd = tmp_path / "cwd"
    root.mkdir()
    cwd.mkdir()
    payload = {
        "hookEventName": "PreToolUse",
        "toolName": "run_terminal_command",
        "toolInput": {"command": "git status --short"},
        "workspaceRoot": str(root),
        "cwd": str(cwd),
    }

    grok = prepare_grok_hook_payload(payload)
    zcode = prepare_zcode_hook_payload(payload)
    assert grok["workspace_root"] == str(root)
    assert zcode["workspace_root"] == str(root)


def test_run_guard_hook_uses_payload_cwd_when_cli_workspace_omitted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    home.mkdir()
    repository = _repository(tmp_path)
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=repository, default_action="review")
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "run_terminal_command",
        "toolInput": {"command": "git diff --cached --check"},
        "cwd": str(repository),
    }

    result = commands_hook._run_guard_hook_command(
        argparse.Namespace(
            artifact_id=None,
            artifact_name=None,
            event_file=None,
            harness="grok",
            json=True,
            policy_action=None,
            runtime_harness=None,
        ),
        guard_home=guard_home,
        workspace=None,
        context=HarnessContext(home, repository, guard_home),
        store=store,
        config=config,
        input_text=json.dumps(event),
        output_stream=io.StringIO(),
    )
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert payload["policy_composition"]["configured_default_disposition"] == "relaxed_verified_benign"
