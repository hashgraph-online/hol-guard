from __future__ import annotations

import argparse
import io
import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook
from codex_plugin_scanner.guard.config import GuardConfig
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


@pytest.mark.usefixtures("native_hook_force")
def test_run_guard_hook_uses_payload_cwd_when_cli_workspace_omitted(tmp_path: Path) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    home.mkdir()
    repository = _repository(tmp_path)
    store = GuardStore(guard_home)
    config = GuardConfig(guard_home=guard_home, workspace=repository, default_action="review")
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "run_terminal_command",
        "toolInput": {"command": "git rev-parse --show-toplevel"},
        "cwd": str(repository),
    }
    output = io.StringIO()

    result = commands_hook._run_guard_hook_command(
        argparse.Namespace(
            artifact_id=None,
            artifact_name=None,
            event_file=None,
            harness="cursor",
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
        output_stream=output,
    )
    payload = json.loads(output.getvalue())

    assert result == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"
