"""A different Guard home does not authenticate ownership of existing hooks."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter


def _command_group(command: str) -> dict[str, object]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": command}],
    }


def test_install_config_hooks_rejects_foreign_owner_without_mutation(tmp_path: Path) -> None:
    current = tmp_path / "guard-home"
    current.mkdir()
    foreign = tmp_path / "pytest-of-user" / "guard-home"
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=current,
    )
    payload: dict[str, object] = {
        "hooks": {
            "PreToolUse": [
                _command_group(f"python -m codex_plugin_scanner.cli guard hook --harness codex --guard-home {foreign}"),
                _command_group("lean-ctx hook observe"),
            ]
        }
    }
    before = deepcopy(payload)
    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict"):
        CodexHarnessAdapter._install_config_hooks(payload, context, config_path=tmp_path / "config.toml")
    assert payload == before
    hooks = payload["hooks"]
    assert isinstance(hooks, dict)
    groups = hooks["PreToolUse"]
    assert isinstance(groups, list)
    commands = [
        hook["command"]
        for group in groups
        if isinstance(group, dict)
        for hook in group.get("hooks", [])
        if isinstance(hook, dict) and isinstance(hook.get("command"), str)
    ]
    assert any("pytest-of-user" in command for command in commands)
    assert any("lean-ctx hook observe" in command for command in commands)
    assert not any("codex_daemon_hook_bridge.py" in command for command in commands)
