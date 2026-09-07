"""Codex install must drop Guard hooks bound to a different Guard home."""

from __future__ import annotations

import shlex
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_registration import (
    is_foreign_guard_codex_hook_group,
    prune_foreign_guard_codex_hook_groups,
)


def _command_group(command: str) -> dict[str, object]:
    return {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": command}],
    }


def test_foreign_hook_detects_pytest_guard_home(tmp_path: Path) -> None:
    current = tmp_path / "guard-home"
    foreign = tmp_path / "pytest-of-user" / "test_repair" / "guard-home"
    group = _command_group(f"python -m codex_plugin_scanner.cli guard hook --harness codex --guard-home {foreign}")
    assert is_foreign_guard_codex_hook_group(group, current_guard_home=current) is True


def test_same_guard_home_legacy_bridge_is_not_foreign(tmp_path: Path) -> None:
    current = tmp_path / "guard-home"
    group = _command_group(
        "python -I /opt/uv/hol-guard/adapters/codex_daemon_hook_bridge.py "
        '{"state_path":"' + str(current / "daemon-state.json") + '"}'
    )
    assert is_foreign_guard_codex_hook_group(group, current_guard_home=current) is False


def test_non_guard_hooks_are_not_foreign() -> None:
    group = _command_group("lean-ctx hook observe")
    assert is_foreign_guard_codex_hook_group(group, current_guard_home=Path("guard-home")) is False


def test_bridge_flag_in_non_guard_command_is_not_foreign(tmp_path: Path) -> None:
    current = tmp_path / "guard-home"
    foreign = tmp_path / "other-home"
    group = _command_group(f"echo --_hol-guard-codex-bridge --guard-home {foreign}")
    assert is_foreign_guard_codex_hook_group(group, current_guard_home=current) is False


def test_unrelated_scanner_cli_hook_is_not_foreign(tmp_path: Path) -> None:
    current = tmp_path / "guard-home"
    foreign = tmp_path / "other-home"
    group = _command_group(f"python -m codex_plugin_scanner.cli scan --guard-home {foreign}")
    assert is_foreign_guard_codex_hook_group(group, current_guard_home=current) is False


def test_quoted_same_home_path_with_spaces_is_not_foreign(tmp_path: Path) -> None:
    current = tmp_path / "Application Support" / "guard-home"
    current.mkdir(parents=True)
    group = _command_group(
        f"python -m codex_plugin_scanner.cli guard hook --harness codex --guard-home {shlex.quote(str(current))}"
    )
    assert is_foreign_guard_codex_hook_group(group, current_guard_home=current) is False


def test_mixed_home_group_keeps_current_handler_only(tmp_path: Path) -> None:
    current = tmp_path / "guard-home"
    current.mkdir()
    foreign = tmp_path / "pytest-of-user" / "guard-home"
    mixed = {
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": (f"python -m codex_plugin_scanner.cli guard hook --harness codex --guard-home {current}"),
            },
            {
                "type": "command",
                "command": (f"python -m codex_plugin_scanner.cli guard hook --harness codex --guard-home {foreign}"),
            },
        ],
    }
    pruned = prune_foreign_guard_codex_hook_groups([mixed], current_guard_home=current)
    assert len(pruned) == 1
    remaining = pruned[0]
    assert isinstance(remaining, dict)
    handlers = remaining.get("hooks")
    assert isinstance(handlers, list)
    assert len(handlers) == 1
    handler = handlers[0]
    assert isinstance(handler, dict)
    command = handler.get("command")
    assert isinstance(command, str)
    assert str(current) in command
    assert "pytest-of-user" not in command


def test_install_config_hooks_drops_foreign_home_and_keeps_other_hooks(tmp_path: Path) -> None:
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
    CodexHarnessAdapter._install_config_hooks(payload, context)
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
    assert all("pytest-of-user" not in command for command in commands)
    assert any("lean-ctx hook observe" in command for command in commands)
    assert any("codex_daemon_hook_bridge.py" in command for command in commands)
