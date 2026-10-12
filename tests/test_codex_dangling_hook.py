"""A Codex Guard handler whose launcher or bridge was deleted gives no protection."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_registration import (
    live_guard_codex_hooks_intercept,
    missing_guard_hook_program,
    require_codex_hook_owner,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX hook command syntax")


def _bridge_command(bridge: Path, python: str = sys.executable) -> str:
    return f"{shlex.quote(python)} {shlex.quote(str(bridge))} --harness codex"


def _hooks(command: str) -> dict[str, object]:
    group = {"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}
    return {"PreToolUse": [group], "PermissionRequest": [dict(group)]}


def _bridge(tmp_path: Path) -> Path:
    bridge = tmp_path / "bin" / "codex_daemon_hook_bridge.py"
    bridge.parent.mkdir(parents=True)
    bridge.write_text("", encoding="utf-8")
    return bridge


def test_existing_bridge_is_not_missing(tmp_path):
    command = _bridge_command(_bridge(tmp_path))

    assert missing_guard_hook_program(command) is None
    assert live_guard_codex_hooks_intercept(_hooks(command))


def test_deleted_bridge_is_reported_and_fails_health(tmp_path):
    bridge = tmp_path / "removed-checkout" / "codex_daemon_hook_bridge.py"
    command = _bridge_command(bridge)

    assert missing_guard_hook_program(command) == str(bridge)
    assert not live_guard_codex_hooks_intercept(_hooks(command))


def test_deleted_interpreter_is_reported(tmp_path):
    python = str(tmp_path / "removed-venv" / "bin" / "python")
    command = _bridge_command(_bridge(tmp_path), python=python)

    assert missing_guard_hook_program(command) == python
    assert not live_guard_codex_hooks_intercept(_hooks(command))


def test_bare_launcher_is_resolved_at_launch_not_here():
    assert missing_guard_hook_program("python -m codex_plugin_scanner.cli guard hook --harness codex") is None


def test_non_guard_command_is_ignored(tmp_path):
    assert missing_guard_hook_program(str(tmp_path / "missing-tool") + " --flag") is None


def test_owner_conflict_names_the_deleted_program(tmp_path):
    bridge = tmp_path / "removed-checkout" / "codex_daemon_hook_bridge.py"

    with pytest.raises(RuntimeError, match="codex_hook_owner_conflict") as raised:
        require_codex_hook_owner(_bridge_command(bridge), ownership="unmanaged")

    message = str(raised.value)
    assert str(bridge) in message
    assert "no longer exists" in message
    assert "existing hooks have been preserved" in message
