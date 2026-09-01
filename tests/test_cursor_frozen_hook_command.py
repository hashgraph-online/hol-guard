"""Frozen Desktop Cursor hooks must use a supported launcher, not a raw .py argv."""

from __future__ import annotations

import shlex
from pathlib import Path

from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    FROZEN_CURSOR_HOOK_COMMAND,
    HOOK_SCRIPT_NAME,
    _managed_hook_command,
    run_frozen_cursor_hook,
)


def test_frozen_cursor_hook_command_uses_supported_launcher(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", True, raising=False)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable",
        "/Applications/HOL Guard.app/Contents/MacOS/hol-guard",
    )
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(python_executable=None, script_path=script)
    tokens = shlex.split(command)
    assert tokens[0] == "/Applications/HOL Guard.app/Contents/MacOS/hol-guard"
    assert tokens[1] == FROZEN_CURSOR_HOOK_COMMAND
    assert tokens[2].endswith(HOOK_SCRIPT_NAME)


def test_unfrozen_cursor_hook_command_uses_current_interpreter(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.frozen", False, raising=False)
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor_hook_config.sys.executable", "/usr/bin/python3")
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    command = _managed_hook_command(python_executable=None, script_path=script)
    assert FROZEN_CURSOR_HOOK_COMMAND not in command
    assert command.startswith("/usr/bin/python3")


def test_run_frozen_cursor_hook_executes_managed_script(tmp_path: Path) -> None:
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    marker = tmp_path / "ran"
    script.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ok', encoding='utf-8')\n",
        encoding="utf-8",
    )
    assert run_frozen_cursor_hook([str(script)]) == 0
    assert marker.read_text(encoding="utf-8") == "ok"


def test_run_frozen_cursor_hook_rejects_unmanaged_script(tmp_path: Path) -> None:
    script = tmp_path / "not-hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir()
    script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    assert run_frozen_cursor_hook([str(script)]) == 2
