"""Frozen Desktop Cursor hooks must use a supported launcher, not a raw .py argv."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.cursor_hook_config import (
    FROZEN_CURSOR_HOOK_COMMAND,
    HOOK_SCRIPT_NAME,
    _live_cursor_hook_script_path,
    _managed_hook_command,
    live_guard_cursor_hooks_intercept,
    run_frozen_cursor_hook,
)


def _blocking_cursor_hooks(command: str) -> dict[str, list[dict[str, str]]]:
    entry = [{"command": command}]
    return {
        "beforeShellExecution": entry,
        "beforeMCPExecution": entry,
        "beforeReadFile": entry,
    }


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
    assert run_frozen_cursor_hook([str(script)]) == 3


def test_run_frozen_cursor_hook_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_text("raise SystemExit(0)\n", encoding="utf-8")
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    try:
        script.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    assert run_frozen_cursor_hook([str(script)]) == 3


def test_run_frozen_cursor_hook_rejects_wrong_argc() -> None:
    assert run_frozen_cursor_hook([]) == 2
    assert run_frozen_cursor_hook(["a", "b"]) == 2


def test_live_cursor_hook_script_path_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_text("raise SystemExit(0)\n", encoding="utf-8")
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    try:
        script.symlink_to(target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlink creation unavailable: {error}")
    frozen_command = shlex.join(["hol-guard", FROZEN_CURSOR_HOOK_COMMAND, str(script)])
    python_command = shlex.join(["python3", str(script)])
    assert _live_cursor_hook_script_path(frozen_command) is None
    assert _live_cursor_hook_script_path(python_command) is None
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(frozen_command)) is False
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(python_command)) is False


def test_live_cursor_hook_script_path_accepts_regular_managed_script(tmp_path: Path) -> None:
    script = tmp_path / ".cursor" / "hooks" / HOOK_SCRIPT_NAME
    script.parent.mkdir(parents=True)
    script.write_text("raise SystemExit(0)\n", encoding="utf-8")
    frozen_command = shlex.join(["hol-guard", FROZEN_CURSOR_HOOK_COMMAND, str(script)])
    python_command = shlex.join(["python3", str(script)])
    assert _live_cursor_hook_script_path(frozen_command) == script
    assert _live_cursor_hook_script_path(python_command) == script
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(frozen_command)) is True
    assert live_guard_cursor_hooks_intercept(_blocking_cursor_hooks(python_command)) is True
