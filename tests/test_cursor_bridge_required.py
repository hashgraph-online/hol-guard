"""Cursor install refuses, and reports unhealthy, when no native runtime answers."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters._modules.cursor.cursor_hook_native import (
    CursorNativeBridgeUnavailableError,
)
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hook_config import _managed_hook_command
from codex_plugin_scanner.guard.adapters.cursor_hooks import (
    cursor_hooks_path,
    cursor_native_hook_state,
    install_cursor_hooks,
    managed_hook_script_path,
)


@pytest.fixture
def no_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """No runtime on this machine advertises the Cursor hook bridge."""

    from codex_plugin_scanner.guard.adapters import native_hook_bridge

    monkeypatch.delenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", raising=False)
    monkeypatch.setattr(native_hook_bridge, "native_hook_bridge_executable", lambda *_args, **_kwargs: None)


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard")


def test_a_hook_command_is_not_rendered_without_the_runtime(tmp_path: Path, no_native_runtime: None) -> None:
    script = tmp_path / "hol-guard-cursor-hook.py"
    script.write_text("", encoding="utf-8")

    with pytest.raises(CursorNativeBridgeUnavailableError):
        _managed_hook_command(python_executable=None, script_path=script, event_name="preToolUse")


def test_the_suite_pin_does_not_apply_outside_test_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_native_runtime: None
) -> None:
    monkeypatch.setenv("HOL_GUARD_CURSOR_HOOK_BRIDGE", "python")
    monkeypatch.delenv("HOL_GUARD_TEST_MODE", raising=False)
    script = tmp_path / "hol-guard-cursor-hook.py"
    script.write_text("", encoding="utf-8")

    with pytest.raises(CursorNativeBridgeUnavailableError):
        _managed_hook_command(python_executable=None, script_path=script, event_name="preToolUse")


def test_installing_cursor_hooks_writes_nothing_without_the_runtime(tmp_path: Path, no_native_runtime: None) -> None:
    context = _context(tmp_path)

    with pytest.raises(CursorNativeBridgeUnavailableError):
        install_cursor_hooks(context)

    assert not cursor_hooks_path(context).exists()
    assert not managed_hook_script_path(context).exists()


def test_the_reported_state_is_unhealthy_without_the_runtime(tmp_path: Path, no_native_runtime: None) -> None:
    state = cursor_native_hook_state(_context(tmp_path))

    assert state["protection_active"] is False
    assert state["integrity_status"] == "missing"
    assert state["reason"] == "guard_cursor_native_bridge_unavailable"
