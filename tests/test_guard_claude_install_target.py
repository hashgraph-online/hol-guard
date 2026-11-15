from __future__ import annotations

import io
import os

from rich.console import Console

from codex_plugin_scanner.guard.adapters import native_harness
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import install_commands, render
from codex_plugin_scanner.guard.cli.claude_settings_target import _command_text


def _context(tmp_path):
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=tmp_path / "project", guard_home=tmp_path / "g")


def _text(payload: dict[str, object]) -> str:
    buffer = io.StringIO()
    render._render_apps(Console(file=buffer, width=200, color_system=None), payload)
    return buffer.getvalue()


def test_dry_run_plan_carries_the_native_claude_target(tmp_path, monkeypatch):
    calls: list[tuple[str, str | None]] = []

    def fake_ask(op, context, *, harness=None, **fields):
        calls.append((op, harness))
        return {"scope": "user", "settings_path": "/synthetic/.claude/settings.json"}

    monkeypatch.setattr(native_harness, "ask", fake_ask)
    plan = install_commands.build_harness_setup_plan("connect", "claude-code", _context(tmp_path), dry_run=True)

    assert calls == [("install_target", "claude-code")]
    assert plan["settings_target"]["settings_path"] == "/synthetic/.claude/settings.json"


def test_an_unavailable_native_target_is_shown_not_guessed(tmp_path, monkeypatch):
    def fake_ask(op, context, *, harness=None, **fields):
        raise OSError("native runtime unavailable")

    monkeypatch.setattr(native_harness, "ask", fake_ask)
    plan = install_commands.build_harness_setup_plan("connect", "claude-code", _context(tmp_path), dry_run=True)

    assert plan["settings_target"] == {"unavailable": True, "reason": "native runtime unavailable"}
    assert "could not read where Claude Code hooks would go" in _text(plan)


def test_the_panel_names_the_file_the_rollback_and_each_override():
    target = {
        "scope": "user",
        "settings_path": "/synthetic/.claude/settings.json",
        "workspace_note": "--workspace does not install into /synthetic/project/.claude.",
        "precedence": [
            {"scope": "managed", "path": "/etc/claude-code/managed-settings.json", "guard_writes": False},
            {"scope": "user", "path": "/synthetic/.claude/settings.json", "guard_writes": True},
        ],
        "rollback": {"command": ["hol-guard", "uninstall", "claude-code"], "effect": "Removes only Guard's entries."},
        "hook_overrides": [{"message": "/synthetic/project/.claude/settings.local.json sets disableAllHooks."}],
    }

    text = _text({"settings_target": target})

    assert "Writes: /synthetic/.claude/settings.json (user settings)" in text
    assert "--workspace does not install into" in text
    assert "* user: /synthetic/.claude/settings.json" in text
    assert "Undo: hol-guard uninstall claude-code." in text
    assert "Warning: /synthetic/project/.claude/settings.local.json sets disableAllHooks." in text


def test_install_dry_run_shows_the_panel_for_each_planned_harness():
    target = {"scope": "user", "settings_path": "/synthetic/.claude/settings.json"}
    buffer = io.StringIO()
    console = Console(file=buffer, width=200, color_system=None)

    render._render_managed_install(console, {"dry_run": True, "setup_plans": [{"settings_target": target}, {}]})

    assert buffer.getvalue().count("Writes: /synthetic/.claude/settings.json (user settings)") == 1


def test_paths_render_literally_and_the_undo_is_shell_quoted():
    target = {
        "scope": "user",
        "settings_path": "/synthetic/[red]home/.claude/settings.json",
        "rollback": {"command": ["hol-guard", "uninstall", "claude-code", "--home", "/synthetic/my home[/b]"]},
        "hook_overrides": [{"message": "/synthetic/[/red] sets disableAllHooks."}],
    }

    text = _text({"settings_target": target})

    assert "Writes: /synthetic/[red]home/.claude/settings.json" in text
    quoted = '"/synthetic/my home[/b]"' if os.name == "nt" else "'/synthetic/my home[/b]'"
    assert f"Undo: hol-guard uninstall claude-code --home {quoted}." in text
    assert "Warning: /synthetic/[/red] sets disableAllHooks." in text


def test_a_copied_undo_uses_double_quotes_for_windows_shells():
    words = ["hol-guard", "uninstall", "claude-code", "--home", r"C:\Guard State"]

    assert _command_text(words, windows=True) == r'hol-guard uninstall claude-code --home "C:\Guard State"'
    assert _command_text(words, windows=False) == "hol-guard uninstall claude-code --home 'C:\\Guard State'"
