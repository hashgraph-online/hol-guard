from __future__ import annotations

import io
from typing import cast

from rich.console import Console

from codex_plugin_scanner.guard import native_harness_client
from codex_plugin_scanner.guard.cli import install_commands, render
from codex_plugin_scanner.guard.harness_context import HarnessContext


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

    monkeypatch.setattr(native_harness_client, "ask", fake_ask)
    plan = install_commands.build_harness_setup_plan("connect", "claude-code", _context(tmp_path), dry_run=True)

    assert calls == [("install_target", "claude-code")]
    assert cast("dict[str, str]", plan["settings_target"])["settings_path"] == "/synthetic/.claude/settings.json"


def test_an_unavailable_native_target_is_shown_not_guessed(tmp_path, monkeypatch):
    def fake_ask(op, context, *, harness=None, **fields):
        raise OSError("native runtime unavailable")

    monkeypatch.setattr(native_harness_client, "ask", fake_ask)
    plan = install_commands.build_harness_setup_plan("connect", "claude-code", _context(tmp_path), dry_run=True)

    assert plan["settings_target"] == {"unavailable": True, "reason": "native runtime unavailable"}
    assert "could not read where Claude Code hooks would go" in _text(plan)


def test_the_panel_prints_the_text_the_runtime_worded_literally():
    # The runtime words the lines (see the install target tests beside it);
    # the CLI prints them, and a path named like Rich markup stays text.
    target = {
        "text": "Writes: /synthetic/[red]home/.claude/settings.json (user settings)\n"
        "Undo: hol-guard uninstall --home '/synthetic/my home[/b]'.\n"
        "Warning: /synthetic/[/red] sets disableAllHooks.",
        "border": "red",
    }

    text = _text({"settings_target": target})

    assert "Writes: /synthetic/[red]home/.claude/settings.json (user settings)" in text
    assert "Undo: hol-guard uninstall --home '/synthetic/my home[/b]'." in text
    assert "Warning: /synthetic/[/red] sets disableAllHooks." in text


def test_install_dry_run_shows_the_panel_for_each_planned_harness():
    target = {"text": "Writes: /synthetic/.claude/settings.json (user settings)", "border": "cyan"}
    buffer = io.StringIO()
    console = Console(file=buffer, width=200, color_system=None)

    render._render_managed_install(console, {"dry_run": True, "setup_plans": [{"settings_target": target}, {}]})

    assert buffer.getvalue().count("Claude Code settings") == 1


def test_an_answer_without_panel_text_shows_nothing():
    assert "Claude Code settings" not in _text({"settings_target": {"scope": "user"}})
