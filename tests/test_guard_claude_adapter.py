"""Guard adapter tests for Claude Code surfaces."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _build_context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
    )


def test_claude_detect_marks_local_cli_install_as_available_when_not_on_path(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    actual_home = tmp_path / "actual-home"
    local_claude = actual_home / ".claude" / "local" / "claude"
    local_claude.parent.mkdir(parents=True, exist_ok=True)
    local_claude.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_claude.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda command: None)
    monkeypatch.setattr(Path, "home", lambda: actual_home)

    detection = adapter.detect(context)

    assert detection.installed is True
    assert detection.command_available is True


def test_claude_launch_command_uses_local_cli_install_when_not_on_path(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    actual_home = tmp_path / "actual-home"
    local_claude = actual_home / ".claude" / "local" / "claude"
    local_claude.parent.mkdir(parents=True, exist_ok=True)
    local_claude.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_claude.chmod(0o755)
    monkeypatch.setattr("shutil.which", lambda command: None)
    monkeypatch.setattr(Path, "home", lambda: actual_home)

    launch_command = adapter.launch_command(context, ["--print", "hello"])

    assert launch_command[0] == str(local_claude)
    assert launch_command[1] == str(context.workspace_dir)
    assert launch_command[2:] == ["--print", "hello"]


def test_claude_detect_ignores_non_executable_local_cli_candidate_when_not_on_path(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    local_binary = tmp_path / "actual-home" / ".claude" / "local" / "claude"
    local_binary.parent.mkdir(parents=True, exist_ok=True)
    local_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    local_binary.chmod(0o644)

    monkeypatch.setattr("shutil.which", lambda command: None)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "actual-home")

    detection = adapter.detect(context)

    assert detection.installed is False
    assert detection.command_available is False


def test_claude_install_bakes_launcher_pythonpath_into_hook_command(monkeypatch, tmp_path):
    context = _build_context(tmp_path)
    adapter = ClaudeCodeHarnessAdapter()
    monkeypatch.setenv("PYTHONPATH", str(Path("/repo/src")))

    install_output = adapter.install(context)

    settings_path = context.workspace_dir / ".claude" / "settings.local.json"
    payload = json.loads(settings_path.read_text(encoding="utf-8"))
    hook_command = str(payload["hooks"]["PreToolUse"][0]["command"])

    assert install_output["active"] is True
    assert "from codex_plugin_scanner.cli import main" in hook_command
    assert "/repo/src" in hook_command
    assert "\"guard\", \"hook\"" not in hook_command
