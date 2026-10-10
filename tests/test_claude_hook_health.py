"""Claude Code hook-health diagnostics must verify the hook entries, not only the launcher shim."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter


@pytest.fixture(autouse=True)
def _claude_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Hook health is only meaningful when the app binary resolves, as on a real install."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    claude = bin_dir / "claude"
    claude.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def _installed(tmp_path: Path) -> tuple[ClaudeCodeHarnessAdapter, HarnessContext, Path]:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")
    adapter = ClaudeCodeHarnessAdapter()
    adapter.install(context)
    return adapter, context, home / ".claude" / "settings.json"


def test_intact_hooks_report_active(tmp_path: Path) -> None:
    adapter, context, _settings = _installed(tmp_path)

    diagnostics = adapter.diagnostics(context)

    assert diagnostics["setup_status"] == "active"


def test_stripped_hooks_with_launcher_shim_report_broken(tmp_path: Path) -> None:
    adapter, context, settings_path = _installed(tmp_path)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["hooks"] = {}
    settings_path.write_text(json.dumps(settings), encoding="utf-8")

    diagnostics = adapter.diagnostics(context)

    assert diagnostics["setup_status"] == "broken"
    warnings = str(diagnostics["warnings"])
    assert "PreToolUse" in warnings
    assert "hol-guard repair" in warnings


def test_only_pretooluse_removed_is_broken_and_user_hooks_do_not_count(tmp_path: Path) -> None:
    adapter, context, settings_path = _installed(tmp_path)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["hooks"]["PreToolUse"] = [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/my-audit-hook"}]}
    ]
    settings_path.write_text(json.dumps(settings), encoding="utf-8")

    diagnostics = adapter.diagnostics(context)

    assert diagnostics["setup_status"] == "broken"
    assert "PermissionRequest" not in str(diagnostics["warnings"])


def test_narrowed_matcher_keeps_the_handler_but_reports_broken(tmp_path: Path) -> None:
    adapter, context, settings_path = _installed(tmp_path)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    for entry in settings["hooks"]["PreToolUse"]:
        if isinstance(entry, dict) and entry.get("matcher"):
            entry["matcher"] = "Read"
    settings_path.write_text(json.dumps(settings), encoding="utf-8")

    diagnostics = adapter.diagnostics(context)

    assert diagnostics["setup_status"] == "broken"
    assert "PreToolUse" in str(diagnostics["warnings"])


def test_reinstall_restores_active_status(tmp_path: Path) -> None:
    adapter, context, settings_path = _installed(tmp_path)
    settings_path.write_text("{}", encoding="utf-8")
    assert adapter.diagnostics(context)["setup_status"] == "broken"

    adapter.install(context)

    assert adapter.diagnostics(context)["setup_status"] == "active"
