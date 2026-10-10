"""Claude Code hook-health diagnostics must verify the hook entries, not only the launcher shim."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter


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


def test_reinstall_restores_active_status(tmp_path: Path) -> None:
    adapter, context, settings_path = _installed(tmp_path)
    settings_path.write_text("{}", encoding="utf-8")
    assert adapter.diagnostics(context)["setup_status"] == "broken"

    adapter.install(context)

    assert adapter.diagnostics(context)["setup_status"] == "active"
