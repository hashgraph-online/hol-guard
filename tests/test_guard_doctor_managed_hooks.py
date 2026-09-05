"""Doctor treats live Guard hooks as installed without claiming missing events."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=tmp_path / "guard-home")


def test_codex_doctor_keeps_live_bridge_hooks_when_interpreter_is_stale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.codex._command_available",
        lambda _command: True,
    )
    command = "python -I ./codex_daemon_hook_bridge.py '{}'"
    hook_entry = {
        "matcher": "*",
        "hooks": [
            {
                "type": "command",
                "command": command,
                "statusMessage": "HOL Guard checking tool action",
            }
        ],
    }
    config_path = context.home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("[features]\nhooks = true\n", encoding="utf-8")
    (context.home_dir / ".codex" / "hooks.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [hook_entry],
                    "PermissionRequest": [hook_entry],
                    "UserPromptSubmit": [hook_entry],
                    "PostToolUse": [hook_entry],
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.codex._verify_live_hook_manifest",
        lambda _context, **_kwargs: {
            "event_matches": {
                "PreToolUse": False,
                "PermissionRequest": False,
                "UserPromptSubmit": False,
                "PostToolUse": False,
            },
            "integrity_status": "tampered",
            "integrity_reason": "codex_hook_interpreter_path_mismatch",
        },
    )

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("codex").diagnostics(context)

    assert payload["native_hook_state"]["managed_hook_installed"] is True
    assert payload["native_hook_state"]["protection_active"] is False
    assert payload["native_hook_state"]["integrity_status"] != "valid"
    assert payload["setup_status"] == "broken"
    assert not any("managed Codex hooks are missing" in warning for warning in payload["warnings"])
    assert not any("Guard is not installed" in warning for warning in payload["warnings"])
    assert any("do not match this Guard CLI" in warning for warning in payload["warnings"])


def _write_cursor_hook_script(context: HarnessContext) -> Path:
    script_path = context.home_dir / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text("# managed cursor hook\n", encoding="utf-8")
    return script_path


def test_doctor_treats_managed_cursor_hooks_as_guard_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    hooks_path = context.home_dir / ".cursor" / "hooks.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"mcpServers": {"local": {"command": "node"}}}), encoding="utf-8")
    script_path = _write_cursor_hook_script(context)
    command = f"current-hol-guard __guard-cursor-hook {script_path} --cursor-hook-event beforeShellExecution"
    hooks_path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [{"command": command, "timeout": 45, "failClosed": True}],
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor.cursor_cli_command_available",
        lambda _context: True,
    )

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "active"
    assert any(artifact["artifact_type"] == "guard_hook" for artifact in payload["artifacts"])
    assert not any("Guard is not installed" in warning for warning in payload["warnings"])


def test_doctor_ignores_name_only_cursor_hook_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    hooks_path = context.home_dir / ".cursor" / "hooks.json"
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    hooks_path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [
                        {"command": "echo hol-guard-cursor-hook", "timeout": 45, "failClosed": True}
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor.cursor_cli_command_available",
        lambda _context: True,
    )

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert not any(artifact["artifact_type"] == "guard_hook" for artifact in payload["artifacts"])
    assert payload["setup_status"] != "active"


def test_doctor_ignores_disabled_or_missing_cursor_hook_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    hooks_path = context.home_dir / ".cursor" / "hooks.json"
    script_path = context.home_dir / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"
    command = f"current-hol-guard __guard-cursor-hook {script_path} --cursor-hook-event beforeShellExecution"
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    hooks_path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [{"command": command, "timeout": 45, "failClosed": True}],
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor.cursor_cli_command_available",
        lambda _context: True,
    )

    from codex_plugin_scanner.guard.adapters import get_adapter

    adapter = get_adapter("cursor")
    missing_payload = adapter.diagnostics(context)
    assert not any(artifact["artifact_type"] == "guard_hook" for artifact in missing_payload["artifacts"])
    assert missing_payload["setup_status"] != "active"

    _write_cursor_hook_script(context)
    hooks_path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [
                        {
                            "command": command,
                            "timeout": 45,
                            "failClosed": True,
                            "enabled": False,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    disabled_payload = adapter.diagnostics(context)
    assert not any(artifact["artifact_type"] == "guard_hook" for artifact in disabled_payload["artifacts"])
    assert disabled_payload["setup_status"] != "active"


def test_finalize_codex_doctor_warnings_drops_false_uninstalled_copy() -> None:
    from codex_plugin_scanner.guard.codex_hook_registration import finalize_codex_doctor_warnings

    warnings = finalize_codex_doctor_warnings(
        [
            "codex config was found, but Guard is not installed for this harness. "
            "Run `hol-guard install codex` to enable protection."
        ],
        {
            "config_present": True,
            "codex_hooks_enabled": True,
            "managed_hook_installed": True,
            "integrity_status": "stale",
        },
    )

    assert not any("Guard is not installed" in warning for warning in warnings)
    assert any("do not match this Guard CLI" in warning for warning in warnings)
