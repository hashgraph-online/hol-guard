"""Doctor treats live Guard hooks as installed without claiming missing events."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests.codex_hook_state_support import fixed_hook_state
from tests.cursor_test_support import cursor_agent_on_path


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
        "codex_plugin_scanner.guard.codex_harness_client.codex_native_hook_state",
        fixed_hook_state(verified=False, reason="codex_hook_interpreter_path_mismatch"),
    )

    from codex_plugin_scanner.guard import native_harness_ops as harness_ops

    payload = harness_ops.diagnostics("codex", context)

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
    cursor_agent_on_path(monkeypatch, tmp_path, present=True)

    from codex_plugin_scanner.guard import native_harness_ops as harness_ops

    payload = harness_ops.diagnostics("cursor", context)

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
    cursor_agent_on_path(monkeypatch, tmp_path, present=True)

    from codex_plugin_scanner.guard import native_harness_ops as harness_ops

    payload = harness_ops.diagnostics("cursor", context)

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
    cursor_agent_on_path(monkeypatch, tmp_path, present=True)

    from codex_plugin_scanner.guard import native_harness_ops as harness_ops

    missing_payload = harness_ops.diagnostics("cursor", context)
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
    disabled_payload = harness_ops.diagnostics("cursor", context)
    assert not any(artifact["artifact_type"] == "guard_hook" for artifact in disabled_payload["artifacts"])
    assert disabled_payload["setup_status"] != "active"


def test_codex_doctor_result_drops_false_uninstalled_copy() -> None:
    from codex_plugin_scanner.guard.codex_hook_registration import codex_doctor_result

    warnings, status = codex_doctor_result(
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
        "partial",
    )

    assert not any("Guard is not installed" in warning for warning in warnings)
    assert any("do not match this Guard CLI" in warning for warning in warnings)
    assert status == "broken"
    installed = {"managed_hook_installed": True, "protection_active": True}
    assert codex_doctor_result([], installed, "partial") == ([], "active")
    assert codex_doctor_result(["codex command is not available"], installed, "partial")[1] == "broken"
    assert codex_doctor_result([], {"managed_hook_installed": False}, "active")[1] == "broken"


def test_codex_doctor_reports_leftover_hooks_for_an_uninstalled_codex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    command = "hol-guard guard hook codex"
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
    events = ("PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse")
    config_path = context.home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("[features]\nhooks = true\n", encoding="utf-8")
    (context.home_dir / ".codex" / "hooks.json").write_text(
        json.dumps({"hooks": {event: [hook_entry] for event in events}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.codex_harness_client.codex_native_hook_state",
        fixed_hook_state(verified=True),
    )

    from codex_plugin_scanner.guard import native_harness_ops as harness_ops

    payload = harness_ops.diagnostics("codex", context)

    # Codex is gone, so its managed hooks cannot run and cannot leave anything
    # unprotected either. That is leftover configuration, not a broken setup.
    assert payload["setup_status"] == "not_found"
    assert any("hol-guard uninstall codex" in warning for warning in payload["warnings"])
