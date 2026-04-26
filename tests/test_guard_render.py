from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.cli.render import emit_guard_payload


def _normalize_render_output(output: str) -> str:
    return " ".join(output.split())


def test_guard_connect_render_clarifies_paid_plan_pending_state(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "first_sync_pending",
            "reason": "Guard Cloud sync requires a paid Guard plan",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "Browser paired" in output
    assert "Connection" in output
    assert "This device is protected locally" in output
    assert "Upgrade to sync this device to Guard Cloud" in output


def test_guard_render_redacts_sensitive_values_before_rich_renderer(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_renderer(_console, payload: dict[str, object]) -> None:
        captured["payload"] = payload

    monkeypatch.setitem(render._RENDERERS, "status", fake_renderer)
    monkeypatch.setattr(render, "_RICH_AVAILABLE", True)

    emit_guard_payload(
        "status",
        {
            "api_key": "secret value",
            "launch_summary": 'api_key="secret value" token=supersecret',
        },
        False,
    )

    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["api_key"] == "*****"
    assert payload["launch_summary"] == "api_key=***** token=*****"


def test_guard_settings_json_omits_billing_flag(capsys) -> None:
    emit_guard_payload(
        "settings",
        {
            "generated_at": "2026-04-17T00:00:00Z",
            "guard_home": "/tmp/guard-home",
            "config_path": "/tmp/guard-home/config.toml",
            "settings": {
                "mode": "prompt",
                "security_level": "balanced",
                "default_action": "warn",
                "unknown_publisher_action": "review",
                "changed_hash_action": "require-reapproval",
                "new_network_domain_action": "warn",
                "subprocess_action": "warn",
                "risk_actions": {"destructive_shell": "require-reapproval"},
                "risk_action_overrides": {},
                "harness_risk_actions": {},
                "approval_wait_timeout_seconds": 120,
                "approval_surface_policy": "auto-open-once",
                "telemetry": False,
                "sync": True,
                "billing": True,
            },
        },
        True,
    )

    output = json.loads(capsys.readouterr().out)
    assert output["settings"]["sync"] is True
    assert "billing" not in output["settings"]


def test_guard_connect_render_defaults_sync_not_available_to_upgrade_guidance(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "sync_not_available",
            "reason": "Sync is not available right now.",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "This device is protected locally" in output
    assert "Upgrade to sync this device to Guard Cloud" in output
    assert "First Guard Cloud proof is on the way" not in output


def test_guard_connect_render_tolerates_non_numeric_sync_counts(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "first_sync_succeeded",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "sync": {
                "receipts_stored": "pending",
                "inventory_tracked": "unknown",
            },
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "Receipts stored" in output
    assert "Inventory tracked" in output
    assert "0" in output


def test_guard_connect_render_tolerates_non_finite_sync_counts(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": True,
            "browser_opened": True,
            "status": "connected",
            "milestone": "first_sync_succeeded",
            "completed_at": "2026-04-17T00:00:00Z",
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "sync": {
                "receipts_stored": float("nan"),
                "inventory_tracked": float("inf"),
            },
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "Receipts stored" in output
    assert "Inventory tracked" in output
    assert "0" in output


def test_guard_connect_render_clarifies_browser_approval_wait(capsys) -> None:
    emit_guard_payload(
        "connect",
        {
            "connected": False,
            "browser_opened": True,
            "status": "waiting",
            "milestone": "waiting_for_browser",
            "completed_at": None,
            "connect_url": "https://hol.org/guard/connect",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "Browser paired" in output
    assert "Browser approval pending" in output
    assert "Waiting for browser approval" in output


def test_guard_status_render_rewrites_internal_next_action_labels(capsys) -> None:
    emit_guard_payload(
        "status",
        {
            "managed_harnesses": 1,
            "receipt_count": 3,
            "pending_approvals": 1,
            "sync_configured": False,
            "cloud_state": "local_only",
            "cloud_state_label": "Local only",
            "cloud_state_detail": "Guard is protecting this machine locally.",
            "dashboard_url": "https://hol.org/guard",
            "connect_url": "https://hol.org/guard/connect",
            "advisory_count": 0,
            "harnesses": [
                {
                    "harness": "codex",
                    "managed": False,
                    "artifact_count": 2,
                    "review_count": 0,
                    "next_action": "install",
                },
                {
                    "harness": "claude-code",
                    "managed": True,
                    "artifact_count": 4,
                    "review_count": 2,
                    "next_action": "review",
                },
                {
                    "harness": "copilot",
                    "managed": True,
                    "artifact_count": 1,
                    "review_count": 0,
                    "next_action": "run",
                },
                {
                    "harness": "cursor",
                    "managed": False,
                    "artifact_count": 0,
                    "review_count": 0,
                    "next_action": "install-harness",
                },
            ],
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "Recommended action" in output
    assert "Install Guard" in output
    assert "Review 2 changes" in output
    assert "Run through Guard" in output
    assert "Install harness first" in output


def test_guard_bootstrap_render_rewrites_skip_reason_labels(capsys) -> None:
    emit_guard_payload(
        "bootstrap",
        {
            "recommended_harness": "codex",
            "approval_center_url": "http://127.0.0.1:4781",
            "approval_center_reachable": True,
            "bootstrap_install": {
                "installed": False,
                "harness": "codex",
                "reason": "skipped_by_flag",
            },
            "shell_alias": {
                "snippet": "alias guardp='hol-guard protect'",
            },
            "next_steps": [],
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Install skipped for now" in output
    assert "skipped_by_flag" not in output


def test_guard_bootstrap_render_rewrites_missing_harness_reason(capsys) -> None:
    emit_guard_payload(
        "bootstrap",
        {
            "recommended_harness": None,
            "approval_center_url": "http://127.0.0.1:4781",
            "approval_center_reachable": True,
            "bootstrap_install": {
                "installed": False,
                "reason": "no_harness_detected",
            },
            "next_steps": [],
        },
        False,
    )

    output = capsys.readouterr().out
    assert "No supported harness detected yet" in output
    assert "no_harness_detected" not in output


def test_guard_install_render_surfaces_proxy_details_and_skipped_servers(capsys) -> None:
    emit_guard_payload(
        "install",
        {
            "managed_install": {
                "harness": "codex",
                "active": True,
                "workspace": "/repo",
                "manifest": {
                    "mode": "codex-mcp-proxy",
                    "config_path": "/repo/.codex/config.toml",
                    "managed_servers": ["global_tools", "workspace_skill"],
                    "skipped_servers": ["existing_global"],
                    "notes": ["Guard rewrote the workspace config with proxy entries."],
                },
            },
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Protection" in output
    assert "Installed" in output
    assert "Mode" in output
    assert "Codex MCP proxy" in output
    assert "Managed servers" in output
    assert "2" in output
    assert "Skipped servers" in output
    assert "existing_global" in output


def test_guard_sync_render_surfaces_policy_and_alert_details(capsys) -> None:
    emit_guard_payload(
        "sync",
        {
            "synced_at": "2026-04-20T19:00:00Z",
            "receipts": 3,
            "inventory_tracked": 4,
            "receipts_stored": 2,
            "advisories_stored": 1,
            "exceptions_stored": 2,
            "remote_policies_stored": 5,
            "pain_signals_uploaded": 1,
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Remote policies" in output
    assert "Exceptions stored" in output
    assert "Pain signals uploaded" in output
    assert "5" in output
    assert "2" in output
    assert "1" in output


def test_guard_uninstall_render_adds_removal_note_without_manifest(capsys) -> None:
    emit_guard_payload(
        "uninstall",
        {
            "managed_install": {
                "harness": "codex",
                "active": False,
                "workspace": "/repo",
            },
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Removed" in output
    assert "Guard removed the managed wrapper configuration for this harness." in output


def test_guard_uninstall_render_adds_removal_note_without_manifest_notes(capsys) -> None:
    emit_guard_payload(
        "uninstall",
        {
            "managed_install": {
                "harness": "codex",
                "active": False,
                "workspace": "/repo",
                "manifest": {
                    "mode": "codex-mcp-proxy",
                },
            },
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Removed" in output
    assert "Guard removed the managed wrapper configuration for this harness." in output


def test_guard_install_render_skips_notes_when_manifest_is_missing_and_active(capsys) -> None:
    emit_guard_payload(
        "install",
        {
            "managed_install": {
                "harness": "codex",
                "active": True,
                "workspace": "/repo",
            },
        },
        False,
    )

    output = capsys.readouterr().out
    assert "Installed" in output
    assert "Guard removed the managed wrapper configuration for this harness." not in output
    assert "Notes" not in output


def test_guard_batch_install_render_surfaces_auto_detected_summary(capsys) -> None:
    emit_guard_payload(
        "install",
        {
            "auto_detected": True,
            "managed_installs": [
                {
                    "harness": "codex",
                    "active": True,
                    "workspace": "/repo",
                    "manifest": {
                        "mode": "codex-mcp-proxy",
                        "config_path": "/repo/.codex/config.toml",
                        "managed_servers": ["global_tools", "workspace_skill"],
                    },
                },
                {
                    "harness": "claude-code",
                    "active": False,
                    "workspace": "/repo",
                    "manifest": {
                        "config_path": "/repo/.claude/settings.json",
                    },
                },
            ],
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "Auto-detected" in output
    assert "Protection" in output
    assert "Mode" in output
    assert "Installed" in output
    assert "Removed" in output
    assert "Codex" in output
    assert "MCP" in output
    assert "proxy" in output
    assert "Servers" in output


def test_guard_batch_install_render_shortens_home_relative_config_paths(capsys) -> None:
    emit_guard_payload(
        "install",
        {
            "managed_installs": [
                {
                    "harness": "codex",
                    "active": True,
                    "workspace": "/repo",
                    "manifest": {
                        "mode": "codex-mcp-proxy",
                        "config_path": str(Path.home() / ".codex" / "config.toml"),
                        "managed_servers": ["global_tools"],
                    },
                }
            ],
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out).replace(" ", "")
    assert "~/.codex/config.toml" in output


def test_guard_batch_install_render_collects_per_harness_notes(capsys) -> None:
    emit_guard_payload(
        "install",
        {
            "managed_installs": [
                {
                    "harness": "codex",
                    "active": True,
                    "workspace": "/repo",
                    "manifest": {
                        "config_path": "/repo/.codex/config.toml",
                        "skipped_servers": ["existing_global"],
                    },
                },
                {
                    "harness": "claude-code",
                    "active": False,
                    "workspace": "/repo",
                },
            ],
        },
        False,
    )

    output = _normalize_render_output(capsys.readouterr().out)
    assert "Notes" in output
    assert "codex: Skipped existing server entries: existing_global" in output
    assert "claude-code: Guard removed the managed wrapper configuration" in output


def test_emit_guard_payload_uses_adaptive_console_width(monkeypatch) -> None:
    captured_kwargs: dict[str, object] = {}

    class FakeConsole:
        def __init__(self, **kwargs: object) -> None:
            captured_kwargs.update(kwargs)

    def _fake_renderer(console: object, payload: dict[str, object]) -> None:
        return None

    monkeypatch.setattr(render, "_RICH_AVAILABLE", True)
    monkeypatch.setattr(render, "Console", FakeConsole)
    monkeypatch.setitem(render._RENDERERS, "status", _fake_renderer)

    emit_guard_payload("status", {"harnesses": []}, False)

    assert captured_kwargs["file"] is not None
    assert captured_kwargs["soft_wrap"] is True
    assert "width" not in captured_kwargs


def test_emit_guard_payload_redacts_sensitive_json_fields(capsys) -> None:
    emit_guard_payload(
        "status",
        {
            "token": "secret-token",
            "authorization": "Bearer super-secret",
            "nested": {
                "api_key": "abc123",
                "message": "Authorization: Bearer top-secret",
            },
        },
        True,
    )

    output = capsys.readouterr().out
    assert "secret-token" not in output
    assert "super-secret" not in output
    assert "top-secret" not in output
    assert '"token": "*****"' in output
    assert '"api_key": "*****"' in output


def test_emit_guard_payload_preserves_policy_literals_for_risk_action_keys(capsys) -> None:
    emit_guard_payload(
        "status",
        {
            "settings": {
                "harness_risk_actions": {
                    "codex": {
                        "local_secret_read": "allow",
                    }
                }
            }
        },
        True,
    )

    output = capsys.readouterr().out
    assert '"local_secret_read": "allow"' in output
