"""Tests for local Guard settings and policy management APIs."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.config import load_guard_config, resolve_risk_action, update_guard_settings
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore


def _json_request(
    port: int,
    token: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


def _with_daemon(guard_home: Path) -> tuple[GuardStore, GuardDaemonServer]:
    store = GuardStore(guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    return store, daemon


def test_relaxed_security_level_persists_granular_risk_settings(tmp_path: Path) -> None:
    _store, daemon = _with_daemon(tmp_path / "guard-home")
    try:
        status, payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={
                "settings": {
                    "security_level": "relaxed",
                    "risk_actions": {
                        "local_secret_read": "require-reapproval",
                        "network_egress": "warn",
                        "destructive_shell": "block",
                        "mcp_dangerous_tool": "block",
                        "malicious_skill": "block",
                        "package_script": "require-reapproval",
                    },
                    "harness_risk_actions": {
                        "codex": {
                            "local_secret_read": "block",
                            "network_egress": "require-reapproval",
                        }
                    },
                }
            },
        )
    finally:
        daemon.stop()

    assert status == 200
    settings = payload["settings"]
    assert settings["security_level"] == "relaxed"
    assert settings["risk_action_overrides"]["destructive_shell"] == "block"
    assert settings["risk_action_overrides"]["mcp_dangerous_tool"] == "block"
    assert settings["risk_action_overrides"]["malicious_skill"] == "block"
    assert settings["risk_action_overrides"]["package_script"] == "require-reapproval"
    assert settings["harness_risk_actions"]["codex"]["local_secret_read"] == "block"


def test_settings_export_import_and_reset_round_trip(tmp_path: Path) -> None:
    _store, daemon = _with_daemon(tmp_path / "guard-home")
    try:
        update_status, _update_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"mode": "enforce", "security_level": "strict", "billing": True, "sync": True}},
        )
        export_status, export_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings/export",
        )
        reset_status, reset_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings/reset",
            method="POST",
            payload={"confirm": "reset-local-settings"},
        )
        import_status, import_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings/import",
            method="POST",
            payload=export_payload,
        )
    finally:
        daemon.stop()

    assert update_status == 200
    assert export_status == 200
    assert export_payload["schema_version"] == 1
    assert export_payload["settings"]["security_level"] == "strict"
    assert "privacy_warning" in export_payload
    assert reset_status == 200
    assert reset_payload["settings"]["security_level"] == "balanced"
    assert reset_payload["settings"]["sync"] is False
    assert import_status == 200
    assert import_payload["settings"]["mode"] == "enforce"
    assert import_payload["settings"]["security_level"] == "strict"
    assert import_payload["settings"]["billing"] is True
    assert import_payload["settings"]["sync"] is True


def test_cloud_sync_requires_paid_team_gate(tmp_path: Path) -> None:
    _store, daemon = _with_daemon(tmp_path / "guard-home")
    try:
        blocked_status, blocked_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"sync": True}},
        )
        allowed_status, allowed_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"billing": True, "sync": True}},
        )
    finally:
        daemon.stop()

    assert blocked_status == 400
    assert blocked_payload["message"] == "Cloud sync requires a paid team plan."
    assert allowed_status == 200
    assert allowed_payload["settings"]["billing"] is True
    assert allowed_payload["settings"]["sync"] is True


def test_risk_settings_drive_runtime_policy_resolution(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    update_guard_settings(
        guard_home,
        {
            "security_level": "custom",
            "risk_actions": {
                "local_secret_read": "require-reapproval",
                "network_egress": "block",
                "destructive_shell": "block",
                "mcp_dangerous_tool": "block",
                "malicious_skill": "require-reapproval",
                "package_script": "require-reapproval",
            },
            "harness_risk_actions": {
                "codex": {
                    "local_secret_read": "allow",
                    "network_egress": "require-reapproval",
                    "mcp_dangerous_tool": "block",
                }
            },
        },
    )
    config = load_guard_config(guard_home)

    assert resolve_risk_action(config, "local_secret_read", harness="codex") == "allow"
    assert resolve_risk_action(config, "network_egress", harness="codex") == "require-reapproval"
    assert resolve_risk_action(config, "network_egress", harness="gemini") == "block"
    assert resolve_risk_action(config, "destructive_shell", harness="codex") == "block"
    assert resolve_risk_action(config, "mcp_dangerous_tool", harness="codex") == "block"
    assert resolve_risk_action(config, "malicious_skill", harness="codex") == "require-reapproval"
    assert resolve_risk_action(config, "package_script", harness="codex") == "require-reapproval"


def test_per_app_clear_only_removes_matching_harness_decisions(tmp_path: Path) -> None:
    store, daemon = _with_daemon(tmp_path / "guard-home")
    store.upsert_policy(PolicyDecision(harness="codex", scope="harness", action="allow"), "2026-01-01T00:00:00Z")
    store.upsert_policy(PolicyDecision(harness="gemini", scope="harness", action="block"), "2026-01-01T00:00:00Z")
    try:
        status, payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/policy/clear",
            method="POST",
            payload={"harness": "codex", "scope": "harness"},
        )
        remaining = store.list_policy_decisions()
    finally:
        daemon.stop()

    assert status == 200
    assert payload["cleared"] == 1
    assert payload["harness"] == "codex"
    assert [item["harness"] for item in remaining] == ["gemini"]


def test_policy_api_rejects_global_allow_without_target(tmp_path: Path) -> None:
    _store, daemon = _with_daemon(tmp_path / "guard-home")
    try:
        status, payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/policy/decisions",
            method="POST",
            payload={"harness": "codex", "scope": "global", "action": "allow"},
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["saved"] is False
    assert payload["error"] == "broad_allow_requires_narrow_scope"
