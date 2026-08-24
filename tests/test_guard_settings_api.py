"""Tests for local Guard settings and policy management APIs."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.config import load_guard_config, resolve_risk_action, update_guard_settings
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.models import GuardApprovalRequest, PolicyDecision
from codex_plugin_scanner.guard.runtime.runner import (
    _LIVE_REQUEST_PRIVACY_PROJECTION_MARKER,
    _ensure_live_request_privacy_projection,
    _persist_cloud_receipt_redaction_level,
    _reset_cloud_receipt_redaction_authority,
)
from codex_plugin_scanner.guard.store import GuardStore

_LIVE_OUTBOX_TABLE = "guard_review_outbox_events"


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


def _pending_request(request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:tool:{request_id}",
        artifact_name="bash",
        artifact_type="tool_action",
        artifact_hash="hash",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="once",
        changed_fields=frozenset({"command"}),
        source_scope="project",
        config_path="config.toml",
        workspace="workspace",
        launch_target="echo safe",
        transport="native",
        risk_summary="review",
        risk_signals=[],
        artifact_label=None,
        source_label=None,
        trigger_summary=None,
        why_now=None,
        launch_summary=None,
        risk_headline=None,
        action_envelope_json={"command": "echo safe"},
        decision_v2_json=None,
        fallback_cli_command=None,
        review_command=f"hol-guard approvals show {request_id}",
        approval_url=f"http://127.0.0.1/requests/{request_id}",
    )


def test_relaxing_receipt_privacy_requeues_pending_cloud_projection(tmp_path: Path) -> None:
    store, daemon = _with_daemon(tmp_path / "guard-home")
    request_id = store.add_approval_request(_pending_request("privacy-refresh"), "2026-08-03T00:00:00Z")
    with store._connect() as connection:
        connection.execute(f"delete from {_LIVE_OUTBOX_TABLE}")
    try:
        status, payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"receipt_redaction_level": "none"}},
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["settings"]["receipt_redaction_level"] == "none"
    with store._connect() as connection:
        rows = connection.execute(
            f"select local_request_id from {_LIVE_OUTBOX_TABLE} where local_request_id = ?",
            (request_id,),
        ).fetchall()
    assert [str(row["local_request_id"]) for row in rows] == [request_id]
    with store._connect() as connection:
        connection.execute(f"delete from {_LIVE_OUTBOX_TABLE}")
    _ensure_live_request_privacy_projection(store, level="none", synced_at="2026-08-03T00:02:00Z")
    with store._connect() as connection:
        assert connection.execute(f"select count(*) from {_LIVE_OUTBOX_TABLE}").fetchone()[0] == 0


def test_upgrade_republishes_pending_cloud_projection_once(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request_id = store.add_approval_request(_pending_request("privacy-upgrade"), "2026-08-03T00:00:00Z")
    with store._connect() as connection:
        connection.execute(f"delete from {_LIVE_OUTBOX_TABLE}")

    _ensure_live_request_privacy_projection(store, level="none", synced_at="2026-08-03T00:01:00Z")

    with store._connect() as connection:
        rows = connection.execute(
            f"select local_request_id from {_LIVE_OUTBOX_TABLE} where local_request_id = ?",
            (request_id,),
        ).fetchall()
        connection.execute(f"delete from {_LIVE_OUTBOX_TABLE}")
    assert [str(row["local_request_id"]) for row in rows] == [request_id]
    assert store.get_sync_payload(_LIVE_REQUEST_PRIVACY_PROJECTION_MARKER) == {
        "level": "none",
        "requeued": 1,
        "updated_at": "2026-08-03T00:01:00Z",
    }

    _ensure_live_request_privacy_projection(store, level="none", synced_at="2026-08-03T00:02:00Z")
    with store._connect() as connection:
        assert connection.execute(f"select count(*) from {_LIVE_OUTBOX_TABLE}").fetchone()[0] == 0


def test_cloud_privacy_transitions_advance_projection_marker(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _ = store.add_approval_request(_pending_request("cloud-privacy"), "2026-08-03T00:00:00Z")

    _persist_cloud_receipt_redaction_level(store, level="none", synced_at="2026-08-03T00:01:00Z")
    assert store.get_sync_payload(_LIVE_REQUEST_PRIVACY_PROJECTION_MARKER)["level"] == "none"
    with store._connect() as connection:
        connection.execute(f"delete from {_LIVE_OUTBOX_TABLE}")
    _ensure_live_request_privacy_projection(store, level="none", synced_at="2026-08-03T00:02:00Z")
    with store._connect() as connection:
        assert connection.execute(f"select count(*) from {_LIVE_OUTBOX_TABLE}").fetchone()[0] == 0

    _reset_cloud_receipt_redaction_authority(store, synced_at="2026-08-03T00:03:00Z")
    assert store.get_sync_payload(_LIVE_REQUEST_PRIVACY_PROJECTION_MARKER)["level"] == "full"


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


def test_settings_export_import_and_reset_round_trip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        daemon_server_module,
        "resolve_package_firewall_entitlement",
        lambda _store: {"allowed": True, "reason": "paid_entitlement_active", "tier": "team"},
    )
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


def test_cloud_sync_requires_trusted_paid_team_entitlement(tmp_path: Path, monkeypatch) -> None:
    _store, daemon = _with_daemon(tmp_path / "guard-home")
    try:
        blocked_status, blocked_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"sync": True}},
        )
        asserted_billing_status, asserted_billing_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"billing": True, "sync": True}},
        )
        monkeypatch.setattr(
            daemon_server_module,
            "resolve_package_firewall_entitlement",
            lambda _store: {"allowed": True, "reason": "paid_entitlement_active", "tier": "team"},
        )
        allowed_status, allowed_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"billing": False, "sync": True}},
        )
        monkeypatch.setattr(
            daemon_server_module,
            "resolve_package_firewall_entitlement",
            lambda _store: {"allowed": False, "reason": "paid_guard_cloud_required", "tier": "free"},
        )
        _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"sync": False}},
        )
        expired_status, expired_payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"mode": "enforce", "sync": True}},
        )
    finally:
        daemon.stop()

    assert blocked_status == 400
    assert blocked_payload["message"] == "Cloud sync requires a paid team plan."
    assert asserted_billing_status == 400
    assert asserted_billing_payload["message"] == "Cloud sync requires a paid team plan."
    assert allowed_status == 200
    assert allowed_payload["settings"]["billing"] is False
    assert allowed_payload["settings"]["sync"] is True
    assert expired_status == 400
    assert expired_payload["message"] == "Cloud sync requires a paid team plan."


def test_existing_cloud_sync_does_not_block_protection_posture_change(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    update_guard_settings(
        guard_home,
        {"sync": True, "protection_posture": "watch"},
        cloud_sync_entitled=True,
    )
    updated = update_guard_settings(
        guard_home,
        {"protection_posture": "protected"},
        cloud_sync_entitled=False,
    )

    assert updated.protection_posture == "protected"
    assert updated.sync is True


def test_watch_to_protected_api_ignores_existing_sync_without_entitlement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    update_guard_settings(
        guard_home,
        {"sync": True, "protection_posture": "watch"},
        cloud_sync_entitled=True,
    )
    _store, daemon = _with_daemon(guard_home)
    monkeypatch.setattr(
        daemon_server_module,
        "resolve_package_firewall_entitlement",
        lambda _store: {"allowed": False, "reason": "paid_guard_cloud_required", "tier": "free"},
    )
    try:
        status, payload = _json_request(
            daemon.port,
            daemon._server.auth_token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"protection_posture": "protected"}},
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["settings"]["protection_posture"] == "protected"
    assert payload["settings"]["sync"] is True


def test_managed_policy_sync_does_not_persist_local_sync_without_entitlement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from codex_plugin_scanner.guard import config as config_module
    from codex_plugin_scanner.guard.mdm.contracts import (
        MDM_POLICY_SCHEMA_VERSION,
        ManagedPolicy,
        ManagedPolicyState,
        ManagedUpdatePolicy,
    )

    guard_home = tmp_path / "guard-home"
    policy = ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings={"sync": True},
        locked_settings=frozenset(),
        update=ManagedUpdatePolicy(owner="mdm", allow_downgrade=False),
        content_hash="managed-sync",
    )
    monkeypatch.setattr(
        config_module,
        "load_managed_policy",
        lambda: ManagedPolicyState(status="active", source="test", policy=policy),
    )
    with pytest.raises(ValueError, match="Cloud sync requires a paid team plan"):
        update_guard_settings(
            guard_home,
            {"sync": True},
            cloud_sync_entitled=False,
        )
    config_path = guard_home / "config.toml"
    persisted = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    assert "sync = true" not in persisted.lower()


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
