"""Actual authenticated HTTP requests return finite source errors, not disconnects."""

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.mcp import policy_tools
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
from tests.guard_mcp_policy_test_support import env_flags as env_flags
from tests.guard_mcp_policy_test_support import store as store
from tests.test_guard_mcp_policy_daemon import TestDaemonMcpPolicyRequestSurface as Surface


@pytest.mark.parametrize("preparation", [True, False])
@pytest.mark.parametrize("kind", ["known", "unknown", "timeout"])
def test_native_source_failures_return_safe_http_json(
    store, env_flags, native_mcp_probe, monkeypatch, preparation, kind
):
    native_mcp_probe(store.guard_home)
    password = "synthetic-dashboard-source-password"
    update_settings(store.guard_home, {"enabled": True, "new_password": password, "confirm_password": password})
    request_id = Surface._stage_pending_request(store)
    expected = "native_business_source_installation_incoherent"
    error = NativePolicySnapshotError(expected)
    if kind == "unknown":
        error = NativePolicySnapshotError("private-source-content-and-path-marker")
        expected = "native_business_source_unavailable"
    elif kind == "timeout":
        error = TimeoutError("private-source-content-and-path-marker")
        expected = "policy_authority_busy"

    def refuse(*args, **kwargs):
        raise error

    target = "pending_policy_import_approval_binding" if preparation else "apply_pending_policy_request"
    monkeypatch.setattr(policy_tools, target, refuse)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = Surface._read_response(
            Surface._request(
                daemon.port,
                f"/v1/mcp-policy/requests/{request_id}/decision",
                payload={"action": "approve", "approval_gate": {"password": password, "use_cooldown": False}},
                token=Surface._dashboard_token_for(store),
                origin="http://127.0.0.1:5474",
            )
        )
    finally:
        daemon.stop()
    assert status == 503 and payload["resolved"] is False and payload["error"] == expected
    assert password not in str(payload) and "private-source-content-and-path-marker" not in str(payload)
