"""Daemon HTTP surfaces for MCP policy creation requests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.mcp.policy_tools import decline_pending_policy_request, execute_create_policy
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_mcp_policy_test_support import _BASIC_POLICY_YAML, _assert_no_policy_response_leaks, _digest
from tests.guard_mcp_policy_test_support import env_flags as env_flags
from tests.guard_mcp_policy_test_support import opaque_request_id as opaque_request_id
from tests.guard_mcp_policy_test_support import store as store


class TestDaemonMcpPolicyRequestSurface:
    """Daemon HTTP surfaces for MCP policy creation requests.

    VPC044-050: the daemon request page and POST decision endpoint enforce
    origin/CSRF, return honest plan display, handle terminal/expired/declined
    states stably, and never persist credentials.  These tests exercise the
    protocol and daemon surfaces without real accounts or provider credentials.
    """

    @staticmethod
    def _dashboard_token(auth_token: str) -> str:
        from codex_plugin_scanner.guard.local_dashboard_session import (
            LOCAL_DASHBOARD_SESSION_AUDIENCE,
        )

        payload_json = json.dumps(
            {
                "aud": LOCAL_DASHBOARD_SESSION_AUDIENCE,
                "version": "guard-local-daemon-session.v1",
                "expires_at": datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat(),
                "surface": "approval-center",
            },
            separators=(",", ":"),
        )
        payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
        signature = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
        encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        return f"gld1.{payload}.{encoded_signature}"

    @staticmethod
    def _dashboard_token_for(store: GuardStore) -> str:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        return TestDaemonMcpPolicyRequestSurface._dashboard_token(auth_token)

    @staticmethod
    def _request(
        port: int,
        path: str,
        *,
        method: str = "POST",
        payload: dict[str, object] | None = None,
        token: str | None = None,
        origin: str | None = None,
    ) -> Any:
        data = json.dumps(payload or {}).encode("utf-8") if method != "GET" else None
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if origin is not None:
            headers["Origin"] = origin
        if token is not None:
            if token.startswith("gld1."):
                headers["X-Guard-Dashboard-Session"] = token
            else:
                headers["Authorization"] = f"Bearer {token}"
        return urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=data,
            headers=headers,
            method=method,
        )

    @staticmethod
    def _read_response(request: Any) -> tuple[int, dict[str, object]]:
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode("utf-8"))

    @staticmethod
    def _stage_pending_request(store: GuardStore, *, idempotency_key: str = "daemon-surface-fixture") -> str:
        candidate_digest = _digest(_BASIC_POLICY_YAML)
        result = json.loads(
            execute_create_policy(
                store,
                {
                    "policyYaml": _BASIC_POLICY_YAML,
                    "mode": "merge",
                    "candidateDigest": candidate_digest,
                    "expectedCurrentDigest": None,
                    "idempotencyKey": idempotency_key,
                },
            )
        )
        assert result["status"] == "pending"
        return str(result["requestId"])

    @pytest.mark.parametrize("alter_grant", [False, True])
    def test_approve_issues_document_bound_native_grant(
        self,
        store: GuardStore,
        env_flags: None,
        native_hook_force: Path,
        native_mcp_probe,
        monkeypatch: pytest.MonkeyPatch,
        alter_grant: bool,
    ) -> None:
        from codex_plugin_scanner.guard.approval_gate import update_settings
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        native_mcp_probe(store.guard_home)
        from codex_plugin_scanner.guard import approval_gate
        from codex_plugin_scanner.guard.daemon import mcp_policy_decisions as server

        native_gate = approval_gate._approval_gate_native

        def require_native_result(method, *args, **kwargs):
            result = native_gate(method, *args, **kwargs)
            if method == "require_high_risk":
                from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code

                assert result is not None, native_resident_client_failure_code()
            return result

        monkeypatch.setattr(approval_gate, "_approval_gate_native", require_native_result)
        if alter_grant:
            from dataclasses import replace

            issue_grant = server.require_high_risk

            def issue_altered_grant(*args, **kwargs):
                grant = issue_grant(*args, **kwargs)
                assert grant is not None
                return replace(grant, subject="different-document")

            monkeypatch.setattr(server, "require_high_risk", issue_altered_grant)
        password = "synthetic-policy-daemon-approval"
        update_settings(
            store.guard_home,
            {
                "enabled": True,
                "new_password": password,
                "confirm_password": password,
                "cooldown_seconds": 0,
            },
        )
        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={
                        "action": "approve",
                        "approval_gate": {
                            "password": password,
                            "use_cooldown": False,
                        },
                    },
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()
        if alter_grant:
            assert status == 403, payload
            assert payload["error"] == "approval_gate_required"
            assert store.list_policy_decisions() == []
            from codex_plugin_scanner.guard.mcp.policy_store import MCPolicyRequestRepository

            pending = MCPolicyRequestRepository(store).get_request(request_id)
            assert pending is not None and pending.status == "failed"
            assert pending.failure_code == "policy_write_failed"
        else:
            assert status == 200, payload
            assert payload["resolved"] is True
            assert len(store.list_policy_decisions()) == 1
        _assert_no_policy_response_leaks(
            {"requestId": request_id, **payload}, request_id=request_id, sensitive_values=(token, password)
        )

    def test_get_returns_vpc045_fields(self, store: GuardStore, env_flags: None, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        assert payload["requestId"] == request_id
        assert payload["status"] == "pending"
        assert payload["mode"] == "merge"
        assert "candidateDigest" in payload
        assert "expectedCurrentDigest" in payload
        assert "expectedPolicyGeneration" in payload
        assert "createdAt" in payload
        assert "expiresAt" in payload
        assert payload["isTerminal"] is False
        assert payload["isExpired"] is False
        assert payload["activeEnforcementWarning"] is True
        assert "semanticDiff" in payload
        assert "writePlan" in payload
        diff = payload["semanticDiff"]
        assert "additionCount" in diff
        assert "replacementCount" in diff
        assert "removalCount" in diff

    def test_get_returns_404_for_unknown_request(self, store: GuardStore, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    "/v1/mcp-policy/requests/nonexistent-request-id",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 404
        assert payload["error"] == "not_found"

    def test_get_requires_auth_token(self, store: GuardStore, env_flags: None, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            status, _payload = self._read_response(
                self._request(
                    daemon.port,
                    "/v1/mcp-policy/requests/some-id",
                    method="GET",
                    token=None,
                )
            )
        finally:
            daemon.stop()

        assert status == 401

    def test_decision_post_rejects_non_loopback_origin(
        self, store: GuardStore, env_flags: None, tmp_path: Path
    ) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=token,
                    origin="https://evil.example",
                )
            )
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"

    def test_decision_post_rejects_missing_token(self, store: GuardStore, env_flags: None, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            status, _payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=None,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 401

    def test_decision_post_rejects_invalid_action(self, store: GuardStore, env_flags: None, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "maybe"},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "missing_required_fields"

    @pytest.mark.parametrize("action", ["approve", "decline"])
    @pytest.mark.parametrize("cleaned", [False, True])
    @pytest.mark.parametrize("terminal_status", ["applied", "declined", "expired", "failed"])
    def test_decision_is_stable_for_terminal_request(
        self, store: GuardStore, env_flags: None, tmp_path: Path, action: str, cleaned: bool, terminal_status: str
    ) -> None:
        """VPC047: repeated decisions retain terminal state after payload cleanup."""
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        decline_pending_policy_request(store, request_id)
        with store._connect() as connection:
            connection.execute(
                "update mcp_policy_requests set status = ? where request_id = ?", (terminal_status, request_id)
            )
            connection.commit()
        if cleaned:
            from codex_plugin_scanner.guard.mcp.policy_store import MCPolicyRequestRepository

            old_time = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
            with store._connect() as connection:
                connection.execute(
                    "update mcp_policy_requests set resolved_at = ? where request_id = ?", (old_time, request_id)
                )
                connection.commit()
            repo = MCPolicyRequestRepository(store)
            repo.purge_expired_and_old()
            retained = repo.get_request(request_id)
            assert retained is not None and retained.canonical_policy_yaml == ""

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": action},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        assert payload["resolved"] is True
        assert payload["status"] == terminal_status
        assert "resolvedAt" in payload

    def test_decline_then_get_shows_terminal_state(self, store: GuardStore, env_flags: None, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        assert payload["status"] == "declined"
        assert payload["isTerminal"] is True
        assert payload["isExpired"] is False
        assert payload["activeEnforcementWarning"] is False
        assert payload["resolvedAt"] is not None

    def test_decision_response_contains_no_credentials(
        self, store: GuardStore, env_flags: None, tmp_path: Path, opaque_request_id: str | None
    ) -> None:
        """VPC046: the decision endpoint never echoes approval-gate material."""
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        if opaque_request_id is not None:
            assert request_id == opaque_request_id
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}/decision",
                    method="POST",
                    payload={"action": "decline"},
                    token=token,
                    origin="http://127.0.0.1:5474",
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        _assert_no_policy_response_leaks(payload, request_id=request_id, sensitive_values=(token,))

    def test_get_response_contains_no_policy_yaml_or_credentials(
        self, store: GuardStore, env_flags: None, tmp_path: Path, opaque_request_id: str | None
    ) -> None:
        """VPC045/046: GET never returns canonical YAML, plan JSON, or credentials."""
        from codex_plugin_scanner.guard.daemon import GuardDaemonServer

        request_id = self._stage_pending_request(store)
        if opaque_request_id is not None:
            assert request_id == opaque_request_id
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            token = self._dashboard_token_for(store)
            status, payload = self._read_response(
                self._request(
                    daemon.port,
                    f"/v1/mcp-policy/requests/{request_id}",
                    method="GET",
                    token=token,
                )
            )
        finally:
            daemon.stop()

        assert status == 200
        _assert_no_policy_response_leaks(payload, request_id=request_id, sensitive_values=(token,))
