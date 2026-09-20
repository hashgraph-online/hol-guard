"""Authenticated daemon resolution and request-bound scope."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import bridge as guard_bridge_module
from codex_plugin_scanner.guard.bridge import BridgeConfig, GuardBridge
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)
from tests.guard_approvals_support import (
    _guard_json_headers,
)


class TestGuardApprovals:
    def test_guard_daemon_rejects_missing_decision_fields(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-400",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-400",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-400",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/approvals/req-400/decision",
                data=json.dumps({"action": "allow"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for missing scope")
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "missing_required_fields"

    def test_guard_daemon_approve_route_derives_workspace_scope_from_request(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-workspace-http",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-400",
                policy_action="require-reapproval",
                recommended_scope="workspace",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-workspace-http",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-workspace-http/approve",
                data=json.dumps({"scope": "workspace"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                status = response.status
        finally:
            daemon.stop()

        assert status == 200
        assert payload["resolved"] is True
        assert payload["resolved_request"]["resolution_scope"] == "artifact"
        assert payload["scope_warning"] == "legacy_scope_narrowed_to_artifact"

    @pytest.mark.parametrize("action", ["approve", "block"])
    @pytest.mark.parametrize("scope", ["artifact", "workspace", "publisher", "harness", "global"])
    def test_guard_daemon_resolution_route_resolves_only_scope_covered_reviews(self, tmp_path, action, scope):
        store = GuardStore(tmp_path / "guard-home")
        workspace = tmp_path / "workspace"
        request_id = f"req-{action}-{scope}"
        artifact_id = f"codex:project:tool-action:{scope}"
        other_artifact_id = f"codex:project:tool-action:{scope}-other"
        store.add_approval_request(
            GuardApprovalRequest(
                request_id=request_id,
                harness="codex",
                artifact_id=artifact_id,
                artifact_name=f"{scope} action",
                artifact_type="tool_action_request",
                artifact_hash=f"hash-{action}-{scope}",
                publisher="codex-local",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(workspace / ".codex" / "config.toml"),
                workspace=str(workspace),
                review_command=f"hol-guard approvals {action} {request_id}",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        store.add_approval_request(
            GuardApprovalRequest(
                request_id=f"{request_id}-other",
                harness="codex",
                artifact_id=other_artifact_id,
                artifact_name=f"{scope} other action",
                artifact_type="tool_action_request",
                artifact_hash=f"hash-{action}-{scope}-other",
                publisher="codex-local",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(workspace / ".codex" / "config.toml"),
                workspace=str(workspace),
                review_command=f"hol-guard approvals {action} {request_id}-other",
                approval_url="http://127.0.0.1/pending-other",
            ),
            "2026-04-11T00:01:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request_payload = {"scope": scope, "reason": "real daemon route scope coverage"}
            if scope == "workspace":
                request_payload["workspace"] = str(workspace)
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/{request_id}/{action}",
                data=json.dumps(request_payload).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                status = response.status
        finally:
            daemon.stop()

        assert status == 200
        assert payload["resolved"] is True
        assert payload["resolved_request"]["request_id"] == request_id
        assert payload["resolved_request"]["resolution_action"] == ("allow" if action == "approve" else "block")
        expected_scope = scope if action == "block" or scope in {"artifact", "workspace"} else "artifact"
        assert payload["resolved_request"]["resolution_scope"] == expected_scope
        assert payload["applied_scope"] == expected_scope
        assert payload["resolved_request"]["approval_url"] == "http://127.0.0.1/pending"
        assert payload["resolved_request"]["review_command"] == f"hol-guard approvals {action} {request_id}"
        other_request_id = f"{request_id}-other"
        resolves_publisher_match = action == "block" and scope == "publisher"
        assert payload.get("resolved_scope_ids", []) == ([other_request_id] if resolves_publisher_match else [])
        assert payload["remaining_pending_count"] == (0 if resolves_publisher_match else 1)
        assert payload["next_selectable_request_id"] == (None if resolves_publisher_match else other_request_id)
        assert store.get_approval_request(other_request_id)["status"] == (
            "resolved" if resolves_publisher_match else "pending"
        )

    def test_guard_daemon_approve_route_requires_auth_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-auth-http",
                harness="codex",
                artifact_id="codex:project:workspace_skill",
                artifact_name="workspace_skill",
                artifact_hash="hash-auth",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("args",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-auth-http",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-auth-http/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers=_guard_json_headers(),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for missing auth token")
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"

    def test_guard_daemon_limits_request_resolution_to_local_dashboard_origin(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-hosted",
                harness="codex",
                artifact_id="codex:session:prompt:demo",
                artifact_name="prompt request",
                artifact_type="prompt_request",
                artifact_hash="hash-hosted",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("prompt_request",),
                source_scope="session",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-hosted",
                approval_url="http://127.0.0.1/pending/req-hosted",
            ),
            "2026-05-01T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            local_origin = f"http://127.0.0.1:{daemon.port}"
            blocked_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-hosted/approve",
                headers={"Origin": "https://hol.org"},
                method="OPTIONS",
            )
            with pytest.raises(urllib.error.HTTPError) as blocked_error:
                urllib.request.urlopen(blocked_request, timeout=5)

            options_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-hosted/approve",
                headers={"Origin": local_origin},
                method="OPTIONS",
            )
            with urllib.request.urlopen(options_request, timeout=5) as response:
                options_origin = response.headers.get("Access-Control-Allow-Origin")

            list_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests",
                headers={
                    "Origin": local_origin,
                    "X-Guard-Token": daemon._server.auth_token,
                },
            )
            with urllib.request.urlopen(list_request, timeout=5) as response:
                list_origin = response.headers.get("Access-Control-Allow-Origin")
                list_payload = json.loads(response.read().decode("utf-8"))

            approve_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-hosted/approve",
                data=json.dumps({"scope": "artifact", "reason": "approved from hosted dashboard"}).encode("utf-8"),
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": local_origin,
                },
                method="POST",
            )
            with urllib.request.urlopen(approve_request, timeout=5) as response:
                approve_origin = response.headers.get("Access-Control-Allow-Origin")
                approve_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert blocked_error.value.code == 403
        assert options_origin == local_origin
        assert list_origin == local_origin
        assert list_payload["items"][0]["request_id"] == "req-hosted"
        assert approve_origin == local_origin
        assert approve_payload["resolved"] is True
        assert store.list_approval_requests(limit=10) == []

    def test_guard_bridge_resolves_requests_against_guard_daemon_api(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        bridge = GuardBridge(
            config=BridgeConfig(guard_url="http://127.0.0.1:4455", dry_run=False),
            store=store,
        )
        token_path = store.guard_home / "daemon-auth-token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("bridge-token", encoding="utf-8")
        token_path.chmod(0o600)
        post_calls: list[tuple[str, dict[str, object], dict[str, str] | None]] = []

        def fake_post(url: str, json: dict[str, object], timeout: int, headers: dict[str, str] | None = None):
            post_calls.append((url, json, headers))
            assert timeout == 30
            return SimpleNamespace(status_code=200, json=lambda: {"resolved": True})

        monkeypatch.setattr(guard_bridge_module._DAEMON_SESSION, "post", fake_post)

        resolved = bridge._execute_resolution("approve", "req-bridge")

        assert resolved is True
        assert post_calls == [
            (
                "http://127.0.0.1:4455/v1/requests/req-bridge/approve",
                {
                    "scope": "artifact",
                    "reason": "resolved from Guard Bridge",
                },
                {"X-Guard-Token": "bridge-token"},
            )
        ]
