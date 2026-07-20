"""Tests for approval web recovery screens (T695-T699)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _guard_json_headers(auth_token: str | None = None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if auth_token is not None:
        headers["X-Guard-Token"] = auth_token
    return headers


def _add_pending_request(store: GuardStore, request_id: str = "req-test-001") -> None:
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness="codex",
            artifact_id="codex:project:test_tool",
            artifact_name="test_tool",
            artifact_hash="hash-test",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=(),
            source_scope="local",
            config_path="/tmp/config",
            review_command=f"hol-guard approvals approve {request_id}",
            approval_url=f"http://127.0.0.1:6174/#/approve/{request_id}",
        ),
        "2026-01-01T00:00:00+00:00",
    )


class TestApproveBlockRecoveryPayloads:
    """T695-T697: approve/block endpoints return structured recovery payloads on error."""

    def test_approve_unknown_request_returns_recovery_payload(self, tmp_path: Path) -> None:
        """T695: Approving an unknown request ID returns recovery copy, not a bare error."""
        store = GuardStore(tmp_path / "guard")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-nonexistent/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                pytest.fail("Expected HTTP error")
            except urllib.error.HTTPError as err:
                payload = json.loads(err.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload.get("resolved") is False
        recovery = payload.get("recovery")
        assert isinstance(recovery, dict), "Recovery payload must be a dict"
        assert recovery.get("code") == "request_unknown"
        assert "no longer waiting" in recovery.get("title", "").lower()

    def test_approve_already_resolved_request_returns_recovery_payload(self, tmp_path: Path) -> None:
        """T696: Approving an already-resolved request returns recovery copy with decision info."""
        store = GuardStore(tmp_path / "guard")
        _add_pending_request(store, "req-resolved-001")
        store.resolve_approval_request(
            "req-resolved-001",
            resolution_action="block",
            resolution_scope="artifact",
            reason=None,
            resolved_at="2026-01-01T01:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-resolved-001/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                pytest.fail("Expected HTTP error")
            except urllib.error.HTTPError as err:
                payload = json.loads(err.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload.get("resolved") is False
        recovery = payload.get("recovery")
        assert isinstance(recovery, dict), "Recovery payload must be a dict"
        assert recovery.get("code") == "request_resolved"
        assert recovery.get("queue_url") == f"http://127.0.0.1:{daemon.port}/#/inbox"
        title = recovery.get("title", "")
        assert "already" in title.lower() or "resolved" in title.lower()

    def test_approve_returns_harness_retry_hint_for_browser_resume(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="req-opencode-resume",
                harness="opencode",
                artifact_id="opencode:project:test_tool",
                artifact_name="test_tool",
                artifact_hash="hash-test",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=(),
                source_scope="local",
                config_path="/tmp/config",
                review_command="hol-guard approvals approve req-opencode-resume",
                approval_url="http://127.0.0.1:6174/#/approve/req-opencode-resume",
            ),
            "2026-01-01T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-opencode-resume/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["resolved"] is True
        assert payload["retry_hint"] == "Return to OpenCode and retry"
        assert payload["copy"] == {"title": "Approved. Retry in chat.", "body": "Return to OpenCode and retry"}

    def test_approve_with_wrong_token_returns_recovery_payload_not_bare_401(self, tmp_path: Path) -> None:
        """T697/T698: approve/block with wrong token returns structured recovery payload."""
        store = GuardStore(tmp_path / "guard")
        _add_pending_request(store, "req-auth-001")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-auth-001/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers=_guard_json_headers("wrong-token-xyz"),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                pytest.fail("Expected HTTP error")
            except urllib.error.HTTPError as err:
                assert err.code == 401
                payload = json.loads(err.read().decode("utf-8"))
        finally:
            daemon.stop()

        recovery = payload.get("recovery")
        assert isinstance(recovery, dict), "401 response must include a recovery payload"
        assert recovery.get("code") == "session_stale"
        assert recovery.get("reconnect_url") is not None

    def test_block_with_wrong_token_returns_recovery_payload(self, tmp_path: Path) -> None:
        """T698: block with wrong token returns structured recovery payload."""
        store = GuardStore(tmp_path / "guard")
        _add_pending_request(store, "req-auth-002")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/req-auth-002/block",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers=_guard_json_headers("bad-token"),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
                pytest.fail("Expected HTTP error")
            except urllib.error.HTTPError as err:
                assert err.code == 401
                payload = json.loads(err.read().decode("utf-8"))
        finally:
            daemon.stop()

        recovery = payload.get("recovery")
        assert isinstance(recovery, dict), "401 block response must include recovery payload"
        assert recovery.get("code") == "session_stale"

    def test_stale_approval_page_shows_recovery_copy_not_blank(self, tmp_path: Path) -> None:
        """T699: GET on stale/nonexistent approval request returns recovery copy instead of bare 404."""
        store = GuardStore(tmp_path / "guard")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(
                        f"http://127.0.0.1:{daemon.port}/v1/requests/req-stale-999",
                        headers=_guard_json_headers(daemon._server.auth_token),
                        method="GET",
                    ),
                    timeout=5,
                ):
                    pytest.fail("Expected HTTP error")
            except urllib.error.HTTPError as err:
                payload = json.loads(err.read().decode("utf-8"))
        finally:
            daemon.stop()

        recovery = payload.get("recovery")
        assert isinstance(recovery, dict), "404 GET on stale request must include recovery payload"
        assert recovery.get("code") in {"request_unknown", "not_found"}
        assert recovery.get("title") is not None
        assert recovery.get("queue_url") == f"http://127.0.0.1:{daemon.port}/#/inbox"
