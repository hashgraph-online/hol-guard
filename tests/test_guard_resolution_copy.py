"""Tests for T725-T731: approval resolution copy field and approval_resolved event."""

from __future__ import annotations

import json
import urllib.request

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _make_approval_request(
    *,
    request_id: str,
    harness: str = "codex",
    artifact_id: str = "codex:project:tool",
    workspace: str | None = None,
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=artifact_id,
        artifact_name="Test tool",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/tmp/config.toml",
        workspace=workspace,
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
    )


def _post_resolution(port: int, request_id: str, endpoint: str, token: str) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/requests/{request_id}/{endpoint}",
        data=json.dumps({"scope": "artifact"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


class TestApprovalResolvedEvent:
    """T725: approval_resolved event is emitted after resolution so SSE stream picks it up."""

    def test_approve_emits_approval_resolved_event(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(_make_approval_request(request_id="req-t725-allow"), "2026-01-01T00:00:00Z")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            _post_resolution(daemon.port, "req-t725-allow", "approve", daemon._server.auth_token)
            events = store.list_events(event_name="approval_resolved")
        finally:
            daemon.stop()

        assert len(events) == 1
        payload = events[0]["payload"]
        assert payload["request_id"] == "req-t725-allow"
        assert payload["action"] == "allow"

    def test_block_emits_approval_resolved_event(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(_make_approval_request(request_id="req-t725-block"), "2026-01-01T00:00:00Z")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            _post_resolution(daemon.port, "req-t725-block", "block", daemon._server.auth_token)
            events = store.list_events(event_name="approval_resolved")
        finally:
            daemon.stop()

        assert len(events) == 1
        payload = events[0]["payload"]
        assert payload["request_id"] == "req-t725-block"
        assert payload["action"] == "block"


class TestApprovalResolutionCopyTitle:
    """T726-T727: Resolution response includes copy field with action-specific titles."""

    def test_approve_response_copy_title(self, tmp_path) -> None:
        """T726: approve response has copy.title == 'Approved. Retry in chat.'"""
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            _make_approval_request(
                request_id="req-t726",
                harness="claude-code",
                artifact_id="claude-code:project:tool",
            ),
            "2026-01-01T00:00:00Z",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            _, payload = _post_resolution(daemon.port, "req-t726", "approve", daemon._server.auth_token)
        finally:
            daemon.stop()

        assert "copy" in payload, "Resolution response must include a 'copy' field"
        assert payload["copy"]["title"] == "Approved. Retry in chat."

    def test_block_response_copy_title(self, tmp_path) -> None:
        """T727: block response has copy.title == 'Blocked. Guard will remember this decision.'"""
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            _make_approval_request(
                request_id="req-t727",
                harness="claude-code",
                artifact_id="claude-code:project:tool",
            ),
            "2026-01-01T00:00:00Z",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            _, payload = _post_resolution(daemon.port, "req-t727", "block", daemon._server.auth_token)
        finally:
            daemon.stop()

        assert "copy" in payload, "Resolution response must include a 'copy' field"
        assert payload["copy"]["title"] == "Blocked. Guard will remember this decision."


class TestApprovalResolutionCopyPerHarness:
    """T728-T731: Per-harness retry hint in copy.body."""

    @pytest.mark.parametrize(
        "harness,expected_body",
        [
            (
                "codex",
                "Decision saved. HOL Guard could not find the Codex session to resume. "
                "Retry the same request in Codex; it should pass because this approval is now saved.",
            ),
            ("claude-code", "Return to Claude and retry"),
            ("opencode", "Return to OpenCode and retry"),
            ("copilot", "Return to Copilot and retry"),
            ("unknown-harness", "Return to your AI assistant and retry"),
        ],
    )
    def test_approve_copy_body_per_harness(self, tmp_path, harness: str, expected_body: str) -> None:
        """T728-T731: copy.body contains harness-specific retry hint after approval."""
        store = GuardStore(tmp_path / "guard-home")
        req_id = f"req-copy-{harness}"
        store.add_approval_request(
            _make_approval_request(request_id=req_id, harness=harness, artifact_id=f"{harness}:project:tool"),
            "2026-01-01T00:00:00Z",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        try:
            _, payload = _post_resolution(daemon.port, req_id, "approve", daemon._server.auth_token)
        finally:
            daemon.stop()

        assert payload["copy"]["body"] == expected_body
