"""Non-Codex approval resolution must not trigger Codex resume."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.adapters.pi_hooks import pi_hook_response_from_guard
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _post_json(port: int, token: str, path: str, payload: dict[str, object]) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def test_pi_approval_with_session_id_metadata_does_not_attempt_codex_resume(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = GuardApprovalRequest(
        request_id="req-pi",
        harness="pi",
        artifact_id="pi:project:read-source",
        artifact_name="Read credential-looking source",
        artifact_hash="hash-pi",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_response",),
        source_scope="project",
        config_path=str(tmp_path / ".pi" / "settings.json"),
        workspace=str(tmp_path),
        launch_target="Read src/lib/guard-notion-api.ts",
        action_envelope_json={"action_type": "file_read", "tool_name": "Read", "target_paths": ["src/file.ts"]},
        review_command="hol-guard approvals approve req-pi",
        approval_url="http://127.0.0.1/pending/req-pi",
    )
    store.add_approval_request(request, "2026-05-08T10:00:00+00:00")
    session = store.upsert_guard_session(
        session_id="pi-session",
        harness="pi",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="pi-hook",
        client_title="Pi hook",
        client_version="1.0.0",
        workspace=str(tmp_path),
        capabilities=["approval-resolution"],
        now="2026-05-08T10:00:00+00:00",
    )
    store.upsert_guard_operation(
        operation_id="pi-operation",
        session_id=str(session["session_id"]),
        harness="pi",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=["req-pi"],
        resume_token="resume-token",
        metadata={"session_id": "pi-session-id-that-must-not-be-codex"},
        now="2026-05-08T10:00:00+00:00",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        payload = _post_json(
            daemon.port,
            daemon._server.auth_token,
            "/v1/requests/req-pi/approve",
            {"scope": "artifact"},
        )
    finally:
        daemon.stop()

    assert payload["resolved"] is True
    assert "codex_resume" not in payload
    assert payload["copy"]["body"] == "Return to Pi and retry"
    assert store.list_events(event_name="codex/thread_resume") == []


def test_pi_hook_response_includes_resume_poll_metadata_for_pending_approval() -> None:
    payload = pi_hook_response_from_guard(
        policy_action="require-reapproval",
        reason="Open HOL Guard to approve this request.",
        approval_payload={
            "primary_approval_request_id": "req-pi",
            "primary_approval_url": "http://127.0.0.1:5474/requests/req-pi",
            "approval_center_url": "http://127.0.0.1:5474",
        },
    )

    assert payload == {
        "decision": "deny",
        "reason": "Open HOL Guard to approve this request.",
        "approval_request_id": "req-pi",
        "resume_poll_path": "/v1/requests/req-pi",
        "approval_url": "http://127.0.0.1:5474/requests/req-pi",
        "approval_center_url": "http://127.0.0.1:5474",
    }
