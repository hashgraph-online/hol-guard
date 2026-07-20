"""Non-Codex approval resolution must not trigger Codex resume."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.adapters.pi_hooks import pi_hook_response_from_guard
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.harness_resume import resume_harness_operation
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
    assert payload["harness_resume"]["status"] == "resumed"
    assert payload["harnessResume"] == payload["harness_resume"]
    assert "resume_token" not in str(payload["harness_resume"])
    assert payload["copy"]["body"] == "Return to Pi and retry"
    assert store.list_events(event_name="codex/thread_resume") == []
    operation = store.get_guard_operation("pi-operation")
    assert operation is not None
    assert operation["status"] == "resumed"
    assert store.list_events(event_name="harness/operation_resume")


def test_pi_denial_marks_waiting_operation_blocked_without_leaking_resume_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
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
        operation_id="pi-operation-block",
        session_id=str(session["session_id"]),
        harness="oh-my-pi",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=["req-pi-block"],
        resume_token="resume-token-secret",
        metadata={"session_id": "pi-session-id"},
        now="2026-05-08T10:00:00+00:00",
    )

    result = resume_harness_operation(
        store,
        request_id="req-pi-block",
        action="block",
        now="2026-05-08T10:01:00+00:00",
    )

    assert result == {
        "operationId": "pi-operation-block",
        "harness": "pi",
        "status": "blocked",
        "action": "block",
        "completedAt": "2026-05-08T10:01:00+00:00",
    }
    assert "resume-token-secret" not in str(result)
    operation = store.get_guard_operation("pi-operation-block")
    assert operation is not None
    assert operation["status"] == "blocked"


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


def test_pi_hook_response_denies_unsatisfied_review() -> None:
    payload = pi_hook_response_from_guard(
        policy_action="review",
        reason="Review in HOL Guard.",
    )

    assert payload == {
        "decision": "deny",
        "reason": "Review in HOL Guard.",
    }


class TestSafeResumeMetadata:
    """3 tests: union normalization, unsafe/blank dropping, merge precedence."""

    @staticmethod
    def _run(resume: dict[str, object]) -> dict[str, object]:
        from codex_plugin_scanner.guard.harness_resume import safe_resume_metadata

        return safe_resume_metadata(resume)

    def test_normalization_union_all_safe_fields(self) -> None:
        """All safe fields map to targets; resolutionAction/strategy/supported included."""
        data = {
            "operation_id": "op-1",
            "harness": "pi",
            "request_id": "req-1",
            "status": "done",
            "resolution_action": "approve",
            "reason": "safe",
            "message": "ok",
            "attempt_count": 3,
            "last_attempt_at": "2026-01-01T00:00:00Z",
            "sent_at": "2026-01-02T00:00:00Z",
            "completed_at": "2026-01-03T00:00:00Z",
            "strategy": "manual",
            "supported": True,
        }
        result = self._run(data)
        assert result == {
            "operationId": "op-1",
            "harness": "pi",
            "requestId": "req-1",
            "status": "done",
            "resolutionAction": "approve",
            "reason": "safe",
            "message": "ok",
            "attemptCount": 3,
            "lastAttemptAt": "2026-01-01T00:00:00Z",
            "sentAt": "2026-01-02T00:00:00Z",
            "completedAt": "2026-01-03T00:00:00Z",
            "strategy": "manual",
            "supported": True,
        }

    def test_unknown_and_blank_are_dropped(self) -> None:
        """Arbitrary unsafe keys dropped; blank strings excluded."""
        result = self._run(
            {
                "status": "done",
                "resolutionAction": "approve",
                "internal_token": "secret",
                "debug_stacktrace": "Traceback …",
                "confidence_score": 0.99,
                "message": "",
                "reason": "  ",
            }
        )
        assert result == {"status": "done", "resolutionAction": "approve"}

    def test_merge_precedence_is_last_in_tuple_wins(self) -> None:
        """Each snake/camel pair: later entry in the mapping tuple overwrites."""
        result = self._run(
            {
                "operation_id": "s",
                "operationId": "c",
                "request_id": "s",
                "requestId": "c",
                "attempt_count": "s",
                "attemptCount": "c",
                "last_attempt_at": "s",
                "lastAttemptAt": "c",
                "sent_at": "s",
                "sentAt": "c",
                "completed_at": "s",
                "completedAt": "c",
                "resolution_action": "s",
                "resolutionAction": "c",
            }
        )
        for key, expected in {
            "operationId": "s",
            "requestId": "s",
            "completedAt": "s",  # snake last in tuple
            "attemptCount": "c",
            "lastAttemptAt": "c",
            "sentAt": "c",
            "resolutionAction": "c",  # camel last
        }.items():
            assert result[key] == expected, f"{key} expected {expected!r}, got {result[key]!r}"
