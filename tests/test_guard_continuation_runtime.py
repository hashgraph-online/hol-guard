"""Durable continuation execution across proven and fallback harness capabilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.continuation_runtime import continue_request_after_application
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-08-24T12:00:00+00:00"


def _seed_request(
    store: GuardStore, *, harness: str, request_id: str, metadata: dict[str, object]
) -> dict[str, object]:
    request = GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=f"{harness}:project:read-source",
        artifact_name="Read source",
        artifact_hash=f"hash-{request_id}",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_response",),
        source_scope="project",
        config_path=f"/tmp/{harness}.json",
        workspace="/tmp/guard-continuation-runtime",
        launch_target="Read source",
        action_envelope_json={"action_type": "file_read", "tool_name": "Read", "target_paths": ["src/file.py"]},
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1/pending/{request_id}",
    )
    store.add_approval_request(request, NOW)
    session = store.upsert_guard_session(
        session_id=f"session-{request_id}",
        harness=harness,
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name=f"{harness}-hook",
        client_title=f"{harness} hook",
        client_version="1.0.0",
        workspace="/tmp/guard-continuation-runtime",
        capabilities=["approval-resolution"],
        now=NOW,
    )
    store.upsert_guard_operation(
        operation_id=f"operation-{request_id}",
        session_id=str(session["session_id"]),
        harness=harness,
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request_id],
        resume_token="resume-token-not-in-response",
        metadata=metadata,
        now=NOW,
    )
    result = store.get_approval_request(request_id)
    assert result is not None
    return result


@pytest.mark.parametrize("harness", ["pi", "omp", "grok", "openclaw", "hermes"])
def test_retry_only_harnesses_persist_a_manual_retry_once(tmp_path: Path, harness: str) -> None:
    store = GuardStore(tmp_path / harness)
    request = _seed_request(store, harness=harness, request_id=f"request-{harness}", metadata={"session_id": "opaque"})

    first = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)
    second = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)

    assert first["continuationStatus"] == "manual_retry_required"
    assert first["localManualRetryNotification"] is True
    assert first["harnessResume"] == first["harness_resume"]
    assert "resume-token-not-in-response" not in str(first)
    assert second["continuationEvidenceId"] == first["continuationEvidenceId"]
    assert "localManualRetryNotification" not in second
    resume = store.get_request_resume(f"request-{harness}")
    assert resume is not None
    assert resume["continuation_contract_version"] == "guard.harness-continuation.v1"
    assert resume["continuation_offer_hash"]
    assert resume["continuation_evidence"][0]["evidenceId"] == first["continuationEvidenceId"]
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1
    assert len(store.list_events(event_name="review.continuation.manual_retry_required")) == 1


def test_live_codex_hook_reports_waiting_without_starting_a_second_resume(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "codex-live")
    request = _seed_request(
        store,
        harness="codex",
        request_id="request-codex-live",
        metadata={
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2026-08-24T12:01:00+00:00",
            "hook_event_name": "PreToolUse",
        },
    )

    payload = continue_request_after_application(store, request_row=request, action="allow_once", now=NOW)

    assert payload["continuationStatus"] == "waiting"
    assert payload["resumeStatus"] == "pending"
    assert payload["resumeReason"] == "live_hook_waiting"
    assert payload["codexResume"]["strategy"] == "codex-live-hook"
    assert store.get_request_resume("request-codex-live")["status"] == "pending"


def test_codex_app_server_result_is_bounded_and_opaque(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "codex-app-server")
    request = _seed_request(
        store,
        harness="codex",
        request_id="request-codex-session",
        metadata={"codex_thread_id": "thread-safe-0001"},
    )
    seen: dict[str, object] = {}

    def fake_retry(*_args: object, **kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return {"status": "sent", "reason": "app_server_turn_started"}

    monkeypatch.setattr("codex_plugin_scanner.guard.continuation_runtime.retry_request_resume", fake_retry)

    payload = continue_request_after_application(
        store,
        request_row=request,
        action="allow_once",
        now=NOW,
        timeout_seconds=0.25,
    )

    assert seen["timeout_seconds"] == 0.25
    assert payload["continuationStatus"] == "resumed"
    assert payload["resumeStatus"] == "sent"
    assert payload["codexResume"]["strategy"] == "codex-app-server-thread"
    assert "thread-safe-0001" not in str(payload)


def test_cancelled_continuation_persists_failure_before_returning(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "cancelled")
    request = _seed_request(store, harness="pi", request_id="request-cancelled", metadata={})

    payload = continue_request_after_application(
        store,
        request_row=request,
        action="allow_once",
        now=NOW,
        cancelled=lambda: True,
    )

    assert payload["continuationStatus"] == "failed"
    assert payload["continuationReason"] == "continuation_cancelled"
    resume = store.get_request_resume("request-cancelled")
    assert resume is not None
    assert resume["continuation_cancelled_at"] == NOW
    assert len(store.list_events(event_name="review.continuation.attempt")) == 1
