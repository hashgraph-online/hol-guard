from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import TypedDict

import pytest

from codex_plugin_scanner.guard.continuation_runtime import (
    continue_request_after_application,
    record_live_hook_completion,
)
from codex_plugin_scanner.guard.live_process_identity import current_process_identity
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_event_integrity import review_event_payload_digest
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import project_cloud_review_event
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_review_event_outbox_writes import append_request_snapshot_event
from tests.guard_review_event_outbox_test_support import as_int

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnusedCallResult=false

_NOW = "2026-08-24T14:00:00+00:00"
_LATER = "2026-08-24T14:00:01+00:00"


class _Binding(TypedDict):
    oauth_subject_hash: str
    workspace_id: str
    machine_id: str
    machine_installation_id: str


def _request(request_id: str, *, summary: str = "Review action") -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Test action",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/test/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        action_identity=request_id,
        queue_group_id=request_id,
        trigger_summary=summary,
        last_seen_at=_NOW,
    )


def _connect(store: GuardStore) -> _Binding:
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "grant-1", "workspace_id": "workspace-1", "machine_id": "machine-1"},
        _NOW,
    )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    return {
        "oauth_subject_hash": binding["oauth_subject_hash"],
        "workspace_id": binding["workspace_id"],
        "machine_id": binding["machine_id"],
        "machine_installation_id": binding["machine_installation_id"],
    }


def _auth(binding: _Binding) -> dict[str, object]:
    return {"oauth_source": "default", **binding}


def _accepting_transport(captured: list[dict[str, object]]) -> Callable[..., dict[str, object]]:
    def post(*_args: object, events: list[dict[str, object]], **_kwargs: object) -> dict[str, object]:
        captured.extend(events)
        return {
            "accepted": len(events),
            "rejected": 0,
            "perEventResults": [{"index": index, "accepted": True} for index, _event in enumerate(events)],
        }

    return post


def _event_row(store: GuardStore) -> sqlite3.Row:
    with store._connect() as connection:
        row = connection.execute("select * from guard_review_outbox_events").fetchone()
    assert row is not None
    return row


def _replace_event_payload(store: GuardStore, row: sqlite3.Row, payload: dict[str, object]) -> None:
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    with store._connect() as connection:
        connection.execute(
            """
            update guard_review_outbox_events set payload_json = ?, payload_hash = ?
            where stream_sequence = ?
            """,
            (
                payload_json,
                review_event_payload_digest(
                    payload_json,
                    oauth_source=row["oauth_source"],
                    oauth_subject_hash=row["oauth_subject_hash"],
                    workspace_id=row["workspace_id"],
                    machine_id=row["machine_id"],
                    machine_installation_id=row["machine_installation_id"],
                ),
                row["stream_sequence"],
            ),
        )


def test_create_then_resolve_before_sync_delivers_distinct_immutable_transitions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    store.resolve_approval_request(
        "request-1",
        resolution_action="approve",
        resolution_scope="artifact",
        reason="approved",
        resolved_at=_LATER,
    )
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(cloud_review_sync, "post_review_events", _accepting_transport(captured))

    result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(binding))

    assert result["synced"] == 2
    assert [event["eventType"] for event in captured] == ["request_created", "request_resolved"]
    assert [event["localEventSequence"] for event in captured] == [1, 2]
    stored_payloads = [event["eventPayloadJson"] for event in captured]
    assert all(isinstance(payload, str) for payload in stored_payloads)
    assert [json.loads(payload).get("eventType") for payload in stored_payloads if isinstance(payload, str)] == [
        "review.request.created",
        "review.request.resolved",
    ]
    payloads = [event["requestPayload"] for event in captured]
    assert all(isinstance(payload, dict) for payload in payloads)
    assert [payload.get("status") for payload in payloads if isinstance(payload, dict)] == ["pending", "resolved"]


def test_projection_uses_frozen_continuation_after_operation_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    correlation_id = "gcr_12345678-1234-1234-1234-123456789abc"
    request = replace(
        _request("request-frozen-continuation"),
        continuation_snapshot={
            "capability": "suspended-response",
            "correlationId": correlation_id,
            "hookAttached": True,
            "opaqueTargetId": None,
            "waitDeadline": "2026-08-24T15:00:00+00:00",
        },
    )
    store.add_approval_request(request, _NOW)
    before = _event_row(store)
    frozen_payload = str(before["payload_json"])

    monkeypatch.setattr(
        GuardStore,
        "get_guard_operation_for_approval_request",
        lambda *_args, **_kwargs: {
            "status": "resolved",
            "metadata": {"correlationId": "gcr_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
        },
    )
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(cloud_review_sync, "post_review_events", _accepting_transport(captured))

    result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(binding))

    assert result["synced"] == 1
    assert len(captured) == 1
    event = captured[0]
    assert event["correlationId"] == correlation_id
    assert event["continuationCapability"] == "suspended-response"
    assert event["continuationHookAttached"] is True
    assert event["continuationWaitDeadline"] == "2026-08-24T15:00:00+00:00"
    assert event["eventPayloadJson"] == frozen_payload


def test_terminal_continuation_projects_as_a_distinct_authenticated_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    correlation_id = "gcr_12345678-1234-1234-1234-123456789abc"
    request = replace(
        _request("request-terminal-continuation"),
        continuation_snapshot={
            "capability": "suspended-response",
            "correlationId": correlation_id,
            "hookAttached": True,
            "opaqueTargetId": None,
            "waitDeadline": "2026-08-24T15:00:00+00:00",
        },
    )
    store.add_approval_request(request, _NOW)
    session = store.upsert_guard_session(
        session_id="session-terminal-continuation",
        harness="codex",
        surface="harness-adapter",
        status="waiting_on_approval",
        client_name="codex-hook",
        client_title="Codex hook",
        client_version="1.0.0",
        workspace="/workspace",
        capabilities=["approval-resolution"],
        now=_NOW,
    )
    process_identity = current_process_identity()
    assert process_identity is not None
    store.upsert_guard_operation(
        operation_id="operation-terminal-continuation",
        session_id=str(session["session_id"]),
        harness="codex",
        operation_type="tool_call",
        status="waiting_on_approval",
        approval_request_ids=[request.request_id],
        resume_token=None,
        metadata={
            "codex_hook_waits_for_browser_approval": True,
            "codex_browser_wait_deadline_at": "2026-08-24T15:00:00+00:00",
            "codex_browser_wait_process": process_identity,
            "correlationId": correlation_id,
        },
        now=_NOW,
    )
    request_row = store.get_approval_request(request.request_id)
    assert request_row is not None
    waiting = continue_request_after_application(
        store,
        request_row=request_row,
        action="allow_once",
        now=_NOW,
        timeout_seconds=30.0,
    )
    assert waiting["continuationStatus"] == "waiting", waiting
    completed = record_live_hook_completion(store, request_id=request.request_id, action="allow", now=_LATER)
    assert completed is not None and completed["continuationStatus"] == "resumed"
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(cloud_review_sync, "post_review_events", _accepting_transport(captured))

    result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(binding))

    assert result["synced"] == 2
    terminal = captured[-1]
    assert terminal["eventType"] == "continuation_resumed"
    assert terminal["localEventSequence"] == 2
    assert terminal["continuationResult"] == {
        "action": "allow_once",
        "capability": "suspended-response",
        "completedAt": _LATER,
        "correlationId": correlation_id,
        "evidenceId": completed["continuationEvidenceId"],
        "reason": "live_hook_completed",
        "status": "resumed",
    }
    envelope = json.loads(str(terminal["eventPayloadJson"]))
    assert envelope["continuationResult"] == terminal["continuationResult"]


def test_terminal_continuation_projects_degraded_runtime_capability(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    correlation_id = "gcr_12345678-1234-1234-1234-123456789abc"
    request = replace(
        _request("request-degraded-continuation"),
        continuation_snapshot={
            "capability": "suspended-response",
            "correlationId": correlation_id,
            "hookAttached": True,
            "opaqueTargetId": None,
            "waitDeadline": "2026-08-24T15:00:00+00:00",
        },
    )
    store.add_approval_request(request, _NOW)
    with store._connect() as connection:
        connection.execute("begin immediate")
        assert (
            append_request_snapshot_event(
                connection,
                request_id=request.request_id,
                source="default",
                event_type="review.continuation.manual_retry_required",
                occurred_at=_LATER,
                continuation_result={
                    "action": "allow_once",
                    "capability": "retry-only",
                    "completedAt": _LATER,
                    "correlationId": correlation_id,
                    "evidenceId": "evidence-runtime-degraded",
                    "reason": "manual_retry_required",
                    "status": "manual_retry_required",
                },
            )
            == 1
        )
    terminal_row = store.list_ready_review_events(now=_LATER, limit=10, **binding)[-1]

    projected = project_cloud_review_event(
        store,
        outbox_row=terminal_row,
        delivery_binding={
            "oauth_subject_hash": binding["oauth_subject_hash"],
            "workspace_id": binding["workspace_id"],
            "machine_id": binding["machine_id"],
            "machine_installation_id": binding["machine_installation_id"],
        },
        redaction_level="full",
        oauth=None,
    )

    assert projected is not None
    _, event = projected
    assert event["continuationCapability"] == "retry-only"
    assert event["continuationResult"] == {
        "action": "allow_once",
        "capability": "retry-only",
        "completedAt": _LATER,
        "correlationId": correlation_id,
        "evidenceId": "evidence-runtime-degraded",
        "reason": "manual_retry_required",
        "status": "manual_retry_required",
    }


def test_request_sequence_survives_ack_compaction_refresh_and_restart(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    first = store.list_ready_review_events(now=_NOW, limit=1, **binding)[0]
    assert store.acknowledge_review_events([as_int(first["sequence"])], **binding) == 1

    restarted = GuardStore(guard_home)
    restarted.add_approval_request(_request("request-1", summary="refreshed"), _LATER)
    refreshed = restarted.list_ready_review_events(now=_LATER, limit=1, **binding)

    assert len(refreshed) == 1
    assert refreshed[0]["request_sequence"] == 2


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    [
        ("update guard_review_outbox_events set payload_json = payload_json || ' '", "payload_hash_mismatch"),
        ("update guard_review_outbox_events set payload_hash = '00'", "payload_hash_mismatch"),
        ("update guard_review_outbox_events set event_schema_version = 999", "unsupported_event_schema"),
    ],
)
def test_invalid_stored_event_is_dead_lettered_without_send_or_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected_reason: str,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    original_sequence = int(_event_row(store)["stream_sequence"])
    with store._connect() as connection:
        connection.execute(mutation)
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(cloud_review_sync, "post_review_events", _accepting_transport(captured))

    result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(binding))

    assert result["synced"] == 0
    assert captured == []
    row = _event_row(store)
    assert row["stream_sequence"] == original_sequence
    assert row["binding_status"] == "quarantined"
    assert row["quarantine_reason"] == expected_reason
    assert (
        store.reassign_quarantined_review_events(
            approved_source="default",
            approved_workspace_id=binding["workspace_id"],
        )
        == 0
    )
    assert _event_row(store)["quarantine_reason"] == expected_reason
    with store._connect() as connection:
        cursor = connection.execute("select * from guard_review_outbox_cursors").fetchone()
    assert cursor is None


def test_missing_canonical_snapshot_is_quarantined_without_fabricated_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    row = _event_row(store)
    payload = json.loads(str(row["payload_json"]))
    del payload["requestSnapshot"]
    _replace_event_payload(store, row, payload)
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(cloud_review_sync, "post_review_events", _accepting_transport(captured))

    result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(binding))

    assert result["synced"] == 0
    assert captured == []
    assert _event_row(store)["quarantine_reason"] == "payload_snapshot_missing"


@pytest.mark.parametrize(
    ("tamper", "expected_reason"),
    [
        ("missing_harness", "payload_snapshot_incomplete"),
        ("extra_field", "payload_snapshot_unexpected_fields"),
        ("source_mismatch", "payload_snapshot_source_mismatch"),
        ("envelope_source_mismatch", "payload_source_binding_mismatch"),
    ],
)
def test_rehashed_noncanonical_snapshot_is_quarantined_before_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
    expected_reason: str,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    row = _event_row(store)
    payload = json.loads(str(row["payload_json"]))
    snapshot = payload["requestSnapshot"]
    assert isinstance(snapshot, dict)
    if tamper == "missing_harness":
        del snapshot["harness"]
    elif tamper == "extra_field":
        snapshot["unexpected"] = "value"
    elif tamper == "source_mismatch":
        snapshot["oauth_source"] = "other"
    else:
        payload["oauthSource"] = "other"
    _replace_event_payload(store, row, payload)
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(cloud_review_sync, "post_review_events", _accepting_transport(captured))

    result = cloud_review_sync.sync_cloud_review_events_once(store, _auth(binding))

    assert result["synced"] == 0
    assert captured == []
    assert _event_row(store)["quarantine_reason"] == expected_reason
