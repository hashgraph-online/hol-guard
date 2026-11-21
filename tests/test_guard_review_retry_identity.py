from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_correlation import cloud_review_correlation_id
from codex_plugin_scanner.guard.runtime.cloud_review_retry_recovery import prepare_retry_identity_replay
from codex_plugin_scanner.guard.runtime.review_event_delivery import decode_stored_review_event
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request

_NOW = "2026-08-24T12:00:00+00:00"
_LATER = "2026-08-24T12:01:00+00:00"
_UPSTREAM = "gcr_22222222-2222-4222-8222-222222222222"


def _snapshot(correlation: str) -> dict[str, object]:
    return {
        "correlationId": correlation,
        "capability": "retry-only",
        "hookAttached": False,
        "opaqueTargetId": None,
        "waitDeadline": None,
    }


@pytest.mark.parametrize("upstream", [None, _UPSTREAM])
@pytest.mark.parametrize("retry_snapshot", [None, _snapshot("gcr_33333333-3333-4333-8333-333333333333")])
def test_deduplicated_retry_preserves_cloud_identity(
    tmp_path: Path, upstream: str | None, retry_snapshot: dict[str, object] | None
) -> None:
    store = GuardStore(tmp_path / "guard")
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "grant-1", "workspace_id": "workspace-1", "machine_id": "machine-1"},
        _NOW,
    )
    request = GuardApprovalRequest(
        request_id="first-attempt",
        harness="codex",
        artifact_id="codex:project:retry-action",
        artifact_name="Test action",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/test/config.toml",
        review_command="hol-guard approvals approve first-attempt",
        approval_url="http://127.0.0.1:5474/requests/first-attempt",
        action_identity="same-action",
        queue_group_id="same-queue",
        continuation_snapshot=_snapshot(upstream) if upstream else None,
    )
    store.add_approval_request(request, _NOW)
    store.add_approval_request(
        replace(request, request_id="second-attempt", continuation_snapshot=retry_snapshot),
        _LATER,
    )

    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    events = store.list_ready_review_events(
        now=_LATER,
        limit=10,
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    assert [event["local_request_id"] for event in events] == ["first-attempt", "first-attempt"]
    assert [event["request_sequence"] for event in events] == [1, 2]
    snapshots = [decode_stored_review_event(event).snapshot["continuation_snapshot_json"] for event in events]
    expected = upstream or cloud_review_correlation_id("first-attempt")
    assert snapshots == [_snapshot(expected), _snapshot(expected)]
    saved = store.get_approval_request("first-attempt")
    assert saved is not None
    assert saved["last_seen_at"] == _LATER
    assert saved["continuation_snapshot"] == _snapshot(expected)
    assert store.get_approval_request("second-attempt") is None


@pytest.mark.parametrize("binding_changed", [False, True])
def test_rejected_identity_repair_is_bound_and_does_not_authorize(tmp_path: Path, binding_changed: bool) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("canonical-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    with store._connect() as connection:
        _ = connection.execute(
            "update approval_requests set continuation_snapshot_json = ? where request_id = ?",
            (json.dumps(_snapshot(_UPSTREAM)), "canonical-request"),
        )
    fields = ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    delivery_binding = {key: binding[key] for key in fields}
    events = store.list_ready_review_events(
        now=_LATER,
        limit=10,
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    sequence = events[-1]["sequence"]
    assert isinstance(sequence, int)
    if binding_changed:
        delivery_binding["workspace_id"] = "another-workspace"
    repaired = store.repair_rejected_review_correlation(
        event_sequence=sequence, binding=delivery_binding, changed_at=_LATER
    )
    assert repaired == (0 if binding_changed else 1)
    saved = store.get_approval_request("canonical-request")
    assert saved is not None
    expected = _UPSTREAM if binding_changed else cloud_review_correlation_id("canonical-request")
    assert saved["continuation_snapshot"] == _snapshot(expected)
    assert saved["status"] == "pending"
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    assert (
        store.repair_rejected_review_correlation(event_sequence=sequence, binding=delivery_binding, changed_at=_LATER)
        == 0
    )


def test_background_retry_replay_is_once_per_binding_and_keeps_ids(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("replay-request"))
    add_review_request(store, review_request("unchanged-request"))
    with store._connect() as connection:
        _ = connection.execute(
            "update approval_requests set continuation_snapshot_json = ? where request_id = ?",
            (json.dumps(_snapshot(_UPSTREAM)), "replay-request"),
        )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    fields = ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    delivery_binding = {field: binding[field] for field in fields}
    events = store.list_ready_review_events(
        now=_LATER,
        limit=10,
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    sequences = [event["sequence"] for event in events]
    assert all(isinstance(sequence, int) for sequence in sequences)
    _ = store.acknowledge_review_events(
        [sequence for sequence in sequences if isinstance(sequence, int)],
        **delivery_binding,
    )
    assert store.review_event_outbox_status(now=_LATER, **delivery_binding)["depth"] == 0
    assert prepare_retry_identity_replay(store, binding=binding) == 1
    assert prepare_retry_identity_replay(store, binding=binding) == 0
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    saved = store.get_approval_request("replay-request")
    assert saved is not None and saved["status"] == "pending"


@pytest.mark.parametrize(
    ("status", "snapshot"),
    [
        ("approved", _snapshot(_UPSTREAM)),
        ("pending", {**_snapshot(_UPSTREAM), "capability": "session-resume", "opaqueTargetId": "session-1"}),
        (
            "pending",
            {
                **_snapshot(_UPSTREAM),
                "capability": "suspended-response",
                "hookAttached": True,
                "waitDeadline": "2099-01-01T00:00:00Z",
            },
        ),
        ("pending", None),
    ],
)
def test_identity_recovery_leaves_decisions_and_resumable_sessions_untouched(
    tmp_path: Path, status: str, snapshot: dict[str, object] | None
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("protected-request"))
    with store._connect() as connection:
        _ = connection.execute(
            "update approval_requests set status = ?, continuation_snapshot_json = ? where request_id = ?",
            (status, json.dumps(snapshot), "protected-request"),
        )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    events = store.list_ready_review_events(
        now=_LATER,
        limit=10,
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    sequence = events[-1]["sequence"]
    assert isinstance(sequence, int)
    fields = ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    assert (
        store.repair_rejected_review_correlation(
            event_sequence=sequence,
            binding={field: binding[field] for field in fields},
            changed_at=_LATER,
        )
        == 0
    )
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None


@pytest.mark.parametrize("failed_write", ["insert", "update of acknowledged_at", "delete"])
def test_identity_repair_and_acknowledgment_roll_back_together(tmp_path: Path, failed_write: str) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("atomic-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    fields = ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    delivery_binding = {field: binding[field] for field in fields}
    with store._connect() as connection:
        _ = connection.execute(
            "update approval_requests set continuation_snapshot_json = ? where request_id = ?",
            (json.dumps(_snapshot(_UPSTREAM)), "atomic-request"),
        )
    _ = store.requeue_pending_review_events(changed_at=_NOW, require_binding=True)
    events = store.list_ready_review_events(
        now=_LATER,
        limit=10,
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    sequences = [event["sequence"] for event in events]
    assert all(isinstance(sequence, int) for sequence in sequences)
    _ = store.acknowledge_review_events(
        [sequence for sequence in sequences[:-1] if isinstance(sequence, int)], **delivery_binding
    )
    with store._connect() as connection:
        before = [tuple(row) for row in connection.execute("select * from guard_review_outbox_events")]
        versions = [tuple(row) for row in connection.execute("select * from guard_review_outbox_request_sequences")]
        sequence = int(connection.execute("select max(stream_sequence) from guard_review_outbox_events").fetchone()[0])
        _ = connection.execute(
            f"""create trigger fail_retry_repair before {failed_write} on guard_review_outbox_events
            begin select raise(abort, 'injected repair failure'); end"""
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected repair failure"):
        _ = store.repair_rejected_review_correlation(
            event_sequence=sequence, binding=delivery_binding, changed_at=_LATER
        )

    with store._connect() as connection:
        snapshot_json = connection.execute(
            "select continuation_snapshot_json from approval_requests where request_id = ?", ("atomic-request",)
        ).fetchone()[0]
        assert json.loads(snapshot_json) == _snapshot(_UPSTREAM)
        assert [tuple(row) for row in connection.execute("select * from guard_review_outbox_events")] == before
        assert [
            tuple(row) for row in connection.execute("select * from guard_review_outbox_request_sequences")
        ] == versions
        _ = connection.execute("drop trigger fail_retry_repair")

    assert (
        store.repair_rejected_review_correlation(event_sequence=sequence, binding=delivery_binding, changed_at=_LATER)
        == 1
    )
    with store._connect() as connection:
        assert (
            connection.execute(
                "select 1 from guard_review_outbox_events where stream_sequence = ?", (sequence,)
            ).fetchone()
            is None
        )
    ready = store.list_ready_review_events(
        now=_LATER,
        limit=10,
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    assert [(event["event_type"], event["local_request_id"]) for event in ready] == [
        ("review.request.refreshed", "atomic-request"),
        ("review.request.snapshot_requeued", "atomic-request"),
    ]
    assert [decode_stored_review_event(event).snapshot["continuation_snapshot_json"] for event in ready] == [
        _snapshot(cloud_review_correlation_id("atomic-request")),
        _snapshot(cloud_review_correlation_id("atomic-request")),
    ]
    saved = store.get_approval_request("atomic-request")
    assert saved is not None and saved["status"] == "pending"
    assert saved["continuation_snapshot"] == _snapshot(cloud_review_correlation_id("atomic-request"))
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
