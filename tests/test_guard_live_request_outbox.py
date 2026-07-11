from __future__ import annotations

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import live_request_sync
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-07-11T12:00:00+00:00"
_AUTH = {
    "machine_id": "machine-1",
    "workspace_id": "workspace-1",
    "machine_installation_id": "22222222-2222-4222-8222-222222222222",
}


def _request(request_id: str, *, summary: str = "Review test action") -> GuardApprovalRequest:
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
        config_path="/tmp/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        action_identity=request_id,
        queue_group_id=request_id,
        trigger_summary=summary,
        last_seen_at=_NOW,
    )


def test_approval_insert_and_resolution_share_transactional_outbox(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")

    request_id = store.add_approval_request(_request("request-1"), _NOW)
    pending = store.list_ready_live_request_outbox(now=_NOW, limit=10)

    assert request_id == "request-1"
    assert len(pending) == 1
    assert pending[0]["local_request_id"] == request_id
    first_sequence = int(pending[0]["sequence"])

    store.resolve_approval_request(
        request_id,
        resolution_action="approve",
        resolution_scope="artifact",
        reason="approved",
        resolved_at="2026-07-11T12:00:00.100000+00:00",
    )
    resolved = store.list_ready_live_request_outbox(
        now="2026-07-11T12:00:01+00:00",
        limit=10,
    )

    assert len(resolved) == 1
    assert int(resolved[0]["sequence"]) > first_sequence
    assert store.get_approval_request(request_id)["status"] == "resolved"


def test_acknowledging_inflight_sequence_preserves_newer_mutation(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    selected = store.list_ready_live_request_outbox(now=_NOW, limit=1)
    old_sequence = int(selected[0]["sequence"])

    store.add_approval_request(
        _request("request-1", summary="Updated review summary"),
        "2026-07-11T12:00:00.050000+00:00",
    )
    assert store.acknowledge_live_request_outbox([old_sequence]) == 0

    remaining = store.list_ready_live_request_outbox(
        now="2026-07-11T12:00:01+00:00",
        limit=10,
    )
    assert len(remaining) == 1
    assert int(remaining[0]["sequence"]) > old_sequence


def test_outbox_ownership_is_not_reassigned_after_workspace_switch(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)

    assert store.claim_unowned_live_request_outbox("workspace-a") == 1
    assert (
        len(
            store.list_ready_live_request_outbox(
                now=_NOW,
                limit=10,
                workspace_id="workspace-a",
            )
        )
        == 1
    )
    assert (
        store.list_ready_live_request_outbox(
            now=_NOW,
            limit=10,
            workspace_id="workspace-b",
        )
        == []
    )

    store.add_approval_request(
        _request("request-1", summary="Updated review summary"),
        "2026-07-11T12:00:00.050000+00:00",
    )
    assert store.claim_unowned_live_request_outbox("workspace-b") == 0
    assert (
        len(
            store.list_ready_live_request_outbox(
                now="2026-07-11T12:00:01+00:00",
                limit=10,
                workspace_id="workspace-a",
            )
        )
        == 1
    )
    assert (
        store.live_request_outbox_status(
            now=_NOW,
            workspace_id="workspace-a",
        )["depth"]
        == 1
    )
    assert (
        store.live_request_outbox_status(
            now=_NOW,
            workspace_id="workspace-b",
        )["depth"]
        == 0
    )


def test_newer_mutation_preserves_retry_backoff(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    selected = store.list_ready_live_request_outbox(now=_NOW, limit=1)
    old_sequence = int(selected[0]["sequence"])
    store.retry_live_request_outbox([old_sequence], now=_NOW, error="offline")

    store.add_approval_request(
        _request("request-1", summary="Updated review summary"),
        "2026-07-11T12:00:00.050000+00:00",
    )

    assert store.list_ready_live_request_outbox(now=_NOW, limit=1) == []
    retried = store.list_ready_live_request_outbox(
        now="2026-07-11T12:00:01+00:00",
        limit=1,
    )
    assert len(retried) == 1
    assert int(retried[0]["sequence"]) > old_sequence
    assert retried[0]["attempt_count"] == 1


def test_explicit_request_deletion_is_not_blocked_by_pending_outbox(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)

    with store._connect() as connection:
        connection.execute(
            "delete from approval_requests where request_id = ?",
            ("request-1",),
        )

    assert store.get_approval_request("request-1") is None


def test_successful_sync_deletes_only_acknowledged_outbox_rows(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    posted: list[list[dict[str, object]]] = []

    def post_events(*_args, **kwargs):
        events = kwargs["events"]
        posted.append(events)
        return {"accepted": len(events), "rejected": 0, "cursor": "cloud-cursor"}

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    first = live_request_sync.sync_live_requests_once(store, _AUTH)
    second = live_request_sync.sync_live_requests_once(store, _AUTH)

    assert first["synced"] == 1
    assert first["outbox"]["depth"] == 0
    assert second["synced"] == 0
    assert len(posted) == 1
    assert posted[0][0]["localRequestId"] == "request-1"


def test_resolution_during_send_preserves_newer_outbox_event(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    resolved_during_send = False

    def resolve_while_posting(*_args, **kwargs):
        nonlocal resolved_during_send
        if not resolved_during_send:
            resolved_during_send = True
            store.resolve_approval_request(
                "request-1",
                resolution_action="approve",
                resolution_scope="artifact",
                reason="approved",
                resolved_at="2026-07-11T12:00:00.100000+00:00",
            )
        return {
            "accepted": len(kwargs["events"]),
            "rejected": 0,
            "cursor": "cloud-cursor",
        }

    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        resolve_while_posting,
    )

    result = live_request_sync.sync_live_requests_once(store, _AUTH)

    assert result["synced"] == 2
    assert result["outbox"]["depth"] == 0
    assert store.get_approval_request("request-1")["status"] == "resolved"


def test_rejected_batch_remains_durable_and_is_backed_off(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        lambda *_args, **_kwargs: {
            "accepted": 0,
            "rejected": 1,
            "errors": ["policy"],
        },
    )

    result = live_request_sync.sync_live_requests_once(store, _AUTH)

    assert result["rejected"] == 1
    status = store.live_request_outbox_status(now=_NOW)
    assert status["depth"] == 1
    assert status["max_attempt_count"] == 1
    assert store.list_ready_live_request_outbox(now=_NOW, limit=10) == []


def test_partial_acknowledgement_retries_only_rejected_event(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-accepted"), "2026-07-11T18:00:00+00:00")
    store.add_approval_request(_request("request-rejected"), _NOW)

    def post_events(*_args, **kwargs):
        return {
            "accepted": 1,
            "rejected": 1,
            "perEventResults": [
                {
                    "index": index,
                    "accepted": event["localRequestId"] == "request-accepted",
                }
                for index, event in enumerate(kwargs["events"])
            ],
        }
    monkeypatch.setattr(live_request_sync, "_post_sync_events", post_events)

    result = live_request_sync.sync_live_requests_once(store, _AUTH)

    assert result["synced"] == 1
    assert result["rejected"] == 1
    rows = store.list_ready_live_request_outbox(now="9999-12-31T23:59:59+00:00", limit=10)
    assert [row["local_request_id"] for row in rows] == ["request-rejected"]
    assert rows[0]["attempt_count"] == 1


def test_stale_rejection_is_acknowledged_while_transient_rejection_retries(
    tmp_path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-stale"), _NOW)
    store.add_approval_request(_request("request-transient"), "2026-07-11T18:00:00+00:00")
    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        lambda *_args, **_kwargs: {
            "accepted": 0,
            "rejected": 2,
            "perEventResults": [
                {"index": 0, "accepted": False, "error": "temporary failure"},
                {
                    "index": 1,
                    "accepted": False,
                    "error": "stale event sequence for request-stale (seq 1 < existing 2)",
                },
            ],
        },
    )

    live_request_sync.sync_live_requests_once(store, _AUTH)

    rows = store.list_ready_live_request_outbox(
        now="9999-12-31T23:59:59+00:00",
        limit=10,
    )
    assert [row["local_request_id"] for row in rows] == ["request-transient"]
    assert rows[0]["attempt_count"] == 1


def test_newest_outbox_event_preempts_historical_backlog(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("historical"), _NOW)
    store.add_approval_request(_request("new"), "2026-07-11T18:00:00+00:00")

    rows = store.list_ready_live_request_outbox(
        now="9999-12-31T23:59:59+00:00",
        limit=1,
    )

    assert [row["local_request_id"] for row in rows] == ["new"]


def test_worker_safety_interval_is_subsecond() -> None:
    assert live_request_sync.DEFAULT_POLL_INTERVAL_SECONDS <= 0.1
    assert live_request_sync.LIVE_REQUEST_SYNC_BATCH_SIZE <= 25
