"""Cloud Review batching, wake, and worker pacing contracts."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_event_wake import review_event_wake_signal
from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery, cloud_review_sync, cloud_review_sync_worker
from codex_plugin_scanner.guard.runtime.cloud_review_batching import (
    CLOUD_REVIEW_DEFAULT_BATCH_EVENTS,
    CLOUD_REVIEW_MAX_BATCH_BYTES,
    CLOUD_REVIEW_MAX_BATCH_EVENTS,
    CloudReviewBatchLimits,
    next_review_batch_limits,
    select_review_event_batch,
)
from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import encoded_review_events_payload
from tests.guard_exact_cloud_review_support import connected_exact_review_store


def _event(sequence: int, *, padding: int = 0) -> dict[str, object]:
    return {
        "eventId": f"event-{sequence}",
        "localStreamSequence": sequence,
        "padding": "x" * padding,
    }


def _approval(index: int) -> GuardApprovalRequest:
    request_id = f"batch-request-{index}"
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{index}",
        artifact_name=f"Action {index}",
        artifact_hash=f"hash-{index}",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/test/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        action_identity=request_id,
        queue_group_id=request_id,
        trigger_summary="Review action",
        last_seen_at="2026-08-26T12:00:00+00:00",
    )


def test_default_batch_is_byte_capped_using_exact_request_encoding() -> None:
    events = [_event(index, padding=80) for index in range(1, 80)]
    one_event_bytes = len(encoded_review_events_payload(events[:1]))
    limits = CloudReviewBatchLimits(bytes=one_event_bytes * 3)

    selected = select_review_event_batch(events, limits)

    assert 1 <= len(selected) < CLOUD_REVIEW_DEFAULT_BATCH_EVENTS
    assert len(encoded_review_events_payload(selected)) <= limits.bytes
    assert len(encoded_review_events_payload(events[: len(selected) + 1])) > limits.bytes


def test_adaptive_limits_honor_server_contract_and_advertised_caps() -> None:
    defaults = CloudReviewBatchLimits()

    grown = next_review_batch_limits(defaults, {})
    advertised = next_review_batch_limits(grown, {"maxBatchEvents": 75, "maxBatchBytes": 200_000})
    hostile = next_review_batch_limits(
        advertised,
        {"maxBatchEvents": 10_000, "maxBatchBytes": 10_000_000},
    )
    maximum = next_review_batch_limits(
        hostile,
        {"maxBatchEvents": 10_000, "maxBatchBytes": 10_000_000},
    )

    assert grown.events == 100
    assert advertised == CloudReviewBatchLimits(events=75, bytes=200_000, event_cap=75)
    assert hostile.events == 150
    assert hostile.bytes == CLOUD_REVIEW_MAX_BATCH_BYTES
    assert maximum.events == CLOUD_REVIEW_MAX_BATCH_EVENTS


def test_sync_shares_requests_across_events_and_adapts_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    for index in range(60):
        store.add_approval_request(_approval(index), "2026-08-26T12:00:00+00:00")
    batch_sizes: list[int] = []

    def accept_batch(
        _auth: dict[str, object],
        *,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        assert path == "/api/guard/review/v2/events:batch"
        events = payload["events"]
        assert isinstance(events, list)
        batch_sizes.append(len(events))
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": events[-1]["localStreamSequence"],
            "accepted": len(events),
            "rejected": 0,
            "results": [{"eventId": event["eventId"], "status": "accepted"} for event in events],
            "maxBatchEvents": CLOUD_REVIEW_MAX_BATCH_EVENTS,
            "maxBatchBytes": CLOUD_REVIEW_MAX_BATCH_BYTES,
        }

    monkeypatch.setattr(cloud_review_event_delivery, "_post_json", accept_batch)

    result = cloud_review_sync.sync_cloud_review_events_once(
        store,
        {"oauth_source": "default", "sync_url": "https://guard.example", **binding},
    )

    assert batch_sizes == [50, 10]
    assert result["synced"] == 60
    assert result["batches"] == 2


def test_authenticated_batch_cap_persists_across_worker_rounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    batch_sizes: list[int] = []

    def accept_batch(
        _store: object,
        auth: dict[str, object],
        events: list[dict[str, object]],
    ) -> tuple[dict[str, object], dict[str, object]]:
        batch_sizes.append(len(events))
        return (
            {
                "accepted": len(events),
                "rejected": 0,
                "perEventResults": [{"index": index, "accepted": True} for index, _event_payload in enumerate(events)],
                "maxBatchEvents": 2,
                "maxBatchBytes": CLOUD_REVIEW_MAX_BATCH_BYTES,
            },
            auth,
        )

    monkeypatch.setattr(cloud_review_sync, "_post_events_with_oauth_refresh", accept_batch)
    store.add_approval_request(_approval(1), "2026-08-26T12:00:00+00:00")
    auth: dict[str, object] = {"oauth_source": "default", "sync_url": "https://guard.example", **binding}
    cloud_review_sync.sync_cloud_review_events_once(store, auth)
    for index in range(2, 5):
        store.add_approval_request(_approval(index), "2026-08-26T12:00:00+00:00")

    cloud_review_sync.sync_cloud_review_events_once(store, auth)

    assert batch_sizes == [1, 2, 1]


def test_oversized_oldest_event_is_quarantined_without_starving_following_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    for index in range(1, 3):
        store.add_approval_request(_approval(index), "2026-08-26T12:00:00+00:00")
    binding_key = cloud_review_sync._batch_binding_key(
        {key: value for key, value in binding.items() if key != "oauth_source"}
    )
    cloud_review_sync._save_sync_state(
        store,
        {
            "batch_binding_key": binding_key,
            "batch_events": 50,
            "batch_max_bytes": 400,
            "batch_event_cap": CLOUD_REVIEW_MAX_BATCH_EVENTS,
        },
    )
    posted_sequences: list[int] = []

    def project(
        _store: object,
        *,
        outbox_row: dict[str, object],
        **_kwargs: object,
    ) -> tuple[int, dict[str, object]]:
        sequence_value = outbox_row["stream_sequence"]
        assert isinstance(sequence_value, int)
        sequence = sequence_value
        return sequence, _event(sequence, padding=1_000 if sequence == 1 else 0)

    def accept_batch(
        _store: object,
        auth: dict[str, object],
        events: list[dict[str, object]],
    ) -> tuple[dict[str, object], dict[str, object]]:
        sequence_values = [event["localStreamSequence"] for event in events]
        assert all(isinstance(sequence, int) for sequence in sequence_values)
        posted_sequences.extend(sequence for sequence in sequence_values if isinstance(sequence, int))
        return (
            {
                "accepted": len(events),
                "rejected": 0,
                "perEventResults": [{"index": index, "accepted": True} for index, _event_payload in enumerate(events)],
            },
            auth,
        )

    monkeypatch.setattr(cloud_review_sync, "project_cloud_review_event", project)
    monkeypatch.setattr(cloud_review_sync, "_post_events_with_oauth_refresh", accept_batch)

    result = cloud_review_sync.sync_cloud_review_events_once(
        store,
        {"oauth_source": "default", "sync_url": "https://guard.example", **binding},
    )

    assert posted_sequences == [2]
    assert result["synced"] == 1
    assert result["rejected"] == 1
    outbox = result["outbox"]
    assert isinstance(outbox, dict)
    assert outbox["quarantined_depth"] == 1


def test_committed_store_write_wakes_worker_but_rollback_does_not(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    signal = review_event_wake_signal(store.path)
    initial = signal.generation()

    with pytest.raises(RuntimeError, match="rollback"), store._connect() as connection:
        connection.execute("update approval_requests set last_seen_at = last_seen_at")
        raise RuntimeError("rollback")
    assert signal.generation() == initial

    store.add_approval_request(_approval(1), "2026-08-26T12:00:00+00:00")

    assert signal.generation() > initial
    committed_generation = signal.generation()
    store.set_sync_payload("unrelated", {"state": "idle"}, "2026-08-26T12:00:00+00:00")
    assert signal.generation() == committed_generation
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    delivery_binding = {key: value for key, value in binding.items() if key != "oauth_source"}
    assert store.review_event_outbox_status(now="2026-08-26T12:00:01+00:00", **delivery_binding)["depth"] == 1


def test_committed_existing_outbox_mutation_wakes_worker(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    store.add_approval_request(_approval(1), "2026-08-26T12:00:00+00:00")
    signal = review_event_wake_signal(store.path)
    initial = signal.generation()

    with store._connect() as connection:
        connection.execute(
            "update guard_review_outbox_events set binding_status = 'quarantined' where stream_sequence = 1"
        )

    assert signal.generation() > initial
    changed = signal.generation()
    with store._connect() as connection:
        connection.execute("update guard_review_outbox_events set machine_id = machine_id")
    assert signal.generation() == changed


def test_retryable_rejection_exposes_next_attempt_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    store.add_approval_request(_approval(1), "2026-08-26T12:00:00+00:00")

    def reject_batch(
        _store: object,
        auth: dict[str, object],
        events: list[dict[str, object]],
    ) -> tuple[dict[str, object], dict[str, object]]:
        return (
            {
                "accepted": 0,
                "rejected": len(events),
                "perEventResults": [
                    {"index": index, "accepted": False, "code": "retry_later"}
                    for index, _event_payload in enumerate(events)
                ],
            },
            auth,
        )

    monkeypatch.setattr(cloud_review_sync, "_post_events_with_oauth_refresh", reject_batch)

    result = cloud_review_sync.sync_cloud_review_events_once(
        store,
        {"oauth_source": "default", "sync_url": "https://guard.example", **binding},
    )

    assert isinstance(result["next_attempt_at"], str)
    outbox = result["outbox"]
    assert isinstance(outbox, dict)
    assert outbox["ready_depth"] == 0


def test_empty_authenticated_round_resets_backoff_to_safety_poll(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    stop_event = threading.Event()
    waits: list[float] = []
    attempts = 0

    class RecordingSignal:
        def generation(self) -> int:
            return 0

        def wait(self, generation: int, timeout: float) -> int:
            del generation
            waits.append(timeout)
            if len(waits) == 2:
                stop_event.set()
            return 0

    def sync_once(_store: object, _auth: dict[str, object]) -> dict[str, object]:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("offline")
        return {"synced": 0}

    monkeypatch.setattr(cloud_review_sync, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
    monkeypatch.setattr(cloud_review_sync, "sync_cloud_review_events_once", sync_once)
    monkeypatch.setattr(cloud_review_sync_worker.random, "uniform", lambda _low, _high: 1.0)

    cloud_review_sync_worker._cloud_sync_sync_loop(
        store,
        stop_event,
        RecordingSignal(),
        poll_interval=7.0,
        error_backoff=30.0,
    )

    assert waits == [2.0, 7.0]


def test_retry_deadline_bounds_healthy_worker_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    stop_event = threading.Event()
    waits: list[float] = []

    class RecordingSignal:
        def generation(self) -> int:
            return 0

        def wait(self, generation: int, timeout: float) -> int:
            del generation
            waits.append(timeout)
            stop_event.set()
            return 0

    retry_at = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    monkeypatch.setattr(cloud_review_sync, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
    monkeypatch.setattr(
        cloud_review_sync,
        "sync_cloud_review_events_once",
        lambda _store, _auth: {"synced": 0, "next_attempt_at": retry_at},
    )

    cloud_review_sync_worker._cloud_sync_sync_loop(
        store,
        stop_event,
        RecordingSignal(),
        poll_interval=30.0,
        error_backoff=30.0,
    )

    assert 0.0 < waits[0] <= 1.0


def test_error_backoff_jitter_is_exponential_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloud_review_sync_worker.random, "uniform", lambda _low, _high: 0.5)

    assert cloud_review_sync_worker._bounded_error_wait(2.0, 30.0, 1) == 2.0
    assert cloud_review_sync_worker._bounded_error_wait(2.0, 30.0, 2) == 4.0
    assert cloud_review_sync_worker._bounded_error_wait(2.0, 30.0, 20) == 15.0
