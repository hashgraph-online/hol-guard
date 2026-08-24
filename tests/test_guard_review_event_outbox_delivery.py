from __future__ import annotations

import json
import urllib.error
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_review_event_dead_letters
from codex_plugin_scanner.guard.review_event_wake import (
    consume_review_event_outbox_signal,
    review_event_outbox_signal_token,
)
from codex_plugin_scanner.guard.runtime import live_request_sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_event_outbox_test_support import (
    as_int,
)
from tests.guard_review_event_outbox_test_support import (
    auth_context as _auth,
)
from tests.guard_review_event_outbox_test_support import (
    connect_store as _connect,
)
from tests.guard_review_event_outbox_test_support import (
    event_row as _event_row,
)
from tests.guard_review_event_outbox_test_support import (
    replace_event_payload as _replace_event_payload,
)
from tests.guard_review_event_outbox_test_support import (
    review_request as _request,
)
from tests.test_guard_review_event_batch_worker import assert_byte_capped_batch

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnusedCallResult=false

_NOW = "2026-08-24T14:00:00+00:00"
_LATER = "2026-08-24T14:00:01+00:00"


def _accepting_transport(captured: list[dict[str, object]]) -> Callable[..., dict[str, object]]:
    def post(*_args: object, events: list[dict[str, object]], **_kwargs: object) -> dict[str, object]:
        captured.extend(events)
        return {
            "accepted": len(events),
            "rejected": 0,
            "highestContiguousAcknowledgedStreamSequence": max(
                (int(event["localStreamSequence"]) for event in events), default=0
            ),
            "perEventResults": [{"index": index, "accepted": True} for index, _event in enumerate(events)],
        }

    return post


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
    monkeypatch.setattr(live_request_sync, "_post_sync_events", _accepting_transport(captured))

    result = live_request_sync.sync_live_requests_once(store, _auth(binding))

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
    _assert_batch_worker_load_and_recovery(tmp_path, monkeypatch)


@pytest.mark.parametrize("cursor", [None, 999])
def test_sync_rejects_missing_or_out_of_batch_contiguous_cursor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cursor: int | None,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)

    def post(*_args: object, events: list[dict[str, object]], **_kwargs: object) -> dict[str, object]:
        response: dict[str, object] = {
            "accepted": len(events),
            "rejected": 0,
            "perEventResults": [{"index": 0, "accepted": True}],
        }
        if cursor is not None:
            response["highestContiguousAcknowledgedStreamSequence"] = cursor
        return response

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post)
    result = live_request_sync.sync_live_requests_once(store, _auth(binding))
    state = store.get_sync_payload(live_request_sync.LIVE_REQUEST_SYNC_STATE_KEY)

    assert result["synced"] == 0
    with store._connect() as connection:
        retained = connection.execute("select count(*) as count from guard_review_outbox_events").fetchone()
    assert retained is not None and retained["count"] == 1
    assert isinstance(state, dict)
    assert state.get("last_acknowledged_sequence") is None
    assert state["last_error_category"] == "schema"


def test_authorization_retry_forces_fresh_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    calls: list[str] = []

    def post(auth: dict[str, object], **_kwargs: object) -> dict[str, object]:
        token = str(auth.get("access_token"))
        calls.append(token)
        if token == "stale":
            raise urllib.error.HTTPError("https://hol.test", 401, "expired", {}, None)
        return {"accepted": 0, "rejected": 0}

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post)
    monkeypatch.setattr(
        live_request_sync,
        "_resolve_auth_context_for_retry",
        lambda _store: {"access_token": "fresh"},
    )
    _, context = live_request_sync._post_sync_events_with_auth_refresh(
        store,
        {"access_token": "stale"},
        workspace_id="workspace-1",
        machine_id="machine-1",
        machine_installation_id="installation-1",
        cursor=None,
        events=[],
    )

    assert calls == ["stale", "fresh"]
    assert context["access_token"] == "fresh"


def test_retry_delay_blocks_later_outbox_rows(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    for index in range(51):
        store.add_approval_request(_request(f"request-{index}"), _NOW)
    rows = store.list_ready_live_request_outbox(now=_NOW, limit=50, **binding)
    sequences = [int(row["sequence"]) for row in rows]

    assert store.retry_live_request_outbox(sequences, now=_NOW, error="offline", **binding) == 50
    assert store.list_ready_live_request_outbox(now=_NOW, limit=50, **binding) == []
    future = store.list_ready_live_request_outbox(now="2026-08-24T14:01:00+00:00", limit=50, **binding)
    assert [int(row["sequence"]) for row in future] == sequences


def test_dead_letter_access_is_binding_scoped_and_retry_appends_new_sequence(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    sequence = int(_event_row(store)["stream_sequence"])
    assert (
        store.dead_letter_live_request_outbox_event(sequence, reason="invalid_event_schema", error="invalid", **binding)
        == 1
    )
    other_binding = {**binding, "workspace_id": "workspace-other"}

    assert store.list_live_request_outbox_dead_letters(**other_binding) == []
    assert store.retry_live_request_outbox_dead_letters(**other_binding) == 0
    assert store.retry_live_request_outbox_dead_letters(**binding) == 1
    retried = store.list_ready_live_request_outbox(now=_LATER, limit=10, **binding)
    assert len(retried) == 1 and int(retried[0]["sequence"]) > sequence


def test_lower_sequence_restore_changes_signal_beneath_same_maximum(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    first_sequence = int(_event_row(store)["stream_sequence"])
    store.add_approval_request(_request("request-2"), _NOW)
    with store._connect() as connection:
        maximum_before = connection.execute(
            "select max(stream_sequence) as maximum from guard_review_outbox_events"
        ).fetchone()
    assert maximum_before is not None
    assert (
        store.dead_letter_live_request_outbox_event(
            first_sequence,
            reason="invalid_event_schema",
            error="invalid",
            retain_outbox_event=True,
            **binding,
        )
        == 1
    )
    signal_before_restore = review_event_outbox_signal_token(store)
    assert consume_review_event_outbox_signal(store) is True

    assert store.retry_live_request_outbox_dead_letters([first_sequence], **binding) == 1
    signal_after_restore = review_event_outbox_signal_token(store)
    with store._connect() as connection:
        maximum_after = connection.execute(
            "select max(stream_sequence) as maximum from guard_review_outbox_events"
        ).fetchone()

    assert maximum_after is not None
    assert maximum_after["maximum"] == maximum_before["maximum"]
    assert signal_before_restore is not None and signal_after_restore is not None


def test_oversized_dead_letter_leaves_active_stream_and_retries_at_tail(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("oversized"), _NOW)
    sequence = int(_event_row(store)["stream_sequence"])

    assert (
        store.dead_letter_live_request_outbox_event(
            sequence, reason="batch_byte_limit_exceeded", error="too large", **binding
        )
        == 1
    )
    with store._connect() as connection:
        active = connection.execute("select 1 from guard_review_outbox_events").fetchone()
    assert active is None
    assert store.retry_live_request_outbox_dead_letters(**binding) == 1
    retried = store.list_ready_live_request_outbox(now=_LATER, limit=1, **binding)
    assert len(retried) == 1 and int(retried[0]["sequence"]) > sequence


def test_explicit_invalid_dead_letter_filter_never_retries_all(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    sequence = int(_event_row(store)["stream_sequence"])
    assert (
        store.dead_letter_live_request_outbox_event(sequence, reason="invalid_event_schema", error="invalid", **binding)
        == 1
    )

    assert store.retry_live_request_outbox_dead_letters([0, -1], **binding) == 0
    assert len(store.list_live_request_outbox_dead_letters(**binding)) == 1


def test_dead_letter_retention_is_bounded_per_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    monkeypatch.setattr(store_review_event_dead_letters, "_MAX_DEAD_LETTERS_PER_BINDING", 2)
    for index in range(3):
        store.add_approval_request(_request(f"request-{index}"), _NOW)
        sequence = int(_event_row(store)["stream_sequence"])
        assert (
            store.dead_letter_live_request_outbox_event(
                sequence, reason="invalid_event_schema", error="invalid", **binding
            )
            == 1
        )

    dead_letters = store.list_live_request_outbox_dead_letters(**binding)
    assert len(dead_letters) == 2
    assert {row["local_request_id"] for row in dead_letters} == {"request-1", "request-2"}


def _assert_batch_worker_load_and_recovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert_byte_capped_batch()
    store = GuardStore(tmp_path / "batch-worker")
    binding = _connect(store)
    for index in range(1_000):
        store.add_approval_request(_request(f"batch-{index:04d}"), _NOW)
    clock = [_NOW]
    monkeypatch.setattr(live_request_sync, "_now", lambda: clock[0])
    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    with pytest.raises(OSError, match="offline"):
        live_request_sync.sync_live_requests_once(store, _auth(binding))
    clock[0] = "2026-08-25T14:00:00+00:00"
    batches: list[list[dict[str, object]]] = []

    def post(*_args: object, events: list[dict[str, object]], **_kwargs: object) -> dict[str, object]:
        batches.append(events)
        return {
            "accepted": len(events),
            "rejected": 0,
            "maxBatchSize": 50,
            "highestContiguousAcknowledgedStreamSequence": max(
                (int(event["localStreamSequence"]) for event in events), default=0
            ),
            "perEventResults": [{"index": index, "accepted": True} for index, _event in enumerate(events)],
        }

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post)
    result = live_request_sync.sync_live_requests_once(store, _auth(binding))
    state = store.get_sync_payload(live_request_sync.LIVE_REQUEST_SYNC_STATE_KEY)
    assert result["synced"] == 1_000 and [len(events) for events in batches] == [50] * 20
    assert isinstance(state, dict) and state["last_acknowledged_sequence"] == 1_000
    assert state["enqueue_to_send_average_ms"] >= 0 and state["enqueue_to_ack_average_ms"] >= 0
    monkeypatch.setattr(
        live_request_sync,
        "_post_sync_events",
        lambda *_args, **_kwargs: {
            "accepted": 0,
            "rejected": 1,
            "highestContiguousAcknowledgedStreamSequence": 1_000,
            "perEventResults": [{"index": 0, "accepted": False, "code": "invalid_event_schema"}],
        },
    )
    store.add_approval_request(_request("dead-letter"), clock[0])
    live_request_sync.sync_live_requests_once(store, _auth(binding))
    assert len(store.list_live_request_outbox_dead_letters(**binding)) == 1
    retained = _event_row(store)
    assert retained["stream_sequence"] == 1_001
    assert retained["binding_status"] == "quarantined"
    assert store.retry_live_request_outbox_dead_letters(**binding) == 1
    retried = store.list_ready_live_request_outbox(now="2026-08-25T14:01:00+00:00", limit=1, **binding)
    assert len(retried) == 1 and retried[0]["stream_sequence"] == 1_001


def test_request_sequence_survives_ack_compaction_refresh_and_restart(
    tmp_path: Path,
) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    first = store.list_ready_live_request_outbox(now=_NOW, limit=1, **binding)[0]
    assert store.acknowledge_live_request_outbox([as_int(first["sequence"])], **binding) == 1

    restarted = GuardStore(guard_home)
    restarted.add_approval_request(_request("request-1", summary="refreshed"), _LATER)
    refreshed = restarted.list_ready_live_request_outbox(now=_LATER, limit=1, **binding)

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
def test_invalid_stored_event_is_quarantined_without_send_or_ack(
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
    monkeypatch.setattr(live_request_sync, "_post_sync_events", _accepting_transport(captured))

    result = live_request_sync.sync_live_requests_once(store, _auth(binding))

    assert result["synced"] == 0
    assert captured == []
    dead_letters = store.list_live_request_outbox_dead_letters(**binding)
    assert len(dead_letters) == 1
    assert dead_letters[0]["stream_sequence"] == original_sequence
    assert dead_letters[0]["dead_letter_reason"] == expected_reason
    retained = _event_row(store)
    assert retained["stream_sequence"] == original_sequence
    assert retained["binding_status"] == "quarantined"
    assert store.retry_live_request_outbox_dead_letters(**binding) == 1
    retried = store.list_ready_live_request_outbox(now=_LATER, limit=1, **binding)
    assert len(retried) == 1 and int(retried[0]["stream_sequence"]) == original_sequence
    with store._connect() as connection:
        cursor = connection.execute("select * from guard_review_outbox_cursors").fetchone()
    assert cursor is None


def test_missing_canonical_snapshot_is_dead_lettered_without_fabricated_defaults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    row = _event_row(store)
    original_sequence = int(row["stream_sequence"])
    payload = json.loads(str(row["payload_json"]))
    del payload["requestSnapshot"]
    _replace_event_payload(store, row, payload)
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(live_request_sync, "_post_sync_events", _accepting_transport(captured))

    result = live_request_sync.sync_live_requests_once(store, _auth(binding))

    assert result["synced"] == 0
    assert captured == []
    dead_letters = store.list_live_request_outbox_dead_letters(**binding)
    assert len(dead_letters) == 1
    assert dead_letters[0]["stream_sequence"] == original_sequence
    assert dead_letters[0]["dead_letter_reason"] == "payload_snapshot_missing"


@pytest.mark.parametrize(
    ("tamper", "expected_reason"),
    [
        ("missing_harness", "payload_snapshot_incomplete"),
        ("extra_field", "payload_snapshot_unexpected_fields"),
        ("source_mismatch", "payload_snapshot_source_mismatch"),
        ("envelope_source_mismatch", "payload_source_binding_mismatch"),
    ],
)
def test_rehashed_noncanonical_snapshot_is_dead_lettered_before_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
    expected_reason: str,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    row = _event_row(store)
    original_sequence = int(row["stream_sequence"])
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
    monkeypatch.setattr(live_request_sync, "_post_sync_events", _accepting_transport(captured))

    result = live_request_sync.sync_live_requests_once(store, _auth(binding))

    assert result["synced"] == 0
    assert captured == []
    dead_letters = store.list_live_request_outbox_dead_letters(**binding)
    assert len(dead_letters) == 1
    assert dead_letters[0]["stream_sequence"] == original_sequence
    assert dead_letters[0]["dead_letter_reason"] == expected_reason
