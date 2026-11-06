from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from codex_plugin_scanner.guard.runtime import native_workspace_review_replay as replay
from codex_plugin_scanner.guard.runtime import native_workspace_review_replay_delivery as replay_delivery
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_review_event_outbox import _all_events
from tests.test_native_workspace_review_replay import (
    _accepted_event,
    _binding,
    _connect,
    _native_context,
    _ReplayStore,
    _request,
)


@pytest.mark.parametrize(
    ("native_context_committed", "marker_write_fails"),
    [(False, False), (True, False), (True, True)],
)
def test_accepted_server_result_completes_replay_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_context_committed: bool,
    marker_write_fails: bool,
) -> None:
    store = GuardStore(tmp_path / "guard")
    delivery_binding = _connect(store)
    store.add_approval_request(_request("request-sync-accepted"), "2026-09-27T12:00:00+00:00")
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    native_context = _native_context()
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: native_context)
    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1

    base_event = _accepted_event("request-sync-accepted")
    with store._connect() as connection:
        marker_row = connection.execute(
            "select state_key from sync_state where state_key like ?",
            ("guard_cloud_review_native_workspace_review_replay:default:request:%",),
        ).fetchone()
    assert marker_row is not None
    marker_key = str(marker_row["state_key"])
    original_set_sync_payload = store.set_sync_payload

    if marker_write_fails:

        def fail_accepted_marker(key: str, payload: object, now: str) -> None:
            if key == marker_key and isinstance(payload, dict) and payload.get("accepted") is True:
                raise OSError("marker write failed")
            original_set_sync_payload(key, cast(dict[str, object], payload), now)

        monkeypatch.setattr(store, "set_sync_payload", fail_accepted_marker)

    marker_states_at_ack: list[object] = []
    original_acknowledge = store.acknowledge_review_events

    def acknowledge_before_marker_check(sequences: object, **kwargs: object) -> int:
        marker_payload = store.get_sync_payload(marker_key)
        marker_states_at_ack.append(cast(dict[str, object], marker_payload or {}).get("accepted"))
        return original_acknowledge(cast(list[int], sequences), **cast(dict[str, str], kwargs))

    monkeypatch.setattr(store, "acknowledge_review_events", acknowledge_before_marker_check)

    def projected(
        _store: object,
        *,
        outbox_row: dict[str, object],
        **_kwargs: object,
    ) -> tuple[int, dict[str, object]]:
        sequence = cast(int, outbox_row["sequence"])
        event = {
            **base_event,
            "eventId": str(outbox_row["event_id"]),
            "eventType": "request_created",
            "localEventSequence": sequence,
            "localStreamSequence": sequence,
        }
        return sequence, event

    monkeypatch.setattr(cloud_review_sync, "project_cloud_review_event", projected)

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        assert path == "/api/guard/review/v2/events:batch"
        events = cast(list[dict[str, object]], payload["events"])
        results = [{"eventId": event["eventId"], "status": "accepted"} for event in events]
        if native_context_committed:
            for result in results:
                result["nativeContextCommitted"] = True
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": len(events),
            "rejected": 0,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    cloud_review_sync.sync_cloud_review_events_once(store, auth)

    marker = cast(dict[str, object], store.get_sync_payload(marker_key))
    expected_accepted = native_context_committed and not marker_write_fails
    assert marker.get("accepted", False) is expected_accepted
    if marker_write_fails or not native_context_committed:
        assert marker_states_at_ack == []
    else:
        assert marker_states_at_ack and all(
            state is (True if native_context_committed else None) for state in marker_states_at_ack
        )
    assert marker["authority_generation"] == native_context["authority_generation"]
    expected_depth = 0 if native_context_committed and not marker_write_fails else 2
    assert (
        store.review_event_outbox_status(now="2026-09-27T12:00:01+00:00", **delivery_binding)["depth"] == expected_depth
    )


def test_marker_write_failure_recovers_from_authenticated_duplicate_without_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    delivery_binding = _connect(store)
    store.add_approval_request(_request("request-duplicate-recovery"), "2026-09-27T12:00:00+00:00")
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    native_context = _native_context()
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: native_context)
    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1

    with store._connect() as connection:
        marker_row = connection.execute(
            "select state_key from sync_state where state_key like ?",
            ("guard_cloud_review_native_workspace_review_replay:default:request:%",),
        ).fetchone()
    assert marker_row is not None
    marker_key = str(marker_row["state_key"])
    original_set_sync_payload = store.set_sync_payload
    fail_once = True

    def fail_first_accepted_marker(key: str, payload: object, now: str) -> None:
        nonlocal fail_once
        if fail_once and key == marker_key and isinstance(payload, dict) and payload.get("accepted") is True:
            fail_once = False
            raise OSError("marker write failed")
        original_set_sync_payload(key, cast(dict[str, object], payload), now)

    monkeypatch.setattr(store, "set_sync_payload", fail_first_accepted_marker)

    def projected(
        _store: object,
        *,
        outbox_row: dict[str, object],
        **_kwargs: object,
    ) -> tuple[int, dict[str, object]]:
        sequence = cast(int, outbox_row["sequence"])
        return sequence, {
            **_accepted_event("request-duplicate-recovery"),
            "eventId": str(outbox_row["event_id"]),
            "eventType": "request_created",
            "localEventSequence": sequence,
            "localStreamSequence": sequence,
        }

    monkeypatch.setattr(cloud_review_sync, "project_cloud_review_event", projected)
    responses = iter(("accepted", "duplicate"))

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        assert path == "/api/guard/review/v2/events:batch"
        events = cast(list[dict[str, object]], payload["events"])
        status = next(responses)
        results = [{"eventId": event["eventId"], "status": status} for event in events]
        if status == "accepted":
            for result in results:
                result["nativeContextCommitted"] = True
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": len(events),
            "rejected": 0,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    cloud_review_sync.sync_cloud_review_events_once(store, auth)
    with store._connect() as connection:
        connection.execute("update guard_review_outbox_events set next_attempt_at = null where acknowledged_at is null")

    cloud_review_sync.sync_cloud_review_events_once(store, auth)

    marker = cast(dict[str, object], store.get_sync_payload(marker_key))
    assert marker.get("accepted") is True
    assert store.review_event_outbox_status(now="2026-09-27T12:00:01+00:00", **delivery_binding)["depth"] == 0


@pytest.mark.parametrize(
    ("duplicate_committed", "expected_depth"),
    [(False, 2), (True, 0)],
)
def test_crash_after_remote_acceptance_requires_duplicate_commit_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    duplicate_committed: bool,
    expected_depth: int,
) -> None:
    store = GuardStore(tmp_path / "guard")
    delivery_binding = _connect(store)
    store.add_approval_request(_request("request-crash-window"), "2026-09-27T12:00:00+00:00")
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    native_context = _native_context()
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: native_context)
    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1

    def projected(
        _store: object,
        *,
        outbox_row: dict[str, object],
        **_kwargs: object,
    ) -> tuple[int, dict[str, object]]:
        sequence = cast(int, outbox_row["sequence"])
        return sequence, {
            **_accepted_event("request-crash-window"),
            "eventId": str(outbox_row["event_id"]),
            "eventType": "request_created",
            "localEventSequence": sequence,
            "localStreamSequence": sequence,
        }

    monkeypatch.setattr(cloud_review_sync, "project_cloud_review_event", projected)
    responses = iter(("accepted", "duplicate"))

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        assert path == "/api/guard/review/v2/events:batch"
        events = cast(list[dict[str, object]], payload["events"])
        status = next(responses)
        results = [{"eventId": event["eventId"], "status": status} for event in events]
        if status == "accepted" or (status == "duplicate" and duplicate_committed):
            for result in results:
                result["nativeContextCommitted"] = True
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": len(events),
            "rejected": 0,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    original_mark = cloud_review_sync._mark_accepted_replay_contexts

    def crash_before_marker(*_args: object) -> bool:
        raise RuntimeError("simulated process loss")

    monkeypatch.setattr(
        cloud_review_sync,
        "_mark_accepted_replay_contexts",
        crash_before_marker,
    )
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    with pytest.raises(RuntimeError, match="simulated process loss"):
        cloud_review_sync.sync_cloud_review_events_once(store, auth)
    monkeypatch.setattr(cloud_review_sync, "_mark_accepted_replay_contexts", original_mark)
    with store._connect() as connection:
        connection.execute("update guard_review_outbox_events set next_attempt_at = null where acknowledged_at is null")

    cloud_review_sync.sync_cloud_review_events_once(store, auth)

    assert (
        store.review_event_outbox_status(now="2026-09-27T12:00:01+00:00", **delivery_binding)["depth"] == expected_depth
    )


@pytest.mark.parametrize(
    ("marker_read_fails", "expected_ready"),
    [(False, True), (True, False)],
)
def test_snapshot_requeued_markerless_attestation_reconstructs_or_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    marker_read_fails: bool,
    expected_ready: bool,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = cast(dict[str, str], cast(object, _connect(store)))
    event = {
        **_accepted_event("request-markerless-replay"),
        "eventId": "markerless-replay-event",
        "eventType": "request_created",
        "eventPayloadJson": json.dumps(
            {
                "eventType": "review.request.snapshot_requeued",
                "requestSnapshot": {"request_id": "request-markerless-replay"},
            }
        ),
    }
    if marker_read_fails:

        def fail_marker_read(*_args: object) -> tuple[str, dict[str, object] | None]:
            raise OSError("marker read")

        monkeypatch.setattr(replay, "_request_marker", fail_marker_read)

    assert (
        replay_delivery._mark_accepted_replay_contexts(
            store,
            [event],
            [{"accepted": True, "nativeContextCommitted": True}],
            binding,
        )
        is expected_ready
    )
    if expected_ready:
        with store._connect() as connection:
            row = connection.execute(
                "select payload_json from sync_state where state_key like ? and state_key not like '%:commit:%'",
                ("guard_cloud_review_native_workspace_review_replay:default:request:%",),
            ).fetchone()
        assert row is not None
        assert json.loads(row["payload_json"])["accepted"] is True


def test_malformed_snapshot_requeued_event_cannot_ack_as_noop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    delivery_binding = _connect(store)
    store.add_approval_request(_request("request-malformed-replay"), "2026-09-27T12:00:00+00:00")
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    native_context = _native_context()
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: native_context)
    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1

    def projected(
        _store: object,
        *,
        outbox_row: dict[str, object],
        **_kwargs: object,
    ) -> tuple[int, dict[str, object]]:
        sequence = cast(int, outbox_row["sequence"])
        event_payload = (
            {"eventType": "review.request.snapshot_requeued"}
            if outbox_row.get("event_type") == "review.request.snapshot_requeued"
            else {"eventType": "review.request.created", "requestSnapshot": {}}
        )
        return sequence, {
            **_accepted_event("request-malformed-replay"),
            "eventId": str(outbox_row["event_id"]),
            "eventType": "request_created",
            "eventPayloadJson": json.dumps(event_payload),
            "localEventSequence": sequence,
            "localStreamSequence": sequence,
        }

    monkeypatch.setattr(cloud_review_sync, "project_cloud_review_event", projected)

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        assert path == "/api/guard/review/v2/events:batch"
        events = cast(list[dict[str, object]], payload["events"])
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": len(events),
            "rejected": 0,
            "results": [
                {"eventId": event["eventId"], "status": "accepted", "nativeContextCommitted": True} for event in events
            ],
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    cloud_review_sync.sync_cloud_review_events_once(store, auth)

    status = store.review_event_outbox_status(now="2026-09-27T12:00:01+00:00", **delivery_binding)
    assert status["depth"] == 1
    assert status["quarantined_depth"] == 1
    with store._connect() as connection:
        row = connection.execute(
            "select binding_status, quarantine_reason from guard_review_outbox_events "
            "where binding_status = 'quarantined' and acknowledged_at is null"
        ).fetchone()
    assert row is not None
    assert row["binding_status"] == "quarantined"
    assert row["quarantine_reason"] == "native_replay_payload_invalid"


def test_real_store_rotation_after_snapshot_compaction_reuses_frozen_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    delivery_binding = _connect(store)
    store.add_approval_request(
        replace(
            _request("request-rotation"),
            launch_target="chrome-devtools navigate_page unknown",
            browser_intent={"intent": "browser.navigation", "target_domain": "hol.org"},
        ),
        "2026-09-27T12:00:00+00:00",
    )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    native_context = _native_context()
    captured: list[dict[str, object]] = []

    def context(
        _store: object,
        _home: Path,
        _request_id: str,
        request_snapshot: dict[str, object],
    ) -> dict[str, object]:
        captured.append(request_snapshot)
        return native_context

    monkeypatch.setattr(replay, "build_native_workspace_review_context", context)
    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1
    assert captured
    frozen_snapshot = captured[0]

    with store._connect() as connection:
        marker_row = connection.execute(
            "select state_key from sync_state where state_key like ?",
            ("guard_cloud_review_native_workspace_review_replay:default:request:%",),
        ).fetchone()
    assert marker_row is not None
    marker_key = str(marker_row["state_key"])
    marker = cast(dict[str, object], store.get_sync_payload(marker_key))
    assert marker["request_snapshot"] == frozen_snapshot
    assert (
        replay.mark_native_workspace_review_context_accepted(
            cast(GuardStore, cast(object, store)),
            event={**_accepted_event("request-rotation"), "eventId": "replay-event-1"},
            binding=binding,
        )
        is True
    )
    marker["next_probe_at"] = "2000-01-01T00:00:00+00:00"
    store.set_sync_payload(marker_key, marker, "2026-09-27T12:00:01+00:00")

    sequences = [int(row["stream_sequence"]) for row in _all_events(store)]
    assert store.acknowledge_review_events(sequences, **delivery_binding) == len(sequences)
    assert store.list_review_event_snapshots("request-rotation") == []

    rotated = {**native_context, "authority_generation": 4, "authority_record_digest": "f" * 64}

    def rotated_context(
        _store: object,
        _home: Path,
        _request_id: str,
        request_snapshot: dict[str, object],
    ) -> dict[str, object]:
        captured.append(request_snapshot)
        return rotated

    monkeypatch.setattr(replay, "build_native_workspace_review_context", rotated_context)
    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1
    assert captured[-1] == frozen_snapshot
    rows = _all_events(store)
    assert any(row["event_type"] == "review.request.snapshot_requeued" for row in rows)
    assert any(row["local_request_id"] == "request-rotation" for row in rows)


def test_identity_mismatch_never_lists_or_reassigns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, ["request-1"])
    store.binding["oauth_subject_hash"] = "c" * 64
    monkeypatch.setattr(replay, "build_native_workspace_review_context", pytest.fail)

    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=_binding()) == 0
    assert store.list_calls == 0
    assert store.requeue_calls == []
