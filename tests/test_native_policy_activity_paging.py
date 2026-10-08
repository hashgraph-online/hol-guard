from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.runtime.native_activity_projection import (
    eligibility_from_store,
    native_activity_coverage,
    project_native_policy_activity,
    resolve_native_activity_eligibility,
    sendable_guard_cloud_events,
)
from codex_plugin_scanner.guard.schemas.guard_event_v1 import GuardEventV1
from codex_plugin_scanner.guard.store import GuardStore

_WORKSPACE_A = "22222222-2222-4222-8222-222222222222"
_WORKSPACE_B = "55555555-5555-4555-8555-555555555555"
_INSTALLATION = "33333333-3333-4333-8333-333333333333"


def _policy_receipt(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "request-1",
        "request_digest": "a" * 64,
        "harness": "claude-code",
        "event_name": "PostToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": "b" * 64,
        "rule_digest": "c" * 64,
        "runtime_identity": "d" * 64,
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_clean_output",
        "workspace_bound": True,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 750,
    }
    value.update(overrides)
    value["decision_id"] = hashlib.sha256(canonical_receipt_bytes(value)).hexdigest()
    validated = validate_native_decision_receipt(value)
    assert validated is not None
    return validated


def _activity_store(tmp_path: Path, *, sync: bool, queue_limit: int = 1000) -> GuardStore:
    home = tmp_path / "activity-home"
    home.mkdir(parents=True)
    (home / "config.toml").write_text(f"sync = {'true' if sync else 'false'}\n")
    return GuardStore(home, guard_event_queue_limit=queue_limit)


def _bind(store: GuardStore, workspace: str = _WORKSPACE_A) -> dict[str, str]:
    store.set_sync_payload(
        "oauth_local_credentials",
        {"grant_id": "grant-1", "workspace_id": workspace, "machine_id": "machine-1"},
        "2026-10-04T05:00:00+00:00",
    )
    with store._connect() as connection:
        updated = connection.execute(
            "update guard_devices set installation_id = ? where device_key = 'local-device'",
            (_INSTALLATION,),
        )
        assert updated.rowcount == 1
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    return binding


def _eligibility(store: GuardStore, *, sync_enabled: bool | None = None):
    if sync_enabled is None:
        return eligibility_from_store(
            store,
            managed_policy_state=ManagedPolicyState(status="absent", source="test"),
        )
    binding = store.get_review_event_oauth_binding()
    return resolve_native_activity_eligibility(binding, sync_enabled=sync_enabled)


def _events(store: GuardStore) -> list[dict[str, object]]:
    return store.list_guard_events_v1(limit=20)


def test_held_native_activity_page_does_not_block_a_later_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    store = _activity_store(tmp_path, sync=False, queue_limit=300)
    for index in range(200):
        store.add_guard_event_v1(
            GuardEventV1(
                event_id=f"native-{index:03d}",
                idempotency_key=f"native-activity:held:{index:03d}",
                event_type="receipt.created",
                source="edge",
                occurred_at="2026-10-04T00:00:00+00:00",
                payload={"receiptKind": "native_policy_decision", "activity": {"decision": "deny"}},
            )
        )
    store.add_guard_event_v1(
        GuardEventV1(
            event_id="later-receipt",
            idempotency_key="receipt.created:later",
            event_type="receipt.created",
            source="edge",
            occurred_at="2026-10-04T00:00:01+00:00",
            payload={"receiptId": "later-receipt"},
        )
    )
    posted: list[str] = []

    def capture_post(*, request: object, timeout_seconds: int, retry_timeout_seconds: int) -> dict[str, object]:
        del timeout_seconds, retry_timeout_seconds
        raw = getattr(request, "data", None)
        assert isinstance(raw, bytes)
        body = json.loads(raw.decode("utf-8"))
        events = body["events"]
        assert isinstance(events, list)
        statuses: list[dict[str, object]] = []
        for event in events:
            assert isinstance(event, dict)
            event_id = str(event["eventId"])
            posted.append(event_id)
            statuses.append({"status": "accepted", "eventId": event_id})
        return {"statuses": statuses}

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", capture_post)
    result = runner.sync_guard_events(
        store,
        auth_context={
            "access_token": "synthetic-test-token",
            "sync_url": "http://127.0.0.1:9/api/guard/receipts/sync",
        },
    )
    assert posted == ["later-receipt"]
    assert result["accepted"] == 1
    pending = store.list_guard_events_v1(uploaded=False, limit=300)
    assert [event["event_id"] for event in pending] == [f"native-{index:03d}" for index in range(200)]


def test_mixed_upload_page_reaches_later_receipts_without_skipping_an_omitted_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    store = _activity_store(tmp_path, sync=False, queue_limit=300)
    for index in range(198):
        store.add_guard_event_v1(
            GuardEventV1(
                event_id=f"native-{index:03d}",
                idempotency_key=f"native-activity:held:{index:03d}",
                event_type="receipt.created",
                source="edge",
                occurred_at="2026-10-04T00:00:00+00:00",
                payload={"receiptKind": "native_policy_decision", "activity": {"decision": "deny"}},
            )
        )
    store.add_guard_event_v1(
        GuardEventV1(
            event_id="native-198",
            idempotency_key="receipt.created:omitted",
            event_type="receipt.created",
            source="edge",
            occurred_at="2026-10-04T00:00:00+00:00",
            payload={"receiptId": "omitted"},
        )
    )
    store.add_guard_event_v1(
        GuardEventV1(
            event_id="native-199",
            idempotency_key="receipt.created:accepted-in-page",
            event_type="receipt.created",
            source="edge",
            occurred_at="2026-10-04T00:00:00+00:00",
            payload={"receiptId": "accepted-in-page"},
        )
    )
    for index in range(40):
        store.add_guard_event_v1(
            GuardEventV1(
                event_id=f"later-{index:02d}",
                idempotency_key=f"receipt.created:later:{index:02d}",
                event_type="receipt.created",
                source="edge",
                occurred_at="2026-10-04T00:00:01+00:00",
                payload={"receiptId": f"later-{index:02d}"},
            )
        )
    batches: list[list[str]] = []

    def capture_post(*, request: object, timeout_seconds: int, retry_timeout_seconds: int) -> dict[str, object]:
        del timeout_seconds, retry_timeout_seconds
        raw = getattr(request, "data", None)
        assert isinstance(raw, bytes)
        body = json.loads(raw.decode("utf-8"))
        events = body["events"]
        assert isinstance(events, list)
        event_ids = [str(event["eventId"]) for event in events if isinstance(event, dict)]
        batches.append(event_ids)
        statuses = [{"status": "accepted", "eventId": event_id} for event_id in event_ids if event_id != "native-198"]
        return {"statuses": statuses}

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", capture_post)
    result = runner.sync_guard_events(
        store,
        auth_context={
            "access_token": "synthetic-test-token",
            "sync_url": "http://127.0.0.1:9/api/guard/receipts/sync",
        },
    )
    assert batches[0] == ["native-198", "native-199"]
    assert batches[1] == ["native-198", *[f"later-{index:02d}" for index in range(40)]]
    assert result["accepted"] == 41
    pending = store.list_guard_events_v1(uploaded=False, limit=300)
    pending_ids = [event["event_id"] for event in pending]
    assert pending_ids == [f"native-{index:03d}" for index in range(199)]


def test_omitted_ready_event_at_the_front_of_a_full_page_stops_that_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.runtime import runner

    store = _activity_store(tmp_path, sync=False, queue_limit=300)
    for index in range(205):
        store.add_guard_event_v1(
            GuardEventV1(
                event_id=f"event-{index:03d}",
                idempotency_key=f"receipt.created:{index:03d}",
                event_type="receipt.created",
                source="edge",
                occurred_at="2026-10-04T00:00:00+00:00",
                payload={"receiptId": f"event-{index:03d}"},
            )
        )
    batches: list[list[str]] = []

    def capture_post(*, request: object, timeout_seconds: int, retry_timeout_seconds: int) -> dict[str, object]:
        del timeout_seconds, retry_timeout_seconds
        raw = getattr(request, "data", None)
        assert isinstance(raw, bytes)
        body = json.loads(raw.decode("utf-8"))
        events = body["events"]
        assert isinstance(events, list)
        event_ids = [str(event["eventId"]) for event in events if isinstance(event, dict)]
        batches.append(event_ids)
        statuses = [{"status": "accepted", "eventId": event_id} for event_id in event_ids if event_id != "event-000"]
        return {"statuses": statuses}

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", capture_post)
    result = runner.sync_guard_events(
        store,
        auth_context={
            "access_token": "synthetic-test-token",
            "sync_url": "http://127.0.0.1:9/api/guard/receipts/sync",
        },
    )

    assert batches == [[f"event-{index:03d}" for index in range(200)]]
    assert result["accepted"] == 199
    pending_ids = [event["event_id"] for event in store.list_guard_events_v1(uploaded=False, limit=300)]
    assert pending_ids == ["event-000", *[f"event-{index:03d}" for index in range(200, 205)]]


def test_second_binding_change_still_queues_the_current_native_activity(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True, queue_limit=2)
    _bind(store)
    eligibility = _eligibility(store, sync_enabled=True)
    project_native_policy_activity(store, eligibility=eligibility, now="2020-01-01T00:00:00+00:00")
    store.record_native_decision_receipt(_policy_receipt(request_id="first-request"))
    assert project_native_policy_activity(store, eligibility=eligibility).projected == 1
    workspace_c = "66666666-6666-4666-8666-666666666666"
    for workspace, request_id in ((_WORKSPACE_B, "second-request"), (workspace_c, "third-request")):
        _bind(store, workspace)
        moved = _eligibility(store, sync_enabled=True)
        project_native_policy_activity(store, eligibility=moved)
        store.record_native_decision_receipt(_policy_receipt(request_id=request_id))
        projected = project_native_policy_activity(store, eligibility=moved)
        assert projected.projected == 1
        assert projected.dropped == 0
    events = _events(store)
    assert len(events) == 3
    assert all(event["uploaded_at"] is None for event in events)
    ready = sendable_guard_cloud_events(store, events, eligibility=_eligibility(store, sync_enabled=True))
    assert len(ready) == 1
    assert workspace_c in str(ready[0]["idempotency_key"])
    assert native_activity_coverage(store)["quarantined"] == 2
    store.add_guard_event_v1(
        GuardEventV1(
            event_id="ordinary-after-rebind",
            idempotency_key="receipt.created:ordinary-after-rebind",
            event_type="receipt.created",
            source="edge",
            occurred_at="2026-10-04T00:00:02+00:00",
            payload={"receiptId": "ordinary-after-rebind"},
        )
    )
    stored_ids = [event["event_id"] for event in _events(store)]
    assert "ordinary-after-rebind" in stored_ids
