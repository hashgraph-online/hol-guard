from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import fail_closed_managed_policy
from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.runtime import native_activity_projection
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


def test_native_activity_is_not_uploaded_when_sync_is_off(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=False)
    _bind(store)
    store.record_native_decision_receipt(_policy_receipt())
    eligibility = _eligibility(store)
    assert eligibility.reason == "sync_disabled"
    projected = project_native_policy_activity(store, eligibility=eligibility)
    assert projected.projected == 0
    assert _events(store) == []
    assert native_activity_coverage(store)["complete"] is False


def test_opted_in_native_activity_projects_without_review_consent(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True)
    _bind(store)
    eligibility = _eligibility(store)
    assert eligibility.sync_enabled is True
    assert (
        project_native_policy_activity(
            store,
            eligibility=eligibility,
            now="2020-01-01T00:00:00+00:00",
        ).projected
        == 0
    )
    receipt = _policy_receipt(observe_mode=True)
    store.record_native_decision_receipt(receipt)
    projected = project_native_policy_activity(store, eligibility=eligibility)
    assert projected.projected == 1
    events = _events(store)
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "receipt.created"
    assert event["idempotency_key"] == (f"native-activity:{_WORKSPACE_A}:{_INSTALLATION}:hook:{receipt['decision_id']}")
    body = json.dumps(event["payload"], sort_keys=True)
    assert "native_policy_decision" in body
    assert '"decision": "observed"' in body
    assert receipt["request_id"] not in body
    assert "command" not in body
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    assert project_native_policy_activity(store, eligibility=eligibility).projected == 0
    assert len(_events(store)) == 1
    assert native_activity_coverage(store)["complete"] is False
    store.mark_guard_events_v1_uploaded([str(event["event_id"])], "2026-10-04T06:00:00+00:00")
    coverage = native_activity_coverage(store)
    assert coverage["accepted"] == 1
    assert coverage["complete"] is True


def test_opted_in_prompt_receipt_projects_without_approval_authority(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True)
    _bind(store)
    eligibility = _eligibility(store, sync_enabled=True)
    assert (
        project_native_policy_activity(
            store,
            eligibility=eligibility,
            now="2020-01-01T00:00:00+00:00",
        ).projected
        == 0
    )
    receipt = _policy_receipt(
        event_name="UserPromptSubmit",
        model_output_action="not_applicable",
        payload_kind="inline",
        request_id="prompt-request",
        decision="deny",
        policy_action="block",
        reason_code="native_prompt_blocked",
    )
    store.record_native_decision_receipt(receipt)
    projected = project_native_policy_activity(store, eligibility=eligibility)
    assert projected.projected == 1
    events = _events(store)
    assert len(events) == 1
    assert events[0]["idempotency_key"] == (
        f"native-activity:{_WORKSPACE_A}:{_INSTALLATION}:prompt:{receipt['decision_id']}"
    )
    body = json.dumps(events[0]["payload"], sort_keys=True)
    assert '"sourceKind": "prompt"' in body
    assert '"receiptKind": "native_policy_decision"' in body
    assert receipt["request_id"] not in body
    assert "command" not in body
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    with store._connect() as connection:
        approvals = connection.execute("select count(*) from approval_requests").fetchone()
        prompt_rows = connection.execute("select count(*) from native_prompt_decision_receipts").fetchone()
    assert approvals is not None and int(approvals[0]) == 0
    assert prompt_rows is not None and int(prompt_rows[0]) == 1


def test_native_activity_backlog_is_withheld_until_authorized(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True)
    _bind(store)
    eligibility = _eligibility(store)
    store.record_native_decision_receipt(_policy_receipt(request_id="old-request"))
    withheld = project_native_policy_activity(
        store,
        eligibility=eligibility,
        now="2099-01-01T00:00:00+00:00",
    )
    assert withheld.withheld == 1
    assert withheld.projected == 0
    assert _events(store) == []
    assert native_activity_coverage(store)["complete"] is False

    authorized = _activity_store(tmp_path / "authorized", sync=True)
    _bind(authorized)
    authorized.record_native_decision_receipt(_policy_receipt(request_id="first-old"))
    authorized.record_native_decision_receipt(_policy_receipt(request_id="second-old"))
    authorized.set_sync_payload(
        "native_activity_backfill_authorization",
        {"installationId": _INSTALLATION, "limit": 1, "workspaceId": _WORKSPACE_A},
        "2099-01-01T00:00:01+00:00",
    )
    backfilled = project_native_policy_activity(
        authorized,
        eligibility=_eligibility(authorized),
        now="2099-01-01T00:00:02+00:00",
    )
    assert backfilled.projected == 1
    assert backfilled.withheld == 1
    assert len(_events(authorized)) == 1
    assert (
        project_native_policy_activity(
            authorized,
            eligibility=_eligibility(authorized),
            now="2099-01-01T00:00:03+00:00",
        ).projected
        == 0
    )


def test_backfill_reduction_counts_only_rows_this_projection_consumed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _activity_store(tmp_path, sync=True)
    _bind(store)
    store.record_native_decision_receipt(_policy_receipt(request_id="counted-old"))
    store.set_sync_payload(
        "native_activity_backfill_authorization",
        {"installationId": _INSTALLATION, "limit": 5, "workspaceId": _WORKSPACE_A},
        "2099-01-01T00:00:01+00:00",
    )
    original = native_activity_projection._backfill_remaining
    calls = {"count": 0}

    def later_writer_raises_the_stored_limit(store: GuardStore, eligibility: object) -> int:
        calls["count"] += 1
        if calls["count"] == 1:
            return original(store, eligibility)  # type: ignore[arg-type]
        return 50

    monkeypatch.setattr(
        native_activity_projection,
        "_backfill_remaining",
        later_writer_raises_the_stored_limit,
    )

    projected = project_native_policy_activity(
        store,
        eligibility=_eligibility(store),
        now="2099-01-01T00:00:02+00:00",
    )

    assert projected.projected == 1
    assert calls["count"] == 1
    remaining = store.get_sync_payload("native_activity_backfill_authorization")
    assert isinstance(remaining, dict)
    assert remaining["limit"] == 4


def test_quarantined_native_activity_does_not_consume_the_upload_queue(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True, queue_limit=1)
    _bind(store)
    eligibility = _eligibility(store, sync_enabled=True)
    project_native_policy_activity(store, eligibility=eligibility, now="2020-01-01T00:00:00+00:00")
    store.record_native_decision_receipt(_policy_receipt(request_id="bound-request"))
    assert project_native_policy_activity(store, eligibility=eligibility).projected == 1
    _bind(store, _WORKSPACE_B)
    moved = _eligibility(store, sync_enabled=True)
    quarantined = project_native_policy_activity(store, eligibility=moved)
    assert quarantined.quarantined == 1
    store.record_native_decision_receipt(_policy_receipt(request_id="current-request"))
    projected = project_native_policy_activity(store, eligibility=moved)
    assert projected.projected == 1
    assert projected.dropped == 0
    events = _events(store)
    assert len(events) == 2
    assert all(event["uploaded_at"] is None for event in events)
    ready = sendable_guard_cloud_events(store, events, eligibility=moved)
    assert len(ready) == 1
    assert _WORKSPACE_B in str(ready[0]["idempotency_key"])
    coverage = native_activity_coverage(store)
    assert coverage["quarantined"] == 1
    assert coverage["complete"] is False


def test_changed_workspace_quarantines_native_activity_without_rekeying(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True)
    _bind(store)
    eligibility = _eligibility(store, sync_enabled=True)
    project_native_policy_activity(store, eligibility=eligibility, now="2020-01-01T00:00:00+00:00")
    receipt = _policy_receipt(request_id="bound-request")
    store.record_native_decision_receipt(receipt)
    assert project_native_policy_activity(store, eligibility=eligibility).projected == 1
    original_key = f"native-activity:{_WORKSPACE_A}:{_INSTALLATION}:hook:{receipt['decision_id']}"
    _bind(store, _WORKSPACE_B)
    moved = _eligibility(store, sync_enabled=True)
    quarantined = project_native_policy_activity(store, eligibility=moved)
    assert quarantined.quarantined == 1
    events = _events(store)
    assert events[0]["idempotency_key"] == original_key
    assert _WORKSPACE_B not in str(events[0]["idempotency_key"])
    ready = sendable_guard_cloud_events(store, events, eligibility=moved)
    assert ready == []
    assert native_activity_coverage(store)["complete"] is False


def test_native_activity_queue_overflow_is_a_coverage_gap(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True, queue_limit=1)
    _bind(store)
    eligibility = _eligibility(store, sync_enabled=True)
    project_native_policy_activity(store, eligibility=eligibility, now="2020-01-01T00:00:00+00:00")
    store.add_guard_event_v1(
        GuardEventV1(
            event_id="guard-event-filler",
            idempotency_key="receipt.created:filler",
            event_type="receipt.created",
            source="edge",
            occurred_at="2026-10-04T00:00:00+00:00",
            payload={"receiptId": "filler"},
        )
    )
    store.record_native_decision_receipt(_policy_receipt(request_id="queued-request"))
    dropped = project_native_policy_activity(store, eligibility=eligibility)
    assert dropped.dropped == 1
    assert [event["idempotency_key"] for event in _events(store)] == ["receipt.created:filler"]
    coverage = native_activity_coverage(store)
    assert coverage["dropped"] == 1
    assert coverage["complete"] is False


def test_managed_policy_can_refuse_native_activity_upload(tmp_path: Path) -> None:
    store = _activity_store(tmp_path, sync=True)
    _bind(store)
    store.record_native_decision_receipt(_policy_receipt(request_id="managed-request"))
    eligibility = eligibility_from_store(
        store,
        managed_policy_state=ManagedPolicyState(
            status="tampered",
            source="test",
            policy=fail_closed_managed_policy(),
        ),
    )
    assert eligibility.sync_enabled is False
    assert project_native_policy_activity(store, eligibility=eligibility).projected == 0
    assert _events(store) == []
