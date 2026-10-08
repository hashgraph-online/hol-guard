from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import fail_closed_managed_policy
from codex_plugin_scanner.guard.native_decision_receipt import (
    canonical_receipt_bytes,
    validate_native_decision_receipt,
)
from codex_plugin_scanner.guard.runtime import native_activity_projection
from codex_plugin_scanner.guard.runtime import native_workspace_review as native
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY
from codex_plugin_scanner.guard.runtime.native_activity_projection import (
    eligibility_from_store,
    native_activity_coverage,
    project_native_policy_activity,
    resolve_native_activity_eligibility,
    sendable_guard_cloud_events,
)
from codex_plugin_scanner.guard.schemas.guard_event_v1 import GuardEventV1
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_native_workspace_review import NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX
from tests.guard_exact_cloud_review_support import add_review_request, review_request

_WORKSPACE_A = "22222222-2222-4222-8222-222222222222"
_WORKSPACE_B = "55555555-5555-4555-8555-555555555555"
_INSTALLATION = "33333333-3333-4333-8333-333333333333"


def _receipt() -> dict[str, object]:
    fields = (
        "claim_id",
        "workspace_binding",
        "device_binding",
        "installation_binding",
        "scope_binding",
        "request_binding",
        "action_binding",
        "intent_binding",
        "revision_binding",
        "policy_binding",
        "retry_scope_binding",
        "request_snapshot_digest",
        "authority_record_digest",
        "envelope_digest",
    )
    return {
        **{field: hashlib.sha256(field.encode()).hexdigest() for field in fields},
        "request_id": "request-1",
        "decision": "allow",
        "status": "verified",
        "replayed": False,
    }


def _store(tmp_path: Path) -> tuple[GuardStore, dict[str, object]]:
    store = GuardStore(tmp_path / "guard-home")
    add_review_request(store, review_request("request-1"))
    request = store.get_approval_request("request-1")
    assert isinstance(request, dict)
    return store, request


def _resolve(store: GuardStore, request: dict[str, object], receipt: dict[str, object]) -> dict[str, object]:
    return store.resolve_native_workspace_review_request(
        "request-1",
        resolution_action="allow",
        expected_request=request,
        resolved_at="2026-09-27T00:00:00+00:00",
        native_replayed=receipt.get("replayed") is True,
        native_receipt=receipt,
    )


def test_native_receipt_and_resolution_commit_together(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    receipt = _receipt()
    assert _resolve(store, request, receipt)["resolved"] is True
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == receipt
    resolved = store.get_approval_request("request-1")
    assert resolved is not None and resolved["resolution_action"] == "allow"


def test_receipt_write_failure_rolls_back_resolution_then_replay_completes(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    with store._connect() as connection:
        connection.execute(
            """create trigger fail_native_receipt before insert on sync_state
            when NEW.state_key like 'native_workspace_review.receipt:%'
            begin select raise(abort, 'injected receipt write failure'); end"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected receipt write failure"):
        _resolve(store, request, _receipt())
    pending = store.get_approval_request("request-1")
    assert pending is not None and pending["status"] == "pending"
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") is None
    with store._connect() as connection:
        connection.execute("drop trigger fail_native_receipt")
    replay = {**_receipt(), "status": "replayed", "replayed": True}
    assert _resolve(store, request, replay)["resolved"] is True
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == replay


def test_renewed_consumed_decision_preserves_original_application_receipt(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    original = _receipt()
    assert _resolve(store, request, original)["resolved"] is True
    renewed = {
        **original,
        "status": "replayed",
        "replayed": True,
        "authority_record_digest": "a" * 64,
        "envelope_digest": "b" * 64,
    }
    result = _resolve(store, request, renewed)
    assert result["resolved"] is True and result["replayed"] is True
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == original


@pytest.mark.parametrize("field", ["claim_id", "action_binding", "policy_binding", "request_snapshot_digest"])
def test_different_consumed_decision_is_not_reported_as_applied(tmp_path: Path, field: str) -> None:
    store, request = _store(tmp_path)
    original = _receipt()
    assert _resolve(store, request, original)["resolved"] is True
    altered = {**original, "status": "replayed", "replayed": True, field: "0" * 64}
    assert _resolve(store, request, altered) == {
        "resolved": False,
        "error": "native_workspace_review_request_resolved",
    }
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == original


def test_local_resolution_does_not_invent_a_native_receipt(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    local = store.resolve_native_workspace_review_request(
        "request-1",
        resolution_action="allow",
        expected_request=request,
        resolved_at="2026-09-27T00:00:00+00:00",
        native_replayed=False,
    )
    assert local["resolved"] is True
    assert _resolve(store, request, {**_receipt(), "status": "replayed", "replayed": True}) == {
        "resolved": False,
        "error": "native_workspace_review_request_resolved",
    }


@pytest.mark.parametrize(
    "field,value", [("decision", "deny"), ("request_id", "other"), ("claim_id", "bad"), ("replayed", True)]
)
def test_invalid_native_receipt_cannot_resolve_request(tmp_path: Path, field: str, value: object) -> None:
    store, request = _store(tmp_path)
    assert _resolve(store, request, {**_receipt(), field: value}) == {
        "resolved": False,
        "error": "native_workspace_review_receipt_invalid",
    }
    current = store.get_approval_request("request-1")
    assert current is not None and current["status"] == "pending"


def test_native_receipt_does_not_bypass_local_disable(tmp_path: Path) -> None:
    store, request = _store(tmp_path)
    store.set_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY, {"revoked": True}, "2026-09-27T00:00:00Z")
    assert _resolve(store, request, _receipt()) == {
        "resolved": False,
        "error": "native_workspace_review_cloud_review_disabled",
    }


def test_resolved_native_delivery_is_reverified_without_restaging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _store(tmp_path)
    calls: list[dict[str, object]] = []

    def native_response(**kwargs: object) -> dict[str, object]:
        calls.append(kwargs)
        return {
            **_receipt(),
            "request_snapshot_digest": kwargs["request_snapshot_digest"],
            "status": "verified" if len(calls) == 1 else "replayed",
            "replayed": len(calls) > 1,
            "envelope_digest": "a" * 64 if len(calls) == 1 else "b" * 64,
        }

    monkeypatch.setattr(
        native,
        "matching_workspace_review_snapshot",
        lambda _store, _home, _request_id, _decision, current: dict(current),
    )
    monkeypatch.setattr(native, "_native_response", native_response)
    native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {})
    staged = tmp_path / "guard-home/native-runtime/workspace-review-requests/request-1.json"
    original_snapshot = staged.read_bytes()
    original_receipt = store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1")
    result = native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {})
    assert len(calls) == 2 and calls[0]["request_snapshot_digest"] == calls[1]["request_snapshot_digest"]
    assert result["status"] == "already_resolved" and result["native_replayed"] is True
    assert staged.read_bytes() == original_snapshot
    assert store.get_sync_payload(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "request-1") == original_receipt


def test_resolved_row_does_not_bypass_native_verification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, request = _store(tmp_path)
    assert _resolve(store, request, _receipt())["resolved"] is True

    def rejected(**_kwargs: object) -> dict[str, object]:
        raise native.NativeWorkspaceReviewError("native_workspace_review_decision_signature_invalid")

    monkeypatch.setattr(native, "_native_response", rejected)
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_decision_signature_invalid"):
        native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {"forged": True})


def test_resolved_native_result_must_match_original_consumption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, request = _store(tmp_path)
    assert _resolve(store, request, _receipt())["resolved"] is True
    changed = {**_receipt(), "status": "replayed", "replayed": True, "action_binding": "0" * 64}
    monkeypatch.setattr(native, "_native_response", lambda **_kwargs: changed)
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_request_resolved"):
        native.apply_native_workspace_review_decision(store, tmp_path / "guard-home", "request-1", {})


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
