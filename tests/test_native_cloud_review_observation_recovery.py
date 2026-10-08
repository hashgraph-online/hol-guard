"""Recovery cursor/error boundaries; fixture receipts are not native crypto proof."""

from __future__ import annotations

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.runtime import native_cloud_review_observation_recovery as recovery
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_approval_v4_transport import _result


def _observation(letter):
    receipt = deepcopy(_result(phase="consumed")["receipt"])
    receipt["request_id"] = "sha256:" + letter * 64
    return {
        "schema": "guard-native-cloud-review-application-result.v4",
        "version": 4,
        "request_id": receipt["request_id"],
        "decision_receipt_id": "decision-" + letter,
        "source_claim_hash": "c" * 64,
        "phase": "consumed",
        "consumed_at_ms": 1500,
        "receipt": receipt,
    }


@pytest.mark.parametrize(
    "error", [RuntimeError("native_cloud_review_v4_unavailable"), ValueError("invalid native response")]
)
def test_unavailable_discovery_preserves_durable_cursor(tmp_path, monkeypatch, error):
    store = GuardStore(tmp_path)
    store.set_sync_payload(recovery._STATE_KEY, {"afterRequestId": "saved-cursor"}, "2026-10-08T00:00:00Z")

    def unavailable(*args, **kwargs):
        raise error

    monkeypatch.setattr(recovery, "discover_native_applications", unavailable)
    result = recovery.recover_native_applications_once(store)
    assert result["state"] == "unavailable"
    assert store.get_sync_payload(recovery._STATE_KEY)["afterRequestId"] == "saved-cursor"


def test_failed_candidate_does_not_skip_cursor_or_prevent_other_candidates(tmp_path, monkeypatch):
    store = GuardStore(tmp_path)
    candidates = [_observation("a"), _observation("b")]
    cursor = "previous-page"
    store.set_sync_payload(recovery._STATE_KEY, {"afterRequestId": cursor}, "2026-10-08T00:00:00Z")
    monkeypatch.setattr(
        recovery, "discover_native_applications", lambda *args, **kwargs: (deepcopy(candidates), "next-page")
    )
    monkeypatch.setattr(
        recovery,
        "request_native_cloud_review",
        lambda home, operation, request: next(
            deepcopy(value) for value in candidates if value["request_id"] == request["request_id"]
        ),
    )
    failing = True
    recorded = set()

    def record(store, value):
        if failing and value["request_id"] == candidates[0]["request_id"]:
            raise ValueError("native_application_pending_request_missing")
        recorded.add(value["request_id"])

    monkeypatch.setattr(recovery, "record_native_application_observation", record)
    first = recovery.recover_native_applications_once(store)
    assert first["state"] == "recovery_required"
    assert first["reasons"] == ["native_application_pending_request_missing"]
    assert recorded == {candidates[1]["request_id"]}
    assert store.get_sync_payload(recovery._STATE_KEY)["afterRequestId"] == cursor
    failing = False
    second = recovery.recover_native_applications_once(store)
    assert second["state"] == "confirmed"
    assert recorded == {value["request_id"] for value in candidates}
    assert store.get_sync_payload(recovery._STATE_KEY)["afterRequestId"] == "next-page"


def test_native_recovery_error_does_not_starve_ordinary_event_delivery(tmp_path, monkeypatch):
    import threading

    from codex_plugin_scanner.guard.runtime import cloud_review_sync as sync
    from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker as worker
    from tests.test_guard_cloud_review_sync_worker import Store

    store = Store(tmp_path)
    stop = threading.Event()
    deliveries = []

    class Wake:
        def generation(self):
            return 0

        def wait(self, generation, timeout):
            stop.set()
            return generation

    def broken_recovery(store):
        raise RuntimeError("native_cloud_review_v4_unavailable")

    def deliver(store, auth):
        deliveries.append("delivered")
        stop.set()
        return {"synced": 1}

    monkeypatch.setattr(worker, "recover_native_applications_once", broken_recovery)
    monkeypatch.setattr(sync, "_resolve_cloud_review_sync_auth_context", lambda store: {})
    monkeypatch.setattr(sync, "sync_cloud_review_events_once", deliver)
    monkeypatch.setattr(worker, "user_health_report_due", lambda home: False)
    worker._cloud_sync_sync_loop(store, stop, Wake(), poll_interval=30, error_backoff=30)
    assert deliveries == ["delivered"]
