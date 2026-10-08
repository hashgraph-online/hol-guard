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


def _paged_discovery(monkeypatch, pages):
    calls = []

    def discover(home, *, after_request_id, limit):
        calls.append(after_request_id)
        return pages[after_request_id]

    monkeypatch.setattr(recovery, "discover_native_applications", discover)
    return calls


def _install_confirmation(monkeypatch, candidates, record):
    by_id = {value["request_id"]: value for value in candidates}
    queries = []

    def query(home, operation, request):
        queries.append(request["request_id"])
        return deepcopy(by_id[request["request_id"]])

    monkeypatch.setattr(recovery, "request_native_cloud_review", query)
    monkeypatch.setattr(recovery, "record_native_application_observation", record)
    return queries


def test_missing_original_uses_real_store_join_and_is_quarantined(tmp_path, monkeypatch):
    store = GuardStore(tmp_path)
    candidate = _observation("a")
    _paged_discovery(monkeypatch, {None: ([candidate], "later-page")})
    monkeypatch.setattr(recovery, "request_native_cloud_review", lambda *args: deepcopy(candidate))

    result = recovery.recover_native_applications_once(store)

    assert result["state"] == "recovery_required"
    assert result["confirmed"] == 0
    assert result["afterRequestId"] == "later-page"
    entry = store.get_sync_payload(recovery._QUARANTINE_KEY)["entries"][candidate["request_id"]]
    assert entry["reason"] == "native_cloud_review_v4_original_pending_mismatch"
    assert entry["observation"] == candidate


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
    assert recovery.native_observation_recovery_status(GuardStore(tmp_path)) == {
        "state": "unavailable",
        "retrying_count": 1,
        "quarantined_count": 0,
    }


def test_terminal_candidate_quarantined_and_later_pages_advance(tmp_path, monkeypatch):
    """A permanently missing SQLite original quarantines durably instead of
    pinning the cursor; the next native journal page is reached."""
    store = GuardStore(tmp_path)
    candidates = [_observation("a"), _observation("b"), _observation("c")]
    pages = {None: (candidates[:2], "page-2"), "page-2": (candidates[2:], None)}
    _paged_discovery(monkeypatch, pages)
    recorded = set()

    def record(store, observation):
        if observation["request_id"] == candidates[0]["request_id"]:
            raise ValueError("native_application_pending_request_missing")
        recorded.add(observation["request_id"])
        return {"ok": True}

    _install_confirmation(monkeypatch, candidates, record)
    first = recovery.recover_native_applications_once(store)
    assert first["state"] == "recovery_required"
    assert first["confirmed"] == 1
    assert first["quarantined"] == 1
    assert first["quarantinedTotal"] == 1
    assert first["quarantineReasons"] == ["native_application_pending_request_missing"]
    assert first["failureCount"] == 0
    assert store.get_sync_payload(recovery._STATE_KEY)["afterRequestId"] == "page-2"

    quarantine = store.get_sync_payload(recovery._QUARANTINE_KEY)
    entry = quarantine["entries"][candidates[0]["request_id"]]
    assert entry["state"] == "quarantined"
    assert entry["reason"] == "native_application_pending_request_missing"
    assert entry["observation"] == candidates[0]

    second = recovery.recover_native_applications_once(store)
    assert second["state"] == "recovery_required"
    assert second["confirmed"] == 1
    assert recorded == {value["request_id"] for value in candidates[1:]}
    assert store.get_sync_payload(recovery._STATE_KEY)["afterRequestId"] is None


@pytest.mark.parametrize(
    "reason",
    [
        "native_application_pending_request_missing",
        "native_application_pending_request_changed",
        "native_application_immutable_binding_conflict",
        "native_application_delivery_cohort_changed",
    ],
)
def test_quarantined_candidate_never_reprocessed_after_restart(tmp_path, monkeypatch, reason):
    """Durable visibility: a quarantined candidate is skipped before any
    native query even when a cold store instance rediscovers its page."""
    first_store = GuardStore(tmp_path)
    candidate = _observation("a")
    pages = {None: ([candidate], None)}
    _paged_discovery(monkeypatch, pages)

    def terminal(store, observation):
        raise ValueError(reason)

    _install_confirmation(monkeypatch, [candidate], terminal)
    assert recovery.recover_native_applications_once(first_store)["quarantinedTotal"] == 1

    restarted = GuardStore(tmp_path)
    restarted.set_sync_payload(recovery._STATE_KEY, {"afterRequestId": None}, "2026-10-08T00:00:00Z")
    record_calls = []

    def record(store, observation):
        record_calls.append(observation["request_id"])
        return {"ok": True}

    queries = _install_confirmation(monkeypatch, [candidate], record)
    result = recovery.recover_native_applications_once(restarted)
    assert result["state"] == "recovery_required"
    assert result["quarantined"] == 1
    assert result["quarantinedTotal"] == 1
    assert queries == []
    assert record_calls == []


def test_transient_failure_retains_candidate_and_retries_without_starving_page(tmp_path, monkeypatch):
    """An uncertain failure keeps the candidate retryable, holds only that
    page's cursor, and does not block confirming later candidates."""
    store = GuardStore(tmp_path)
    candidates = [_observation("a"), _observation("b")]
    cursor = "previous-page"
    store.set_sync_payload(recovery._STATE_KEY, {"afterRequestId": cursor}, "2026-10-08T00:00:00Z")
    _paged_discovery(monkeypatch, {cursor: (candidates, "next-page")})
    recorded = set()
    failing = True

    def record(store, observation):
        if failing and observation["request_id"] == candidates[0]["request_id"]:
            raise recovery.NativeCloudReviewV4Error("native_cloud_review_v4_transport_uncertain")
        recorded.add(observation["request_id"])
        return {"ok": True}

    _install_confirmation(monkeypatch, candidates, record)
    first = recovery.recover_native_applications_once(store)
    assert first["state"] == "recovery_required"
    assert first["reasons"] == ["native_cloud_review_v4_transport_uncertain"]
    assert first["quarantinedTotal"] == 0
    assert store.get_sync_payload(recovery._QUARANTINE_KEY) is None
    assert recorded == {candidates[1]["request_id"]}
    assert store.get_sync_payload(recovery._STATE_KEY)["afterRequestId"] == cursor

    failing = False
    second = recovery.recover_native_applications_once(store)
    assert second["state"] == "confirmed"
    assert recorded == {value["request_id"] for value in candidates}
    assert store.get_sync_payload(recovery._STATE_KEY)["afterRequestId"] == "next-page"


def test_terminal_quarantine_survives_page_cursor_when_transient_failure_retained(tmp_path, monkeypatch):
    """Quarantine evidence is persisted immediately, not buffered behind a
    cursor-holding transient failure on the same page."""
    store = GuardStore(tmp_path)
    candidates = [_observation("a"), _observation("b")]
    _paged_discovery(monkeypatch, {None: (candidates, "next-page")})
    flaky = True

    def record(store, observation):
        if observation["request_id"] == candidates[0]["request_id"]:
            raise ValueError("native_application_pending_request_changed")
        if flaky and observation["request_id"] == candidates[1]["request_id"]:
            raise recovery.NativeCloudReviewV4Error("native_cloud_review_v4_unavailable")
        return {"ok": True}

    _install_confirmation(monkeypatch, candidates, record)
    first = recovery.recover_native_applications_once(store)
    assert first["state"] == "recovery_required"
    assert first["afterRequestId"] is None
    assert first["quarantinedTotal"] == 1
    quarantine = store.get_sync_payload(recovery._QUARANTINE_KEY)
    assert quarantine["entries"][candidates[0]["request_id"]]["reason"] == (
        "native_application_pending_request_changed"
    )

    flaky = False
    queries = _install_confirmation(monkeypatch, candidates, record)
    second = recovery.recover_native_applications_once(store)
    assert second["state"] == "recovery_required"
    assert second["afterRequestId"] == "next-page"
    assert candidates[0]["request_id"] not in queries


def test_quarantine_is_bounded_and_overflow_stays_retryable(tmp_path, monkeypatch):
    """Quarantine never grows past its bound; an overflowing terminal failure
    stays a visible retained failure instead of dropping evidence."""
    store = GuardStore(tmp_path)
    entries = {
        f"sha256:{index:064x}": {"state": "quarantined", "reason": "native_application_pending_request_missing"}
        for index in range(recovery._QUARANTINE_LIMIT)
    }
    store.set_sync_payload(
        recovery._QUARANTINE_KEY,
        {"schema": recovery._QUARANTINE_SCHEMA, "entries": entries, "updatedAt": "2026-10-08T00:00:00Z"},
        "2026-10-08T00:00:00Z",
    )
    candidate = _observation("f")
    _paged_discovery(monkeypatch, {None: ([candidate], "next-page")})

    def record(store, observation):
        raise ValueError("native_application_pending_request_missing")

    _install_confirmation(monkeypatch, [candidate], record)
    result = recovery.recover_native_applications_once(store)
    assert result["state"] == "recovery_required"
    assert result["afterRequestId"] is None
    assert result["reasons"] == ["native_application_pending_request_missing"]
    quarantine = store.get_sync_payload(recovery._QUARANTINE_KEY)
    assert len(quarantine["entries"]) == recovery._QUARANTINE_LIMIT
    assert candidate["request_id"] not in quarantine["entries"]


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
    assert store.get_sync_payload(recovery._STATE_KEY)["state"] == "unavailable"
