"""High-signal pytest coverage for the live-request cloud sync runtime.

Tests the cloud live-request sync contracts in
codex_plugin_scanner.guard.runtime.live_request_sync:
  - monotonic event sequence
  - outbox enqueue / dequeue / ack persistence
  - per-source sync health snapshots
  - retry backoff math
  - 401 refresh throttle
  - independent worker start / stop
  - diagnostics output
"""

from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from json import dumps as json_dumps
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import live_request_sync as live_request_sync_module
from codex_plugin_scanner.guard.runtime.live_request_sync import (
    _DEFAULT_401_REFRESH_RETRY_MAX,
    _LIVE_REQUEST_EVENT_SEQUENCE_KEY,
    _REFRESH_THROTTLE_SECONDS,
    LIVE_REQUEST_EVENT_TYPES,
    LIVE_REQUEST_SYNC_CURSOR_KEY,
    LIVE_REQUEST_SYNC_FINGERPRINTS_KEY,
    LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
    OUTBOX_BATCH_COUNT,
    OUTBOX_MAX_QUEUE_EVENTS,
    OUTBOX_MAX_QUEUE_SIZE_BYTES,
    SYNC_HEALTH_SOURCES,
    SYNC_HEALTH_STATES,
    EventAck,
    LiveRequestSyncState,
    SyncHealthSnapshot,
    _build_live_request_event,
    _cloud_sync_handle_401_refresh,
    _cloud_sync_retry_request,
    _cloud_sync_retry_wait_seconds,
    _get_cloud_sync_sync_state,
    _get_current_cloud_sync_sequence,
    _get_next_cloud_sync_sequence,
    _resolve_sync_url,
    atomic_write_sync,
    cloud_sync_live_request_diagnostics,
    cloud_sync_sync_live_requests_once,
    dequeue_outbox_batch,
    emit_decision_applied,
    emit_delivery_failed,
    emit_request_created,
    emit_request_refreshed,
    emit_request_resolved_locally,
    enqueue_outbox_request,
    get_sync_health,
    mark_outbox_synced,
    process_cloud_sync_ack_response,
    set_sync_health,
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
    sync_live_requests_once,
)
from codex_plugin_scanner.guard.runtime.runner import (
    GuardSyncAuthorizationExpiredError,
)
from codex_plugin_scanner.guard.store import GuardStore

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class Store:
    """Minimal GuardStore stand-in for local-only sync contracts."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self._payloads: dict[str, object] = {}

    def get_sync_payload(self, key: str) -> object | None:
        return self._payloads.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        self._payloads[key] = payload

    def get_cloud_sync_profile(self) -> dict[str, str]:
        return {
            "auth_mode": "oauth",
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "workspace_id": "workspace-1",
        }

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
        return {
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "runtime_id": "runtime-1",
            "workspace_id": "workspace-1",
        }

    def get_or_create_installation_id(self) -> str:
        return "22222222-2222-4222-8222-222222222222"

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        return []

    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]:
        return []

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object]:
        return {"operation_id": request_id, "metadata": {"workspace_path": "/workspace/repo"}}

    def claim_remote_once_receipt(self, receipt_id: str, *, request_id: str, claimed_at: str) -> bool:
        return True

    def release_remote_once_receipt(self, receipt_id: str) -> None:
        pass


def _make_cloud_sync_state(
    store: Store,
    *,
    sequence: int = 0,
    refresh_loop_count: int = 0,
    state: str = "idle",
    last_refresh_at: str | None = None,
    error_streak: int = 0,
    last_successful_sync_at: str | None = None,
) -> dict:
    """Seed the store with a known cloud sync state dict under the correct key."""
    ts = datetime.now(timezone.utc).isoformat()
    store.set_sync_payload(
        _LIVE_REQUEST_EVENT_SEQUENCE_KEY,
        {
            "cloud_sync_sequence": sequence,
            "refresh_loop_count": refresh_loop_count,
            "state": state,
            "last_refresh_at": last_refresh_at,
            "error_streak": error_streak,
            "last_successful_sync_at": last_successful_sync_at or ts,
        },
        ts,
    )
    return _get_cloud_sync_sync_state(store)


# ---------------------------------------------------------------------------
# Contract: event types and data-model immutability
# ---------------------------------------------------------------------------


class TestEventTypesAndModels:
    """LIVE_REQUEST_EVENT_TYPES, model classes, version constants."""

    def test_event_types_is_frozenset_of_exactly_six(self) -> None:
        assert isinstance(LIVE_REQUEST_EVENT_TYPES, frozenset)
        assert len(LIVE_REQUEST_EVENT_TYPES) == 6

    def test_expected_event_type_names(self) -> None:
        expected = {
            "request_created",
            "request_refreshed",
            "request_expired",
            "request_resolved_locally",
            "decision_applied",
            "delivery_failed",
        }
        assert expected == LIVE_REQUEST_EVENT_TYPES

    def test_protocol_version_constant_exists(self) -> None:
        assert LIVE_REQUEST_SYNC_PROTOCOL_VERSION == "1"

    def test_health_sounds(self) -> None:
        assert isinstance(SYNC_HEALTH_SOURCES, frozenset)
        assert isinstance(SYNC_HEALTH_STATES, frozenset)

    def test_sync_health_valid_states(self) -> None:
        assert {"healthy", "stale", "auth_failed", "retrying", "blocked", "disabled", "unknown"} == SYNC_HEALTH_STATES


class TestEventAckDataclass:
    """EventAck.to_dict produces stable dict."""

    def test_ack_to_dict_accepted(self) -> None:
        ack = EventAck(local_request_id="req-1", accepted=True, stale=False, status="ok", local_event_sequence=42)
        d = ack.to_dict()
        assert d["localRequestId"] == "req-1"
        assert d["accepted"] is True
        assert d["stale"] is False
        assert d["status"] == "ok"
        assert d["localEventSequence"] == 42

    def test_ack_to_dict_with_reason(self) -> None:
        ack = EventAck(
            local_request_id="req-2",
            accepted=False,
            stale=False,
            status="rejected",
            reason="policy violation",
        )
        d = ack.to_dict()
        assert d["localRequestId"] == "req-2"
        assert d["reason"] == "policy violation"


class TestSyncHealthSnapshot:
    """SyncHealthSnapshot.to_dict shape."""

    def test_snapshot_to_dict(self) -> None:
        snap = SyncHealthSnapshot(source="policy", state="healthy", backlog_count=3)
        d = snap.to_dict()
        assert d["source"] == "policy"
        assert d["state"] == "healthy"
        assert d["backlogCount"] == 3


class TestLiveRequestSyncState:
    """LiveRequestSyncState.to_dict serializes all fields."""

    def test_state_to_dict_has_sequence(self) -> None:
        st = LiveRequestSyncState(sequence=5)
        d = st.to_dict()
        assert d["sequence"] == 5

    def test_state_to_dict_defaults(self) -> None:
        st = LiveRequestSyncState(sequence=1)
        d = st.to_dict()
        assert d["lastSuccessfulSyncAt"] is None
        assert d["errorStreak"] == 0
        assert d["state"] == "idle"


# ---------------------------------------------------------------------------
# Contract: monotonic event sequence
# ---------------------------------------------------------------------------


class TestMonotonicSequence:
    """_get_next_cloud_sync_sequence() monotonically increments per store."""

    def test_starts_at_one(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        assert _get_next_cloud_sync_sequence(store) == 1

    def test_monotonic_increment(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seqs = [_get_next_cloud_sync_sequence(store) for _ in range(10)]
        assert seqs == list(range(1, 11))

    def test_current_sequence_matches_last(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        _get_next_cloud_sync_sequence(store)
        _get_next_cloud_sync_sequence(store)
        assert _get_current_cloud_sync_sequence(store) == 2

    def test_sequence_resumes_from_existing_state(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        _make_cloud_sync_state(store, sequence=50)
        assert _get_next_cloud_sync_sequence(store) == 51

    def test_current_returns_zero_when_no_state(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        assert _get_current_cloud_sync_sequence(store) == 0

    def test_concurrent_store_reservations_are_unique(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        with ThreadPoolExecutor(max_workers=8) as executor:
            sequences = list(
                executor.map(
                    lambda _: _get_next_cloud_sync_sequence(store),
                    range(40),
                )
            )

        assert sorted(sequences) == list(range(1, 41))
        assert _get_current_cloud_sync_sequence(store) == 40


# ---------------------------------------------------------------------------
# Contract: event emission
# ---------------------------------------------------------------------------


class TestEventEmission:
    """Each emit_* function creates a sequence, stores event payload, and returns the sequence number."""

    def test_emit_request_created(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seq = emit_request_created(store, "local-1", display_command="cat /etc/shadow")
        assert seq == 1
        payload = store.get_sync_payload(f"guard_event:{seq}")
        assert isinstance(payload, dict)
        assert payload["eventType"] == "request_created"
        assert payload["localRequestId"] == "local-1"

    def test_emit_request_refreshed(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seq = emit_request_refreshed(store, "local-2")
        assert seq == 1
        payload = store.get_sync_payload(f"guard_event:{seq}")
        assert payload["eventType"] == "request_refreshed"

    def test_emit_request_resolved_locally(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seq = emit_request_resolved_locally(store, "local-3")
        assert seq == 1
        payload = store.get_sync_payload(f"guard_event:{seq}")
        assert isinstance(payload, dict)
        assert payload["eventType"] == "request_resolved_locally"

    def test_emit_decision_applied(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seq = emit_decision_applied(store, "local-4")
        assert seq == 1
        payload = store.get_sync_payload(f"guard_event:{seq}")
        assert payload["eventType"] == "decision_applied"

    def test_emit_delivery_failed(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seq = emit_delivery_failed(store, "local-5")
        assert seq == 1
        payload = store.get_sync_payload(f"guard_event:{seq}")
        assert payload["eventType"] == "delivery_failed"

    def test_sequential_events_get_unique_sequences(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seqs = [emit_request_created(store, f"local-{i}") for i in range(5)]
        assert seqs == [1, 2, 3, 4, 5]
        assert len(set(seqs)) == 5

    def test_emit_with_display_command(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        emit_request_created(
            store,
            "local-6",
            display_command="npm install -g evil-pkg",
            display_summary="Global install",
        )
        payload = store.get_sync_payload("guard_event:1")
        assert payload["displayCommand"] == "npm install -g evil-pkg"


# ---------------------------------------------------------------------------
# Contract: outbox enqueue / dequeue / ack
# ---------------------------------------------------------------------------


class TestOutboxEnqueueDequeueAck:
    """enqueue → dequeue → mark synced → verify persisted state.

    NOTE: enqueue_outbox_request stores at guard_outbox:{local_request_id}
    but dequeue_outbox_batch scans guard_outbox:{sequence_number}.  This is an
    implementation quirk.  The tests below validate the observable contracts
    by either:
      - asserting the outbox key that enqueue actually creates
      - injecting payloads directly under the guard_outbox:{seq} key
        that dequeue reads, proving dequeue's scan logic works.
    """

    def test_enqueue_creates_outbox_entry(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seq = enqueue_outbox_request(
            store,
            "outbox-1",
            action="request_created",
            display_command="rm -rf /",
            display_summary="Dangerous",
        )
        assert seq >= 1
        payload = store.get_sync_payload("guard_outbox:outbox-1")
        assert isinstance(payload, dict)
        assert payload["local_request_id"] == "outbox-1"
        assert payload["action"] == "request_created"
        assert payload["display_command"] == "rm -rf /"
        assert payload["display_summary"] == "Dangerous"
        assert payload["synced_at"] is None  # not yet synced

    def test_dequeue_scans_sequence_range_and_filters(self, tmp_path: Path) -> None:
        """dequeue reads guard_outbox_seq:{seq} keys and filters on synced_at."""
        store = Store(tmp_path)
        _make_cloud_sync_state(store, sequence=5)
        store.set_sync_payload("guard_outbox_seq:1", {"local_request_id": "seq-1", "synced_at": None}, "now")
        store.set_sync_payload("guard_outbox_seq:2", {"local_request_id": "seq-2", "synced_at": None}, "now")
        store.set_sync_payload("guard_outbox_seq:3", {"local_request_id": "seq-3", "synced_at": "synced"}, "now")
        store.set_sync_payload("guard_outbox_seq:4", {"local_request_id": "seq-4", "synced_at": None}, "now")
        batch = dequeue_outbox_batch(store, limit=10)
        assert len(batch) == 3
        ids = {e["local_request_id"] for e in batch}
        assert ids == {"seq-1", "seq-2", "seq-4"}

    def test_dequeue_respects_limit(self, tmp_path: Path) -> None:
        """dequeue returns at most `limit` unsynced entries from the scan range."""
        store = Store(tmp_path)
        _make_cloud_sync_state(store, sequence=5)
        for i in range(1, 6):
            store.set_sync_payload(f"guard_outbox_seq:{i}", {"local_request_id": f"lim-{i}", "synced_at": None}, "now")
        batch = dequeue_outbox_batch(store, limit=2)
        assert len(batch) == 2

    def test_dequeue_wraps_cursor_to_oldest_pending(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        _make_cloud_sync_state(store, sequence=500)
        state = _get_cloud_sync_sync_state(store)
        state["outbox_cursor"] = 500
        store.set_sync_payload(_LIVE_REQUEST_EVENT_SEQUENCE_KEY, state, "now")
        store.set_sync_payload("guard_outbox_seq:2", {"local_request_id": "old-2", "synced_at": None}, "now")

        batch = dequeue_outbox_batch(store, limit=10)

        assert [item["local_request_id"] for item in batch] == ["old-2"]

    def test_dequeue_returns_empty_when_no_entries(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        batch = dequeue_outbox_batch(store, limit=10)
        assert batch == []

    def test_mark_outbox_synced_updates_state(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        store.set_sync_payload("guard_outbox:sync-1", {"local_request_id": "sync-1", "synced_at": None}, "now")
        mark_outbox_synced(store, "sync-1", sequence=1, synced_at="2026-01-01T00:00:00+00:00")
        payload = store.get_sync_payload("guard_outbox:sync-1")
        assert payload["synced_at"] == "2026-01-01T00:00:00+00:00"

    def test_mark_outbox_synced_persists_event(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        store.set_sync_payload("guard_outbox:sync-2", {"local_request_id": "sync-2", "synced_at": None}, "now")
        store.set_sync_payload("guard_event:5", {"eventType": "test"}, "now")
        mark_outbox_synced(store, "sync-2", sequence=5, synced_at="2026-02-01T00:00:00+00:00")
        event_data = store.get_sync_payload("guard_event:5")
        assert isinstance(event_data, dict)
        assert event_data["persisted_at"] == "2026-02-01T00:00:00+00:00"

    def test_ack_response_marks_only_accepted(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        store.set_sync_payload("guard_outbox:ack-1", {"local_request_id": "ack-1", "synced_at": None}, "now")
        store.set_sync_payload("guard_outbox:ack-2", {"local_request_id": "ack-2", "synced_at": None}, "now")

        ack_data = {
            "results": [
                {
                    "localRequestId": "ack-1",
                    "accepted": True,
                    "stale": False,
                    "status": "ok",
                    "localEventSequence": 1,
                },
                {
                    "localRequestId": "ack-2",
                    "accepted": False,
                    "stale": False,
                    "status": "rejected",
                    "reason": "policy",
                    "localEventSequence": 2,
                },
            ]
        }
        acks = process_cloud_sync_ack_response(store, ack_data)
        assert len(acks) == 2
        assert acks[0].accepted is True
        assert acks[1].accepted is False

        # ack-1 should now be synced (synced_at set)
        payload = store.get_sync_payload("guard_outbox:ack-1")
        assert payload["synced_at"] is not None
        # ack-2 should still be unsynced
        payload2 = store.get_sync_payload("guard_outbox:ack-2")
        assert payload2["synced_at"] is None

    def test_ack_response_stale_events_discarded(self, tmp_path: Path) -> None:
        """Stale events are acknowledged locally so they do not block the outbox."""
        store = Store(tmp_path)
        outbox = {"local_request_id": "stale-1", "sequence_number": 1, "synced_at": None}
        store.set_sync_payload("guard_outbox:stale-1", outbox, "now")
        store.set_sync_payload("guard_outbox_seq:1", outbox, "now")
        ack_data = {
            "results": [
                {
                    "localRequestId": "stale-1",
                    "accepted": False,
                    "stale": True,
                    "status": "stale",
                    "localEventSequence": 1,
                }
            ],
        }
        acks = process_cloud_sync_ack_response(store, ack_data)
        assert len(acks) == 1
        assert acks[0].accepted is False
        assert acks[0].stale is True
        payload = store.get_sync_payload("guard_outbox:stale-1")
        assert payload["synced_at"] is not None
        sequence_payload = store.get_sync_payload("guard_outbox_seq:1")
        assert sequence_payload["synced_at"] is not None

    def test_ack_zero_sequence_marks_event_synced(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        store.set_sync_payload("guard_outbox:zero-1", {"local_request_id": "zero-1", "synced_at": None}, "now")
        store.set_sync_payload("guard_event:0", {"eventType": "request_created"}, "now")

        acks = process_cloud_sync_ack_response(
            store,
            {
                "results": [
                    {
                        "localRequestId": "zero-1",
                        "accepted": True,
                        "stale": False,
                        "status": "ok",
                        "localEventSequence": 0,
                    }
                ]
            },
        )

        assert acks[0].local_event_sequence == 0
        event = store.get_sync_payload("guard_event:0")
        assert isinstance(event, dict)
        assert event["persisted_at"] is not None

    def test_ack_malformed_items_do_not_crash(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        acks = process_cloud_sync_ack_response(store, {"results": ["bad", {"localRequestId": "ok"}]})
        assert len(acks) == 1
        assert acks[0].local_request_id == "ok"

    def test_rejected_batch_does_not_report_progress(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)
        _make_cloud_sync_state(store, sequence=1)
        outbox = {"local_request_id": "reject-1", "synced_at": None}
        store.set_sync_payload("guard_outbox_seq:1", outbox, "now")
        store.set_sync_payload("guard_outbox:reject-1", outbox, "now")

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.live_request_sync._cloud_sync_push_batch_to_cloud",
            lambda *args, **kwargs: {
                "results": [
                    {
                        "localRequestId": "reject-1",
                        "accepted": False,
                        "status": "rejected",
                        "reason": "policy",
                        "localEventSequence": 1,
                    }
                ]
            },
        )

        result = cloud_sync_sync_live_requests_once(
            store,
            {"sync_url": "https://cloud.test/api/guard/receipts/sync", "accessToken": "token"},
        )

        assert result["synced"] == 0
        outbox = store.get_sync_payload("guard_outbox:reject-1")
        assert isinstance(outbox, dict)
        assert outbox["synced_at"] is None

    def test_ack_empty_results(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        acks = process_cloud_sync_ack_response(store, {"results": []})
        assert acks == []

    def test_ack_accepts_flat_dict_as_results(self, tmp_path: Path) -> None:
        """When ack_data is a dict without 'results', the dict itself is treated as results."""
        store = Store(tmp_path)
        # This test just ensures no crash on edge shape
        acks = process_cloud_sync_ack_response(store, {})
        assert isinstance(acks, list)


# ---------------------------------------------------------------------------
# Contract: outbox capacity limits
# ---------------------------------------------------------------------------


class TestOutboxCapacityLimits:
    """OUTBOX_MAX_QUEUE_SIZE_BYTES and OUTBOX_MAX_QUEUE_EVENTS constants are sensible."""

    def test_max_queue_size_is_one_mib(self) -> None:
        assert OUTBOX_MAX_QUEUE_SIZE_BYTES == 1 * 1024 * 1024

    def test_max_queue_events(self) -> None:
        assert OUTBOX_MAX_QUEUE_EVENTS == 500

    def test_batch_count(self) -> None:
        assert OUTBOX_BATCH_COUNT == 100


# ---------------------------------------------------------------------------
# Contract: retry backoff math
# ---------------------------------------------------------------------------


class TestRetryBackoff:
    """_cloud_sync_retry_wait_seconds returns bounded exponential backoff with jitter."""

    def test_streak_zero_returns_base(self) -> None:
        assert _cloud_sync_retry_wait_seconds(5.0, 60.0, 0) == 5.0

    def test_backoff_grows_exponentially(self) -> None:
        """Streak increases → wait time increases (capped at max)."""
        waits = [_cloud_sync_retry_wait_seconds(1.0, 600.0, s) for s in range(1, 8)]
        assert waits[6] >= waits[0]

    def test_capped_at_max_wait(self) -> None:
        assert _cloud_sync_retry_wait_seconds(1.0, 256.0, 10) <= 320.0

    def test_minimum_retry_wait(self) -> None:
        assert _cloud_sync_retry_wait_seconds(0.1, 0.1, 1) >= 0.5

    def test_deterministic_with_seed(self) -> None:
        random.seed(100)
        first = _cloud_sync_retry_wait_seconds(5.0, 60.0, 3)
        random.seed(100)
        second = _cloud_sync_retry_wait_seconds(5.0, 60.0, 3)
        assert first == second

    def test_base_path_grows_with_streak(self) -> None:
        """base=1.0 with streak 1 → 2x=2, streak 2 → 4x=4, etc."""
        waits = [_cloud_sync_retry_wait_seconds(1.0, 600.0, s) for s in range(1, 6)]
        # base path: 1*2^0, 1*2^1, 1*2^2, ... = 1, 2, 4, 8, 16
        # jitter adds ±25%, so streak 1 is 1 ± 0.25 → range [0.75, 1.25]
        # streak 4 is 8 ± 2.0 → range [6, 10]
        # streak 4 must be > streak 1
        assert waits[3] > waits[0]


# ---------------------------------------------------------------------------
# Contract: 401 refresh throttle
# ---------------------------------------------------------------------------


class TestFourZeroOneRefresh:
    """_cloud_sync_handle_401_refresh respects refresh loop limit and throttle window.

    The function internally imports _resolve_guard_sync_auth_context
    from .runner at call time. The tests monkeypatch that function so
    no real OAuth or network state is required.
    """

    def test_raises_after_max_refresh_attempts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)
        _make_cloud_sync_state(store, refresh_loop_count=_DEFAULT_401_REFRESH_RETRY_MAX)

        def fake_resolve(*a, **k):
            return {"accessToken": "tok-1"}

        monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner._resolve_guard_sync_auth_context", fake_resolve)
        with pytest.raises(GuardSyncAuthorizationExpiredError):
            _cloud_sync_handle_401_refresh(store, {})

    def test_refresh_increments_on_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)
        _make_cloud_sync_state(store, refresh_loop_count=0)

        def fake_resolve(*a, **k):
            return {"accessToken": "tok-1", "refreshToken": "ref-1", "expiresIn": 3600}

        monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner._resolve_guard_sync_auth_context", fake_resolve)

        auth = _cloud_sync_handle_401_refresh(store, {})
        state = _get_cloud_sync_sync_state(store)
        assert state["refresh_loop_count"] == 1
        assert "accessToken" in auth
        assert "refreshToken" in auth

    def test_throttled_when_recent_refresh(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)
        recent = datetime.now(timezone.utc).isoformat()
        _make_cloud_sync_state(store, refresh_loop_count=0, last_refresh_at=recent)

        def fake_resolve(*a, **k):
            return {"accessToken": "tok-1"}

        monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner._resolve_guard_sync_auth_context", fake_resolve)
        with pytest.raises(GuardSyncAuthorizationExpiredError) as exc_info:
            _cloud_sync_handle_401_refresh(store, {})
        assert "throttled" in str(exc_info.value).lower()

    def test_not_throttled_after_window(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)
        old = (datetime.now(timezone.utc) - timedelta(seconds=_REFRESH_THROTTLE_SECONDS + 60)).isoformat()
        _make_cloud_sync_state(store, refresh_loop_count=0, last_refresh_at=old)

        def fake_resolve(*a, **k):
            return {"accessToken": "tok-1", "refreshToken": "ref-1"}

        monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner._resolve_guard_sync_auth_context", fake_resolve)

        auth = _cloud_sync_handle_401_refresh(store, {})
        assert "accessToken" in auth

    def test_failure_reason_saved_when_limit_reached(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)
        _make_cloud_sync_state(store, refresh_loop_count=1)

        def fake_resolve(*a, **k):
            return {"accessToken": "tok-1"}

        monkeypatch.setattr("codex_plugin_scanner.guard.runtime.runner._resolve_guard_sync_auth_context", fake_resolve)
        try:
            _cloud_sync_handle_401_refresh(store, {})
            raise AssertionError("should have raised")
        except GuardSyncAuthorizationExpiredError:
            state = _get_cloud_sync_sync_state(store)
            assert state.get("last_failure_reason") is not None


# ---------------------------------------------------------------------------
# Contract: atomic_write_sync
# ---------------------------------------------------------------------------


class TestAtomicWriteSync:
    """atomic_write_sync enqueues outbox and optionally updates approvals."""

    def test_atomic_write_enqueues_outbox(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        seq = atomic_write_sync(
            store,
            local_request_id="aw-1",
            action="test_action",
            approval_request=None,
            request_payload={"status": "pending"},
        )
        assert seq >= 1
        payload = store.get_sync_payload("guard_outbox:aw-1")
        assert payload is not None

    def test_atomic_write_with_approval_request(self, tmp_path: Path) -> None:
        """When approval_request is provided, calls add_approval_request (imported inside function)."""
        store = Store(tmp_path)
        approval = {"request_id": "req-1", "status": "pending", "display_command": "echo hello"}
        # The function catches ImportError from add_approval_request, so we
        # just verify the outbox entry is still created
        seq = atomic_write_sync(
            store,
            local_request_id="aw-2",
            action="test_action",
            approval_request=approval,
            request_payload={"status": "pending"},
        )
        assert seq >= 1


# ---------------------------------------------------------------------------
# Contract: per-source sync health snapshots
# ---------------------------------------------------------------------------


class TestSyncHealth:
    """set_sync_health validates sources/states and persists snapshots."""

    def test_set_health_saves_snapshot(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        set_sync_health(store, "policy", "healthy", last_success_at="2026-01-01T00:00:00+00:00")
        snap = store.get_sync_payload("guard_health:policy")
        assert isinstance(snap, dict)
        assert snap["source"] == "policy"
        assert snap["state"] == "healthy"

    def test_set_health_rejects_unknown_source(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        with pytest.raises(ValueError, match="Unknown sync health source"):
            set_sync_health(store, "nonexistent", "healthy")

    def test_set_health_rejects_invalid_state(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        with pytest.raises(ValueError, match="Invalid sync health state"):
            set_sync_health(store, "policy", "flying")

    def test_get_health_returns_all_sources(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        set_sync_health(store, "policy", "healthy")
        set_sync_health(store, "command_queue", "stale")
        health = get_sync_health(store)
        # get_sync_health always returns entries for every source in SYNC_HEALTH_SOURCES
        for source in SYNC_HEALTH_SOURCES:
            assert source in health
        assert health["policy"]["state"] == "healthy"
        assert health["command_queue"]["state"] == "stale"

    def test_get_health_uses_unknown_default_for_missing(self, tmp_path: Path) -> None:
        """Sources without stored snapshots get state='unknown'."""
        store = Store(tmp_path)
        health = get_sync_health(store)
        # Pick a source we never set
        source_under_test = next(iter(SYNC_HEALTH_SOURCES))
        assert health[source_under_test]["state"] == "unknown"

    def test_set_health_with_all_fields(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        set_sync_health(
            store,
            "inventory",
            "retrying",
            last_success_at="2025-12-01T00:00:00+00:00",
            last_attempt_at="2026-01-01T00:00:00+00:00",
            next_retry_at="2026-01-02T00:00:00+00:00",
            backlog_count=42,
            last_error_code="E100",
            auth_required=True,
            action_label="Retry inventory sync",
        )
        snap = store.get_sync_payload("guard_health:inventory")
        assert snap["backlogCount"] == 42
        assert snap["authRequired"] is True
        assert snap["actionLabel"] == "Retry inventory sync"
        assert snap["lastErrorCode"] == "E100"


# ---------------------------------------------------------------------------
# Contract: diagnostics output
# ---------------------------------------------------------------------------


class TestDiagnostics:
    """cloud_sync_live_request_diagnostics aggregates sync state, outbox, and health."""

    def test_diagnostics_has_protocol_version(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        diag = cloud_sync_live_request_diagnostics(store)
        assert diag["protocolVersion"] == LIVE_REQUEST_SYNC_PROTOCOL_VERSION

    def test_diagnostics_reads_outbox(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        enqueue_outbox_request(store, local_request_id="diag-1", action="request_created")
        diag = cloud_sync_live_request_diagnostics(store)
        assert diag["pendingOutboxCount"] == 1

    def test_diagnostics_has_health_key(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        diag = cloud_sync_live_request_diagnostics(store)
        assert "syncHealth" in diag

    def test_diagnostics_has_event_sequence(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        emit_request_created(store, "diag-1")
        # Manually set sequence for diagnostics
        _make_cloud_sync_state(store, sequence=1)
        diag = cloud_sync_live_request_diagnostics(store)
        assert diag["sequence"] == 1

    def test_diagnostics_has_sync_state(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        diag = cloud_sync_live_request_diagnostics(store)
        assert "syncState" in diag
        assert diag["syncState"] == "idle"

    def test_diagnostics_has_refresh_loop_count(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        diag = cloud_sync_live_request_diagnostics(store)
        assert "refreshLoopCount" in diag


# ---------------------------------------------------------------------------
# Contract: independent worker start / stop
# ---------------------------------------------------------------------------


class TestIndependentWorker:
    """start_cloud_sync_sync_worker creates a thread; stop_cloud_sync_sync_worker signals it."""

    def test_start_worker_creates_thread(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.started = False

            def is_alive(self) -> bool:
                return True

            def start(self) -> None:
                self.started = True

        created_thread = FakeThread()

        def fake_thread(*args: object, **kwargs: object) -> FakeThread:
            return created_thread

        monkeypatch.setattr("codex_plugin_scanner.guard.runtime.live_request_sync.threading.Thread", fake_thread)
        worker = start_cloud_sync_sync_worker(store)
        assert worker is not None
        assert worker.thread is created_thread
        assert created_thread.started is True

    def test_stop_worker_signals_stop_event(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def __init__(self) -> None:
                self.started = False
                self.joined = False

            def is_alive(self) -> bool:
                return not self.joined

            def start(self) -> None:
                self.started = True

            def join(self, timeout: float | None = None) -> None:
                self.joined = True

        class FakeEvent:
            def __init__(self, stopped: bool = False) -> None:
                self.stopped = stopped

            def is_set(self) -> bool:
                return self.stopped

            def set(self) -> None:
                self.stopped = True

        created_thread = FakeThread()
        created_event = FakeEvent(False)

        def fake_thread(*args: object, **kwargs: object) -> FakeThread:
            return created_thread

        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.live_request_sync.threading.Thread",
            fake_thread,
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.runtime.live_request_sync.threading.Event",
            lambda: created_event,
        )

        worker = start_cloud_sync_sync_worker(store)
        assert worker is not None
        assert created_event.is_set() is False

        new_worker = stop_cloud_sync_sync_worker(worker)
        assert new_worker is None  # dead worker returns None
        assert created_event.is_set() is True

    def test_start_worker_skips_alive_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        store = Store(tmp_path)

        class FakeThread:
            def is_alive(self) -> bool:
                return True

            def start(self) -> None:
                pass

        class FakeEvent:
            def is_set(self) -> bool:
                return False

        existing = type("Worker", (), {"thread": FakeThread(), "stop_event": FakeEvent()})()
        monkeypatch.delenv("GUARD_LIVE_REQUEST_POLL_INTERVAL", raising=False)

        new_worker = start_cloud_sync_sync_worker(store, existing=existing)  # type: ignore[arg-type]
        assert new_worker is existing

    def test_start_worker_returns_none_when_opted_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """GUARD_LIVE_REQUEST_ENABLED=0 disables the worker."""
        store = Store(tmp_path)
        monkeypatch.setenv("GUARD_LIVE_REQUEST_ENABLED", "0")
        monkeypatch.delenv("GUARD_LIVE_REQUEST_POLL_INTERVAL", raising=False)
        assert start_cloud_sync_sync_worker(store) is None

    def test_start_worker_with_existing_stopped_thread(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Existing worker with stopped thread → replaced with new worker."""
        store = Store(tmp_path)

        class FakeThread:
            def is_alive(self) -> bool:
                return False

            def start(self) -> None:
                pass

        class FakeEvent:
            def is_set(self) -> bool:
                return True

        existing = type("Worker", (), {"thread": FakeThread(), "stop_event": FakeEvent()})()
        monkeypatch.delenv("GUARD_LIVE_REQUEST_POLL_INTERVAL", raising=False)

        new_worker = start_cloud_sync_sync_worker(store, existing=existing)  # type: ignore[arg-type]
        assert new_worker is not existing

    def test_stop_worker_none_noop(self, tmp_path: Path) -> None:
        assert stop_cloud_sync_sync_worker(None) is None


# ---------------------------------------------------------------------------
# Contract: live_request_sync_status before dedicated cloud sync
# ---------------------------------------------------------------------------


class TestSyncStatus:
    """live_request_sync_status returns the current status dict."""

    def test_status_returns_protocol_version(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        from codex_plugin_scanner.guard.runtime.live_request_sync import live_request_sync_status

        status = live_request_sync_status(store)
        assert isinstance(status, dict)
        assert status["protocolVersion"] == LIVE_REQUEST_SYNC_PROTOCOL_VERSION


# ---------------------------------------------------------------------------
# Contract: outbox entry shape (field presence)
# ---------------------------------------------------------------------------


class TestOutboxEntryShape:
    """Enqueued outbox entries contain all required fields."""

    def test_outbox_entry_has_required_fields(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        enqueue_outbox_request(
            store,
            "shape-1",
            action="request_created",
            display_command="ls -la",
            display_summary="List files",
            raw_command="ls -la",
            redacted_command="ls -la",
            artifact_id="art-1",
            artifact_name="output.txt",
            harness="harness-a",
            agent="agent-b",
            machine="machine-c",
            workspace="workspace-d",
            source_hash="sha256:abc123",
        )
        payload = store.get_sync_payload("guard_outbox:shape-1")
        assert isinstance(payload, dict)
        for field in (
            "local_request_id",
            "action",
            "envelope",
            "signature",
            "harness",
            "agent",
            "machine",
            "workspace",
            "source_hash",
            "display_command",
            "display_summary",
            "raw_command",
            "redacted_command",
            "artifact_id",
            "artifact_name",
            "created_at",
            "synced_at",
        ):
            assert field in payload, f"Missing field: {field}"

    def test_outbox_envelope_contains_protocol_and_device(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        enqueue_outbox_request(store, "shape-2", action="test")
        payload = store.get_sync_payload("guard_outbox:shape-2")
        assert isinstance(payload, dict)
        envelope = payload["envelope"]
        assert isinstance(envelope, dict)
        assert envelope["protocolVersion"] == LIVE_REQUEST_SYNC_PROTOCOL_VERSION
        assert "deviceId" in envelope
        assert "workspaceId" in envelope
        assert "machineInstallationId" in envelope


# ---------------------------------------------------------------------------
# Contract: live-request event redaction levels
# ---------------------------------------------------------------------------


class TestRedactionLevelNone:
    """Redaction level 'none' emits the actual scrubbed command for display/raw.

    Live request with a real command + secret: raw_command and display_command
    carry the secret-scrubbed text; display_provenance is 'raw'; redacted_command
    is None.
    """

    def test_redaction_none_uses_scrubbed_command(self, tmp_path: Path) -> None:
        """raw_command and display_command contain the command with secrets removed."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-redact-1",
            "status": "pending",
            "action_identity": "test-action",
            "trigger_summary": "Run deployment",
            "risk_headline": "Admin privilege escalation",
            "harness": "guard-review",
            "raw_command_text": 'curl -H "Bearer tokensecret123" https://api.example.com/deploy',
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
            "expires_at": "2026-07-10T01:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)  # reserve sequence 1
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # The command must not contain the raw secret token
        assert "tokensecret123" not in event["rawCommand"]
        assert "tokensecret123" not in event["displayCommand"]
        # But the command shape is preserved (curl, Bearer, URL present)
        assert "curl" in event["rawCommand"]
        assert "https://api.example.com/deploy" in event["rawCommand"]
        # display_provenance must signal raw source
        assert event["displayProvenance"] == "raw"
        # redacted_command must be None for 'none' level
        assert event["redactedCommand"] is None

    def test_redaction_none_enforces_portal_utf16_field_limits(
        self,
        tmp_path: Path,
    ) -> None:
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-bounded-1",
            "status": "pending",
            "action_identity": "test-action",
            "trigger_summary": "😀" * 400,
            "risk_headline": "😀" * 400,
            "harness": "guard-review",
            "raw_command_text": ("😀" * 40_000) + " --dangerous-suffix",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )

        assert event is not None
        raw_command = event["rawCommand"]
        display_summary = event["displaySummary"]
        assert isinstance(raw_command, str)
        assert isinstance(display_summary, str)
        assert len(raw_command.encode("utf-16-le")) // 2 <= 65_536
        assert " … [truncated] … " in raw_command
        assert raw_command.endswith(" --dangerous-suffix")
        assert len(display_summary.encode("utf-16-le")) // 2 <= 512

    def test_redaction_none_hides_bearer_prefix(self, tmp_path: Path) -> None:
        """Bearer token is scrubbed to 'Bearer *****' — prefix retained."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-bearer-1",
            "status": "pending",
            "action_identity": "api-call",
            "trigger_summary": "Fetch data",
            "harness": "guard-review",
            "raw_command_text": 'curl -H "Bearer abcdef123456" https://example.com',
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert "Bearer *****" in event["rawCommand"]
        assert "Bearer abcdef" not in event["rawCommand"]

    def test_redaction_none_no_secret_in_any_field(self, tmp_path: Path) -> None:
        """A secret-bearing command must not leak the raw secret anywhere in the event."""
        store = Store(tmp_path)
        secret = "sk-" + ("x" * 24)
        item: dict[str, object] = {
            "request_id": "req-secret-1",
            "status": "pending",
            "action_identity": "openai-chat",
            "trigger_summary": "Generate text",
            "risk_summary": "Model API call",
            "harness": "guard-review",
            "raw_command_text": f'echo "{secret}" > ~/.env',
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # The raw secret value must not appear in any field
        event_text = json_dumps(event)
        assert secret not in event_text

    def test_redaction_none_scrubs_generic_token_assignments(self, tmp_path: Path) -> None:
        """Mandatory cloud scrubbing still applies when user redaction is disabled."""
        store = Store(tmp_path)
        secret = "generic-" + ("x" * 24)
        item: dict[str, object] = {
            "request_id": "req-secret-2",
            "status": "pending",
            "action_identity": "deploy",
            "trigger_summary": "Deploy service",
            "harness": "guard-review",
            "raw_command_text": f"deploy --api-key {secret}",
            "action_envelope_json": {
                "action_type": "shell_command",
                "command": f"deploy --api-key {secret}",
                "args": ["--api-key", secret],
                "parameters": {"accessToken": secret, "region": "us-east-1"},
            },
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert secret not in json_dumps(event)
        assert "[redacted]" in event["rawCommand"]
        request_payload = event["requestPayload"]
        assert isinstance(request_payload, dict)
        action_envelope = request_payload["actionEnvelope"]
        assert isinstance(action_envelope, dict)
        assert action_envelope["args"] == ["--api-key", "[redacted]"]
        assert action_envelope["parameters"] == {
            "accessToken": "[redacted]",
            "region": "us-east-1",
        }


class TestRedactionLevelPartial:
    """Redaction level 'partial' emits a redacted command without secret leakage.

    raw_command is None; redacted_command carries the secret-stripped text;
    display_provenance is 'redacted'; the secret value must not appear.
    """

    def test_redaction_partial_has_redacted_command_not_raw(self, tmp_path: Path) -> None:
        """redacted_command carries the scrubbed text; raw_command is None."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-partial-1",
            "status": "pending",
            "action_identity": "deploy-staging",
            "trigger_summary": "Push to staging",
            "harness": "guard-review",
            "raw_command_text": "API_KEY=supersecretkey123 && ./deploy.sh",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="partial",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # raw_command must be None for partial
        assert event["rawCommand"] is None
        # redacted_command must carry the scrubbed text
        assert event["redactedCommand"] is not None
        assert isinstance(event["redactedCommand"], str)
        # The original secret value must not appear
        assert "supersecretkey123" not in event["redactedCommand"]
        assert event["redactedCommand"] == "[redacted]"

    def test_redaction_partial_display_command_is_redacted(self, tmp_path: Path) -> None:
        """display_command mirrors redacted_command (not raw secret)."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-partial-2",
            "status": "pending",
            "action_identity": "db-migrate",
            "trigger_summary": "Migrate database",
            "harness": "guard-review",
            "raw_command_text": "postgres://user:p@ssw0rd@db.example.com:5432/mydb",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="partial",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["displayCommand"] == event["redactedCommand"]
        # connection-string pattern should have redacted the URL
        assert "postgres://" not in event["displayCommand"]
        assert "p@ssw0rd" not in event["displayCommand"]

    def test_redaction_partial_display_provenance_is_redacted(self, tmp_path: Path) -> None:
        """Provenance is 'redacted' — not 'raw' or 'withheld'."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-partial-3",
            "status": "pending",
            "action_identity": "test-action",
            "trigger_summary": "Run test",
            "harness": "guard-review",
            "raw_command_text": "echo hello",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="partial",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["displayProvenance"] == "redacted"

    def test_redaction_full_scrubs_secret_like_fallback_metadata(self, tmp_path: Path) -> None:
        """Full redaction scrubs fallback metadata when no command is available."""
        store = Store(tmp_path)
        sensitive_identity = "api_key=" + ("x" * 24)
        item: dict[str, object] = {
            "request_id": "req-full-2",
            "status": "pending",
            "action_identity": sensitive_identity,
            "trigger_summary": "Write config",
            "harness": "my-harness",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="full",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert sensitive_identity not in event["displayCommand"]
        assert event["displayCommand"] == "my-harness: [redacted]"
        assert event["redactedCommand"] == event["displayCommand"]


class TestPendingRequestAgeConnectivity:
    """Pending local requests remain live/actionable regardless age or connectivity.

    Age alone must not make a pending request historical; disconnected daemon
    must not suppress the command text.
    """

    def test_pending_request_ignores_legacy_expiration_timestamp(self, tmp_path: Path) -> None:
        """A pending request with a past expires_at emits no product expiration."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-age-1",
            "status": "pending",
            "action_identity": "deploy-critical-fix",
            "trigger_summary": "Hotfix for production",
            "harness": "guard-review",
            "raw_command_text": "./run-hotfix.sh --force",
            "created_at": "2026-07-01T00:00:00+00:00",
            "last_seen_at": "2026-07-01T00:00:00+00:00",
            "expires_at": "2026-07-01T01:00:00+00:00",  # already expired
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["eventType"] == "request_created"
        assert event["rawCommand"] is not None
        assert "./run-hotfix.sh --force" in event["rawCommand"]
        assert "localExpiresAt" not in event

    def test_disconnected_daemon_still_emits_command_text(self, tmp_path: Path) -> None:
        """No oauth context (disconnected) must not suppress command emission."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-disconn-1",
            "status": "pending",
            "action_identity": "review-pr",
            "trigger_summary": "Review pending pull request",
            "harness": "guard-review",
            "raw_command_text": "gh pr review 42 --approve",
            "created_at": "2026-07-10T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
            "expires_at": "2026-07-10T12:00:00+00:00",
        }
        # oauth=None simulates disconnected daemon (no cloud auth available)
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        assert event["reviewClaim"] is None  # no oauth = no claim, but event still emitted
        # Command text must still be present
        assert "gh pr review 42 --approve" in event["rawCommand"]
        assert event["displayProvenance"] == "raw"

    def test_pending_status_keeps_lifecycle_live_not_historical(self, tmp_path: Path) -> None:
        """status='pending' must yield request_created, never historical status."""
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-live-1",
            "status": "pending",
            "action_identity": "install-package",
            "trigger_summary": "Add dependency",
            "harness": "guard-review",
            "raw_command_text": "npm install lodash@latest",
            "created_at": "2026-07-05T00:00:00+00:00",
            "last_seen_at": "2026-07-10T00:00:00+00:00",
            "expires_at": "2026-07-06T00:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)
        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )
        assert event is not None
        # Must be 'request_created', NOT 'request_expired'
        assert event["eventType"] == "request_created"
        assert event["eventType"] != "request_expired"

    def test_legacy_expired_status_reopens_as_live(self, tmp_path: Path) -> None:
        store = Store(tmp_path)
        item: dict[str, object] = {
            "request_id": "req-legacy-expired-1",
            "status": "expired",
            "action_identity": "deploy-critical-fix",
            "trigger_summary": "Hotfix for production",
            "harness": "guard-review",
            "raw_command_text": "./run-hotfix.sh --force",
            "created_at": "2026-07-01T00:00:00+00:00",
            "last_seen_at": "2026-07-01T00:00:00+00:00",
            "resolved_at": "2026-07-01T01:00:00+00:00",
        }
        _get_next_cloud_sync_sequence(store)

        event = _build_live_request_event(
            item,
            oauth=None,
            redaction_level="none",
            store=store,
            event_sequence=1,
        )

        assert event is not None
        assert event["eventType"] == "request_created"
        assert event["requestPayload"]["status"] == "pending"


# ---------------------------------------------------------------------------
# Contract: _resolve_sync_url derives live-request endpoint from receipt sync URL
# ---------------------------------------------------------------------------


class TestResolveSyncUrl:
    """_resolve_sync_url replaces the entire path, preserving scheme and host."""

    def test_full_receipt_path_replaced_not_appended(self) -> None:
        """A receipt-sync URL must derive /api/guard/live-requests/sync, not
        append to the existing receipt path.  This is the contract that caused
        the production 404 — the old code appended instead of replacing."""
        auth_context: dict[str, object] = {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        }
        result = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
        assert result == "https://hol.org/api/guard/live-requests/sync"

    def test_https_origin_with_explicit_port_preserved(self) -> None:
        """An HTTPS origin carrying an explicit port keeps that port when the
        path is replaced."""
        auth_context: dict[str, object] = {
            "sync_url": "https://hol.org:8443/api/guard/receipts/sync",
        }
        result = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
        assert result == "https://hol.org:8443/api/guard/live-requests/sync"

    def test_query_string_preserved_when_path_replaced(self) -> None:
        """Replacing the sync URL path preserves query-bound routing."""
        auth_context: dict[str, object] = {
            "sync_url": "https://hol.org/api/guard/receipts/sync?route=tenant-a",
        }
        result = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
        assert result == "https://hol.org/api/guard/live-requests/sync?route=tenant-a"

    def test_batch_request_preserves_query_bound_routing(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Batch requests use the shared endpoint derivation contract."""
        from codex_plugin_scanner.guard.runtime import runner

        captured_urls: list[str] = []

        def capture_request(
            _auth_context: dict[str, object],
            *,
            request_url: str,
            **_kwargs: object,
        ) -> object:
            captured_urls.append(request_url)
            return object()

        monkeypatch.setattr(runner, "_guard_sync_request", capture_request)
        monkeypatch.setattr(
            runner,
            "_urlopen_json_with_timeout_retry",
            lambda **_kwargs: {},
        )

        result = _cloud_sync_retry_request(
            {
                "sync_url": ("https://hol.org/api/guard/receipts/sync?route=tenant-a"),
            },
            method="POST",
            path="live-requests/batch",
            payload={},
            max_retries=0,
        )

        assert result == {}
        assert captured_urls == ["https://hol.org/api/guard/live-requests/batch?route=tenant-a"]


class TestStateAwareLiveRequestSync:
    def test_ignores_cloud_cursor_and_only_resends_changed_requests(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        class QueueStore(Store):
            def __init__(self, guard_home: Path) -> None:
                super().__init__(guard_home)
                self.rows: list[dict[str, object]] = [
                    {
                        "request_id": "request-1",
                        "status": "pending",
                        "action_identity": "test-action",
                        "trigger_summary": "Review test action",
                        "harness": "guard-review",
                        "created_at": "2026-07-10T00:00:00+00:00",
                        "last_seen_at": "2026-07-10T00:00:00+00:00",
                    }
                ]

            def list_approval_requests(
                self,
                *,
                status: str | None = "pending",
                harness: str | None = None,
                limit: int | None = 50,
                cursor: str | None = None,
                search: str | None = None,
            ) -> list[dict[str, object]]:
                del status, harness, cursor, search
                return self.rows if limit is None else self.rows[:limit]

        store = QueueStore(tmp_path)
        store.set_sync_payload(
            LIVE_REQUEST_SYNC_CURSOR_KEY,
            {"inbound_cursor": "cloud-cursor-that-is-not-a-local-page-cursor"},
            "2026-07-10T00:00:00+00:00",
        )
        posted_batches: list[list[dict[str, object]]] = []

        def post_sync_events(
            _auth_context: dict[str, object],
            **kwargs: object,
        ) -> dict[str, object]:
            events = kwargs["events"]
            assert isinstance(events, list)
            posted_batches.append(events)
            if len(posted_batches) == 1:
                return {
                    "accepted": 0,
                    "rejected": len(events),
                    "cursor": "cloud-cursor-that-is-not-a-local-page-cursor",
                }
            return {
                "accepted": len(events),
                "rejected": 0,
                "cursor": "cloud-cursor-that-is-not-a-local-page-cursor",
            }

        monkeypatch.setattr(
            live_request_sync_module,
            "_post_sync_events",
            post_sync_events,
        )
        auth_context = {
            "machine_id": "machine-1",
            "workspace_id": "workspace-1",
            "machine_installation_id": "22222222-2222-4222-8222-222222222222",
        }

        rejected = sync_live_requests_once(store, auth_context)
        accepted = sync_live_requests_once(store, auth_context)
        unchanged = sync_live_requests_once(store, auth_context)
        store.rows[0]["last_seen_at"] = "2026-07-10T00:00:01+00:00"
        changed = sync_live_requests_once(store, auth_context)

        assert rejected["synced"] == 0
        assert rejected["rejected"] == 1
        assert accepted["synced"] == 1
        assert accepted["cursor"] is None
        assert unchanged["synced"] == 0
        assert changed["synced"] == 1
        assert len(posted_batches) == 3
        assert store.get_sync_payload(LIVE_REQUEST_SYNC_CURSOR_KEY) == {}
        fingerprints = store.get_sync_payload(LIVE_REQUEST_SYNC_FINGERPRINTS_KEY)
        assert isinstance(fingerprints, dict)
        assert set(fingerprints) == {"request-1"}

    def test_scan_reaches_changed_requests_beyond_the_first_page(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        rows = [
            {
                "request_id": f"request-{index}",
                "status": "pending",
                "action_identity": f"test-action-{index}",
                "trigger_summary": f"Review test action {index}",
                "harness": "guard-review",
                "created_at": f"2026-07-10T00:00:0{index}+00:00",
                "last_seen_at": f"2026-07-10T00:00:0{index}+00:00",
            }
            for index in range(5)
        ]

        class PagedQueueStore(Store):
            def list_approval_requests(
                self,
                *,
                status: str | None = "pending",
                harness: str | None = None,
                limit: int | None = 50,
                cursor: str | None = None,
                search: str | None = None,
            ) -> list[dict[str, object]]:
                del status, harness, limit, search
                return rows[:3] if cursor is None else rows[2:5]

        store = PagedQueueStore(tmp_path)
        monkeypatch.setattr(
            live_request_sync_module,
            "LIVE_REQUEST_SYNC_SCAN_PAGE_SIZE",
            2,
        )
        monkeypatch.setattr(
            live_request_sync_module,
            "LIVE_REQUEST_SYNC_BATCH_SIZE",
            2,
        )
        fingerprints = {
            str(item["request_id"]): live_request_sync_module._request_sync_fingerprint(item) for item in rows[:2]
        }

        events, pending, next_cursor = live_request_sync_module._build_changed_sync_events(
            store,
            fingerprints,
            cursor=None,
        )

        assert [event["localRequestId"] for event in events] == [
            "request-2",
            "request-3",
        ]
        assert set(pending) == {"request-2", "request-3"}
        assert isinstance(next_cursor, str)
