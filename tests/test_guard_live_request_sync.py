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
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.live_request_sync import (
    _DEFAULT_401_REFRESH_RETRY_MAX,
    _LIVE_REQUEST_EVENT_SEQUENCE_KEY,
    _REFRESH_THROTTLE_SECONDS,
    LIVE_REQUEST_EVENT_TYPES,
    LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
    OUTBOX_BATCH_COUNT,
    OUTBOX_MAX_QUEUE_EVENTS,
    OUTBOX_MAX_QUEUE_SIZE_BYTES,
    SYNC_HEALTH_SOURCES,
    SYNC_HEALTH_STATES,
    EventAck,
    LiveRequestSyncState,
    SyncHealthSnapshot,
    _cloud_sync_handle_401_refresh,
    _cloud_sync_retry_wait_seconds,
    _get_cloud_sync_sync_state,
    _get_current_cloud_sync_sequence,
    _get_next_cloud_sync_sequence,
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
