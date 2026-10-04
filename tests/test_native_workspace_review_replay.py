from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.review_contracts import GuardReviewOAuthMetadata
from codex_plugin_scanner.guard.runtime import cloud_review_event_projection as projection
from codex_plugin_scanner.guard.runtime import native_workspace_review_replay as replay
from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import project_cloud_review_event
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_review_event_outbox import _all_events, _connect, _request


def _binding() -> dict[str, str]:
    return {
        "oauth_source": "default",
        "oauth_subject_hash": "a" * 64,
        "workspace_id": "workspace-1",
        "machine_id": "machine-1",
        "machine_installation_id": "installation-1",
    }


def _context() -> dict[str, object]:
    return {
        "authority_generation": 3,
        "authority_record_digest": "b" * 64,
    }


def _native_context() -> dict[str, object]:
    return {
        **_context(),
        "action_binding": "c" * 64,
        "intent_binding": "d" * 64,
        "policy_binding": "e" * 64,
    }


def _accepted_event(request_id: str = "request-1") -> dict[str, object]:
    return {
        "localRequestId": request_id,
        "reviewClaim": {
            "nativeActionBinding": "c" * 64,
            "nativeIntentBinding": "d" * 64,
            "nativePolicyBinding": "e" * 64,
        },
        "requestPayload": {"nativeWorkspaceReview": _native_context()},
    }


class _ReplayStore:
    guard_home: Path
    guard_source = "default"

    def __init__(self, tmp_path: Path, request_ids: list[str]) -> None:
        self.guard_home = tmp_path
        self.binding = _binding()
        self.request_ids = request_ids
        self.payloads: dict[str, object] = {}
        self.context_calls: list[str] = []
        self.requeue_calls: list[dict[str, object]] = []
        self.list_calls = 0
        self.requeue_result = 1
        self.fail_marker_update = False

    def get_review_event_oauth_binding(self) -> dict[str, str]:
        return dict(self.binding)

    def get_sync_payload(self, key: str) -> object | None:
        return self.payloads.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        del now
        if self.fail_marker_update and ":request:" in key:
            raise OSError("marker update failed")
        self.payloads[key] = payload

    def list_pending_review_request_ids(
        self,
        *,
        binding: dict[str, str],
        limit: int,
        after_request_id: str | None = None,
        through_request_id: str | None = None,
        descending: bool = False,
    ) -> list[str]:
        self.list_calls += 1
        if binding != self.binding:
            return []
        candidates = sorted(
            request_id
            for request_id in self.request_ids
            if (after_request_id is None or request_id > after_request_id)
            and (through_request_id is None or request_id <= through_request_id)
        )
        return list(reversed(candidates))[:limit] if descending else candidates[:limit]

    def requeue_pending_review_events_with_marker(
        self,
        *,
        changed_at: str,
        marker_key: str,
        marker_payload: dict[str, object],
        require_binding: bool = False,
        request_ids: set[str] | None = None,
    ) -> int:
        self.requeue_calls.append(
            {
                "changed_at": changed_at,
                "marker_key": marker_key,
                "marker_payload": dict(marker_payload),
                "require_binding": require_binding,
                "request_ids": set(request_ids or ()),
            }
        )
        self.payloads[marker_key] = {**marker_payload, "requeued": self.requeue_result}
        return self.requeue_result


def test_replay_rotates_past_failed_first_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, [f"request-{index:02d}" for index in range(10)])

    def context(_store: object, _home: Path, request_id: str) -> dict[str, object] | None:
        store.context_calls.append(request_id)
        return _context() if request_id >= "request-08" else None

    monkeypatch.setattr(replay, "build_native_workspace_review_context", context)

    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    assert store.context_calls == ["request-00", "request-01"]
    for _ in range(3):
        assert (
            replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding)
            == 0
        )
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 2
    )
    assert store.context_calls[-2:] == ["request-08", "request-09"]
    assert [call["request_ids"] for call in store.requeue_calls] == [{"request-08"}, {"request-09"}]


def test_replay_revisits_lower_ids_despite_continuous_full_batches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _ReplayStore(tmp_path, [f"request-{index:02d}" for index in range(4)])

    def context(_store: object, _home: Path, request_id: str) -> None:
        store.context_calls.append(request_id)

    monkeypatch.setattr(replay, "build_native_workspace_review_context", context)

    def prepare() -> int:
        return replay.prepare_native_workspace_review_replay(
            cast(GuardStore, cast(object, store)), binding=store.binding, force_probe=True
        )

    assert prepare() == 0
    store.request_ids.extend(["request--1", "request-99"])
    assert prepare() == 0
    store.request_ids.append("request-100")
    assert prepare() == 0
    assert store.context_calls == ["request-00", "request-01", "request-02", "request-03", "request--1", "request-00"]


def test_legacy_unbounded_cursor_restarts_from_lower_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, ["request-00", "request-99"])
    replay_store = cast(replay._NativeWorkspaceReplayStore, cast(object, store))
    store.payloads[replay._scan_key(replay_store)] = {"binding": store.binding, "cursor": "request-99"}

    def context(_store: object, _home: Path, request_id: str) -> None:
        store.context_calls.append(request_id)

    monkeypatch.setattr(replay, "build_native_workspace_review_context", context)
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    assert store.context_calls == ["request-00", "request-99"]


def test_failed_markers_are_revisited_after_finite_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, [f"request-{index:02d}" for index in range(4)])
    store.fail_marker_update = True

    def context(_store: object, _home: Path, request_id: str) -> None:
        store.context_calls.append(request_id)

    monkeypatch.setattr(replay, "build_native_workspace_review_context", context)
    for _ in range(3):
        assert (
            replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding)
            == 0
        )
    assert store.context_calls == ["request-00", "request-01", "request-02", "request-03", "request-00", "request-01"]
    assert not any(":request:" in key for key in store.payloads)


def test_interrupted_batch_does_not_advance_scan_progress(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, ["request-00", "request-01"])
    read_marker = replay._request_marker

    def interrupted_marker(*_args: object) -> tuple[str, dict[str, object] | None]:
        raise OSError("interrupted batch")

    monkeypatch.setattr(replay, "_request_marker", interrupted_marker)
    with pytest.raises(OSError, match="interrupted batch"):
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding)
    assert store.payloads == {}
    monkeypatch.setattr(replay, "_request_marker", read_marker)

    def context(_store: object, _home: Path, request_id: str) -> None:
        store.context_calls.append(request_id)

    monkeypatch.setattr(replay, "build_native_workspace_review_context", context)
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    assert store.context_calls == ["request-00", "request-01"]


def test_pending_scan_bounds_are_binding_checked_in_sqlite(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    _connect(store)
    for request_id in ("request-00", "request-01", "request-02"):
        store.add_approval_request(_request(request_id), "2026-09-27T12:00:00+00:00")
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    assert store.list_pending_review_request_ids(binding=binding, limit=1, descending=True) == ["request-02"]
    assert store.list_pending_review_request_ids(
        binding=binding, limit=2, after_request_id="request-00", through_request_id="request-01"
    ) == ["request-01"]
    assert store.list_pending_review_request_ids(binding={**binding, "machine_id": "other"}, limit=1) == []


def test_replay_marker_prevents_duplicate_flood_and_projects_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard")
    delivery_binding = _connect(store)
    store.add_approval_request(_request("request-native"), "2026-09-27T12:00:00+00:00")
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    context = _context()
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: context)

    projection_calls = 0

    def transient_projection(*_args: object) -> dict[str, object] | None:
        nonlocal projection_calls
        projection_calls += 1
        return None if projection_calls == 1 else context

    monkeypatch.setattr(projection, "build_native_workspace_review_context", transient_projection)
    monkeypatch.setattr(projection, "build_local_review_request_claim", lambda **_kwargs: None)

    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1
    rows = [dict(row) for row in _all_events(store)]
    snapshot = next(row for row in rows if row["event_type"] == "review.request.snapshot_requeued")
    assert json.loads(str(snapshot["payload_json"]))["nativeReplay"] is True
    snapshot["sequence"] = snapshot["stream_sequence"]
    projected = project_cloud_review_event(
        store,
        outbox_row=snapshot,
        delivery_binding=cast(dict[str, str], dict(delivery_binding)),
        redaction_level="none",
        oauth=cast(GuardReviewOAuthMetadata, object()),
    )
    assert projected is None
    with store._connect() as connection:
        quarantined = connection.execute(
            "select binding_status, quarantine_reason, next_attempt_at, last_error "
            "from guard_review_outbox_events where stream_sequence = ?",
            (snapshot_sequence := int(snapshot["stream_sequence"]),),
        ).fetchone()
    assert quarantined is not None
    assert quarantined["binding_status"] == "ready"
    assert quarantined["quarantine_reason"] is None
    assert isinstance(quarantined["next_attempt_at"], str)
    assert quarantined["last_error"] == (
        "Native replay event requires temporarily unavailable native workspace review context."
    )

    store.acknowledge_review_events([snapshot_sequence], **delivery_binding)
    with store._connect() as connection:
        marker_row = connection.execute(
            "select state_key, payload_json from sync_state where state_key like ?",
            ("guard_cloud_review_native_workspace_review_replay:default:request:%",),
        ).fetchone()
    assert marker_row is not None
    marker = json.loads(str(marker_row["payload_json"]))
    marker["next_probe_at"] = "2000-01-01T00:00:00+00:00"
    store.set_sync_payload(str(marker_row["state_key"]), marker, "2026-09-27T12:00:01+00:00")

    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1
    rows = [dict(row) for row in _all_events(store)]
    newest_sequence = max(int(row["stream_sequence"]) for row in rows)
    refreshed = next(row for row in rows if int(row["stream_sequence"]) == newest_sequence)
    refreshed["sequence"] = refreshed["stream_sequence"]
    projected = project_cloud_review_event(
        store,
        outbox_row=refreshed,
        delivery_binding=cast(dict[str, str], dict(delivery_binding)),
        redaction_level="none",
        oauth=cast(GuardReviewOAuthMetadata, object()),
    )
    assert projected is not None
    assert "nativeReplay" not in projected[1]
    assert json.loads(str(projected[1]["eventPayloadJson"]))["nativeReplay"] is True
    payload = projected[1]["requestPayload"]
    assert isinstance(payload, dict)
    assert payload["nativeWorkspaceReview"] == context
    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 0
    request = store.get_approval_request("request-native")
    assert request is not None and request["status"] == "pending"
    assert len(rows) == 3


def test_replay_context_uses_authenticated_frozen_snapshot_not_live_display_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    _connect(store)
    store.add_approval_request(
        replace(
            _request("request-frozen-replay"),
            launch_target="chrome-devtools navigate_page unknown",
            browser_intent={"intent": "browser.navigation", "target_domain": "hol.org"},
        ),
        "2026-09-27T12:00:00+00:00",
    )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    captured: list[dict[str, object] | None] = []

    def context(
        _store: object,
        _home: Path,
        _request_id: str,
        request_snapshot: dict[str, object],
    ) -> dict[str, object]:
        captured.append(request_snapshot)
        return _native_context()

    monkeypatch.setattr(replay, "build_native_workspace_review_context", context)
    monkeypatch.setattr(store, "get_approval_request", pytest.fail)

    assert replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=binding) == 1
    assert captured and captured[0] is not None
    assert captured[0]["launch_target"] == "chrome-devtools navigate_page unknown"
    assert captured[0]["browser_intent_json"] == {"intent": "browser.navigation", "target_domain": "hol.org"}


def test_missing_authority_is_retryable_without_requeue_flood(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, ["request-1"])
    monkeypatch.setattr(
        replay,
        "build_native_workspace_review_context",
        lambda *_args: store.context_calls.append("request-1") or None,
    )

    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    assert store.context_calls == ["request-1"]
    assert store.requeue_calls == []
    assert any(":request:" in key for key in store.payloads)


def test_atomic_requeue_marker_retains_cooldown_when_followup_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _ReplayStore(tmp_path, ["request-1"])
    store.fail_marker_update = True
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: _native_context())

    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 1
    )
    assert len(store.requeue_calls) == 1
    marker_key = next(key for key in store.payloads if ":request:" in key)
    marker = cast(dict[str, object], store.payloads[marker_key])
    assert isinstance(marker.get("next_probe_at"), str)

    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    assert len(store.requeue_calls) == 1


def test_accepted_authority_is_completed_but_still_probed_for_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _ReplayStore(tmp_path, ["request-1"])
    context = _native_context()
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: context)

    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 1
    )
    assert replay.mark_native_workspace_review_context_accepted(
        cast(GuardStore, cast(object, store)),
        event=_accepted_event(),
        binding=store.binding,
    )
    marker_key = next(key for key in store.payloads if ":request:" in key)
    marker = cast(dict[str, object], store.payloads[marker_key])
    assert marker["accepted"] is True

    marker["next_probe_at"] = "2000-01-01T00:00:00+00:00"
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    assert len(store.requeue_calls) == 1
    refreshed_marker = cast(dict[str, object], store.payloads[marker_key])
    assert refreshed_marker["next_probe_at"] != "2000-01-01T00:00:00+00:00"

    rotated = {**context, "authority_generation": 4, "authority_record_digest": "f" * 64}
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: rotated)
    refreshed_marker["next_probe_at"] = "2000-01-01T00:00:00+00:00"
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 1
    )
    assert len(store.requeue_calls) == 2


def test_invalid_claim_bindings_do_not_complete_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, ["request-1"])
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: _native_context())
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 1
    )

    event = _accepted_event()
    claim = cast(dict[str, object], event["reviewClaim"])
    claim["nativePolicyBinding"] = "0" * 64
    assert not replay.mark_native_workspace_review_context_accepted(
        cast(GuardStore, cast(object, store)), event=event, binding=store.binding
    )
    marker = next(value for key, value in store.payloads.items() if ":request:" in key)
    assert cast(dict[str, object], marker).get("accepted") is None


def test_zero_append_probe_can_still_complete_prior_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ReplayStore(tmp_path, ["request-1"])
    monkeypatch.setattr(replay, "build_native_workspace_review_context", lambda *_args: _native_context())
    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 1
    )
    marker_key = next(key for key in store.payloads if ":request:" in key)
    marker = cast(dict[str, object], store.payloads[marker_key])
    marker["next_probe_at"] = "2000-01-01T00:00:00+00:00"
    store.requeue_result = 0

    assert (
        replay.prepare_native_workspace_review_replay(cast(GuardStore, cast(object, store)), binding=store.binding) == 0
    )
    marker = cast(dict[str, object], store.payloads[marker_key])
    assert marker["requeued"] == 0
    assert marker["replay_attempts"] == 2
    assert replay.mark_native_workspace_review_context_accepted(
        cast(GuardStore, cast(object, store)),
        event=_accepted_event(),
        binding=store.binding,
    )
