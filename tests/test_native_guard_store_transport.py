"""Transport, paging, oversize and unavailable-status behavior of the native Review outbox store."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_guard_store, store_review_event_outbox
from codex_plugin_scanner.guard.cli.connect_flow import build_connect_status_payload
from codex_plugin_scanner.guard.daemon.cloud_review_settings import cloud_review_settings_status
from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.runtime.cloud_review_sync import cloud_review_sync_status
from codex_plugin_scanner.guard.store import GuardStore

# pyright: reportAny=false, reportPrivateUsage=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false


_IDENTITY: dict[str, Any] = {
    "oauth_subject_hash": "a" * 64,
    "workspace_id": "workspace-1",
    "machine_id": "machine-1",
    "machine_installation_id": "install-1",
}


def _unavailable_native(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(**_kwargs: Any) -> tuple[Any, int | None]:
        raise native_guard_store._unavailable("native_guard_store_prerequisite_unavailable")

    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", refuse)


def test_connect_status_reports_unavailable_outbox_instead_of_falling_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _unavailable_native(monkeypatch)
    payload = build_connect_status_payload(
        store=store,
        sync_url="https://hol.org/api/guard/receipts/sync",
        connect_url="https://hol.org/guard/connect",
    )
    outbox = payload["review_event_outbox"]
    assert isinstance(outbox, dict)
    assert outbox["outbox_available"] is False
    assert outbox["unavailable_reason"] == "native_guard_store_prerequisite_unavailable"


def test_cloud_review_settings_status_flags_unavailable_outbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _unavailable_native(monkeypatch)
    status = cloud_review_settings_status(store)
    assert status["outbox_available"] is False
    assert status["outbox_unavailable_reason"] == "native_guard_store_prerequisite_unavailable"
    assert status["pending_uploads"] == 0


def test_cloud_review_sync_status_reports_unavailable_outbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _unavailable_native(monkeypatch)
    status = cloud_review_sync_status(store)
    outbox = status["outbox"]
    assert isinstance(outbox, dict)
    assert outbox["outbox_available"] is False
    assert outbox["unavailable_reason"] == "native_guard_store_prerequisite_unavailable"


def test_unavailable_error_is_never_swallowed_by_non_status_callers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _unavailable_native(monkeypatch)
    with pytest.raises(NativeGuardStoreUnavailable):
        store.refresh_review_event_outbox_binding()


def test_invalid_reason_from_the_resident_is_surfaced() -> None:
    with pytest.raises(NativeGuardStoreUnavailable) as raised:
        native_guard_store._raise_for_code(
            "native_guard_store_invalid", {"message": "native_guard_store_unknown_method"}
        )
    assert raised.value.reason == "native_guard_store_unknown_method"
    with pytest.raises(NativeGuardStoreUnavailable) as raised:
        native_guard_store._raise_for_code("native_guard_store_invalid", {"message": "free text, not a code"})
    assert raised.value.reason == "native_guard_store_invalid"


def _patch_transport(
    monkeypatch: pytest.MonkeyPatch, clock: list[float], seen: dict[str, Any], on_request: Callable[[], None]
) -> None:
    monkeypatch.setattr(native_guard_store, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_guard_store.time, "monotonic", lambda: clock[0])

    def request(**kwargs: Any) -> None:
        seen.update(kwargs)
        on_request()
        return None

    monkeypatch.setattr(native_guard_store, "_resident_request", request)


def _call(tmp_path: Path, deadline: float) -> None:
    native_guard_store.native_guard_store_call(
        store_path=tmp_path / "guard.db",
        guard_home=tmp_path,
        source="default",
        method="get_review_event_oauth_binding",
        args={},
        deadline_monotonic=deadline,
    )


def test_transport_wait_is_capped_at_the_callers_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    seen: dict[str, Any] = {}
    _patch_transport(monkeypatch, clock, seen, lambda: None)
    with pytest.raises(NativeGuardStoreUnavailable):
        _call(tmp_path, deadline=103.0)
    assert seen["timeout_seconds"] == pytest.approx(3.0)
    assert seen["request"]["busy_timeout_ms"] == 3000


def test_transport_does_not_start_after_the_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [105.0]
    seen: dict[str, Any] = {}
    _patch_transport(monkeypatch, clock, seen, lambda: None)
    with pytest.raises(TimeoutError):
        _call(tmp_path, deadline=105.0)
    assert seen == {}


def test_transport_uses_budget_left_after_the_gate_wait(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [100.0]
    seen: dict[str, Any] = {}
    _patch_transport(monkeypatch, clock, seen, lambda: None)
    clock[0] = 108.0  # the storage gate consumed most of a 10 s budget
    with pytest.raises(NativeGuardStoreUnavailable):
        _call(tmp_path, deadline=110.0)
    assert seen["timeout_seconds"] == pytest.approx(2.0)
    assert seen["request"]["busy_timeout_ms"] == 2000


def test_store_records_native_call_timing_in_the_sqlite_profiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", lambda **_kwargs: (None, None))
    _ = store.get_review_event_oauth_binding()
    assert store._sqlite_profiler().snapshot()["transactions"] >= 1


def test_busy_native_call_counts_as_busy_locked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")

    def busy(**_kwargs: Any) -> tuple[Any, int | None]:
        native_guard_store._raise_for_code("native_guard_store_busy", None)
        raise AssertionError("unreachable")

    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", busy)
    with pytest.raises(sqlite3.OperationalError):
        store.get_review_event_oauth_binding()
    assert store._sqlite_profiler().snapshot()["busy_locked"] >= 1


def test_snapshot_history_follows_the_resident_cursor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    pages = [
        {"snapshots": [{"n": 1}, {"n": 2}], "next": {"request_sequence": 5, "stream_sequence": 2}},
        {"snapshots": [{"n": 3}], "next": None},
    ]
    sent: list[dict[str, Any]] = []

    def call(**kwargs: Any) -> tuple[Any, None]:
        sent.append(dict(kwargs["args"]))
        return pages[len(sent) - 1], None

    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", call)
    assert store.list_review_event_snapshots("request-1") == [{"n": 1}, {"n": 2}, {"n": 3}]
    assert sent == [
        {"request_id": "request-1"},
        {"request_id": "request-1", "after": {"request_sequence": 5, "stream_sequence": 2}},
    ]


def test_snapshot_paging_without_progress_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    cursor = {"request_sequence": 5, "stream_sequence": 2}
    monkeypatch.setattr(
        store_review_event_outbox,
        "native_guard_store_call",
        lambda **_kwargs: ({"snapshots": [{"n": 1}], "next": cursor}, None),
    )
    with pytest.raises(ValueError, match="no progress"):
        _ = store.list_review_event_snapshots("request-1")


def test_oversized_ready_event_is_quarantined_then_the_batch_is_requeried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _IDENTITY
    replies: list[list[dict[str, object]]] = [
        [{"sequence": 7, "payload_json": "", "payload_oversized": True, "payload_bytes": 3_000_000, **identity}],
        [{"sequence": 8, "payload_json": "{}", **identity}],
    ]
    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", lambda **_kwargs: (replies.pop(0), None))
    quarantined: list[tuple[int, dict[str, Any]]] = []

    def quarantine(sequence: int, **kwargs: Any) -> int:
        quarantined.append((sequence, kwargs))
        return 1

    monkeypatch.setattr(store, "quarantine_review_event", quarantine)
    events = store.list_ready_review_events(now="2026-09-01T12:00:00+00:00", limit=10, **identity)
    assert [event["sequence"] for event in events] == [8]
    assert quarantined[0][0] == 7
    assert quarantined[0][1]["reason"] == "event_exceeds_upload_limit"


def test_unquarantinable_oversized_event_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    identity = _IDENTITY
    reply = [{"sequence": 7, "payload_json": "", "payload_oversized": True, "payload_bytes": 9, **identity}]
    monkeypatch.setattr(store_review_event_outbox, "native_guard_store_call", lambda **_kwargs: (reply, None))
    monkeypatch.setattr(store, "quarantine_review_event", lambda *_a, **_k: 0)
    with pytest.raises(ValueError, match="could not be quarantined"):
        _ = store.list_ready_review_events(now="2026-09-01T12:00:00+00:00", limit=10, **identity)


def test_idle_watcher_does_not_stay_alive_on_an_unavailable_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import time

    from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer

    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=1)
    _unavailable_native(monkeypatch)
    monkeypatch.setattr(store, "get_cloud_sync_profile", lambda: {"workspace_id": "workspace-1"})
    shutdowns: list[bool] = []
    monkeypatch.setattr(daemon._server, "shutdown", lambda: shutdowns.append(True))
    daemon._server.last_activity_monotonic = time.monotonic() - 30
    daemon._watch_for_idle_shutdown()
    assert shutdowns == [True]
