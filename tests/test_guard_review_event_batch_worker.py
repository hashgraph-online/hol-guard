"""Shared batch-worker assertions used by Review outbox delivery coverage."""

from __future__ import annotations

import argparse
import logging
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.cli.commands_review_event_dead_letters import (
    review_event_dead_letter_usage_error,
)
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_event_wake import register_review_event_outbox_wake_callback
from codex_plugin_scanner.guard.runtime import live_request_sync, review_event_worker_lifecycle
from codex_plugin_scanner.guard.runtime.review_event_batch_worker import take_bounded_batch
from codex_plugin_scanner.guard.runtime.review_event_worker_lifecycle import (
    LiveRequestSyncWorker,
    _restart_dead_review_event_worker,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_event_outbox_test_support import connect_store


def assert_byte_capped_batch() -> None:
    """Exercise the byte cap independently of an event's request shape."""

    bounded, oversized = take_bounded_batch(
        [(1, {"payload": "x" * 256}), (2, {"payload": "y" * 256})],
        maximum_events=50,
        maximum_bytes=300,
    )
    assert bounded.sequences == [1] and bounded.byte_size <= 300 and oversized == []


def test_oversized_leading_event_blocks_later_entries() -> None:
    bounded, oversized = take_bounded_batch(
        [(1, {"payload": "x" * 512}), (2, {"payload": "ok"})],
        maximum_events=50,
        maximum_bytes=300,
    )

    assert bounded.sequences == [] and oversized == [1]


def test_watchdog_restarts_confirmed_dead_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state: dict[str, object] = {}

    class ReplacementThread:
        def __init__(self, **_kwargs: object) -> None:
            self.started = False

        def start(self) -> None:
            self.started = True

        def is_alive(self) -> bool:
            return self.started

    sync = SimpleNamespace(
        _load_sync_state=lambda _store: dict(state),
        _state_int=lambda payload, key: int(payload.get(key, 0)),
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _save_sync_state=lambda _store, payload: state.update(payload),
        threading=SimpleNamespace(Thread=ReplacementThread),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.review_event_worker_lifecycle._sync_module",
        lambda: sync,
    )
    worker = LiveRequestSyncWorker(
        thread=threading.Thread(target=lambda: None),
        stop_event=threading.Event(),
        wake_event=threading.Event(),
    )

    store = GuardStore(tmp_path / "guard")
    assert _restart_dead_review_event_worker(store, worker) is True
    assert worker.thread.is_alive() is True
    assert state["watchdog_restart_count"] == 1


def test_requeue_commit_wakes_delivery_worker(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    request = GuardApprovalRequest(
        request_id="request-1",
        harness="codex",
        artifact_id="artifact-1",
        artifact_name="Test action",
        artifact_hash="hash-1",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/test/config.toml",
        review_command="hol-guard approvals approve request-1",
        approval_url="http://127.0.0.1/requests/request-1",
        action_identity="request-1",
        queue_group_id="request-1",
        trigger_summary="Review action",
        last_seen_at="2026-08-24T14:00:00+00:00",
    )
    store.add_approval_request(request, "2026-08-24T14:00:00+00:00")
    wakes: list[None] = []
    unregister = register_review_event_outbox_wake_callback(store, lambda: wakes.append(None))

    assert store.requeue_pending_live_requests(changed_at="2026-08-24T14:00:01+00:00") == 1
    unregister()
    assert wakes == [None]


def test_cross_process_fallback_poll_remains_prompt() -> None:
    assert live_request_sync.DEFAULT_POLL_INTERVAL_SECONDS <= 0.1


def test_dead_letter_cli_rejects_invalid_filters_and_context() -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)

    with pytest.raises(SystemExit):
        parser.parse_args(["connect", "dead-letters", "--retry-dead-letters", "--dead-letter-sequence", "0"])
    ordinary = parser.parse_args(["connect", "--retry-dead-letters"])
    filtered = parser.parse_args(["connect", "dead-letters", "--dead-letter-sequence", "1"])
    assert review_event_dead_letter_usage_error(ordinary, ordinary.connect_command) is not None
    assert review_event_dead_letter_usage_error(filtered, filtered.connect_command) is not None


def test_wake_during_sync_triggers_immediate_follow_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    stop_event = threading.Event()
    wake_event = threading.Event()
    calls: list[int] = []

    def sync_once(_store: GuardStore, _auth: dict[str, object]) -> None:
        calls.append(len(calls) + 1)
        if len(calls) == 1:
            wake_event.set()
        else:
            stop_event.set()

    sync = SimpleNamespace(
        _load_sync_state=lambda _store: {},
        _save_sync_state=lambda _store, _state: None,
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _resolve_live_request_sync_auth_context=lambda _store: {},
        sync_live_requests_once=sync_once,
        _LOGGER=logging.getLogger(__name__),
    )
    monkeypatch.setattr(review_event_worker_lifecycle, "_sync_module", lambda: sync)
    monkeypatch.setattr(review_event_worker_lifecycle, "_cloud_connection_is_ready", lambda _store: True)
    monkeypatch.setattr(review_event_worker_lifecycle, "user_health_report_due", lambda _home: False)
    review_event_worker_lifecycle._cloud_sync_sync_loop(
        store,
        stop_event,
        wake_event=wake_event,
        poll_interval=60,
        error_backoff=1,
    )
    assert calls == [1, 2]


def test_idle_fallback_poll_skips_network_and_state_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    stop_event = threading.Event()
    network_calls = 0
    state_writes = 0

    def sync_once(_store: GuardStore, _auth: dict[str, object]) -> None:
        nonlocal network_calls
        network_calls += 1

    def save_state(_store: GuardStore, _state: dict[str, object]) -> None:
        nonlocal state_writes
        state_writes += 1

    sync = SimpleNamespace(
        DEFAULT_HEALTH_INTERVAL_SECONDS=30.0,
        _load_sync_state=lambda _store: {},
        _save_sync_state=save_state,
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _resolve_live_request_sync_auth_context=lambda _store: {},
        sync_live_requests_once=sync_once,
        _LOGGER=logging.getLogger(__name__),
    )
    monkeypatch.setattr(review_event_worker_lifecycle, "_sync_module", lambda: sync)
    monkeypatch.setattr(review_event_worker_lifecycle, "_cloud_connection_is_ready", lambda _store: True)
    monkeypatch.setattr(review_event_worker_lifecycle, "user_health_report_due", lambda _home: False)
    before = {
        path.relative_to(store.guard_home): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in store.guard_home.rglob("*")
    }

    worker = threading.Thread(
        target=review_event_worker_lifecycle._cloud_sync_sync_loop,
        kwargs={
            "store": store,
            "stop_event": stop_event,
            "wake_event": threading.Event(),
            "poll_interval": 0.001,
            "error_backoff": 1,
        },
    )
    worker.start()
    time.sleep(0.02)
    stop_event.set()
    worker.join(timeout=1)

    assert worker.is_alive() is False
    assert network_calls == 1
    assert state_writes == 1
    after = {
        path.relative_to(store.guard_home): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in store.guard_home.rglob("*")
    }
    assert after == before


def test_retry_deadline_wakes_before_health_cadence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    stop_event = threading.Event()
    calls: list[float] = []

    def sync_once(_store: GuardStore, _auth: dict[str, object]) -> dict[str, object]:
        calls.append(time.monotonic())
        if len(calls) == 2:
            stop_event.set()
        return {"outbox": {"next_attempt_at": "2026-08-24T14:00:00.050000+00:00"}}

    sync = SimpleNamespace(
        DEFAULT_HEALTH_INTERVAL_SECONDS=30.0,
        _load_sync_state=lambda _store: {},
        _save_sync_state=lambda _store, _state: None,
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _resolve_live_request_sync_auth_context=lambda _store: {},
        sync_live_requests_once=sync_once,
        _LOGGER=logging.getLogger(__name__),
    )
    monkeypatch.setattr(review_event_worker_lifecycle, "_sync_module", lambda: sync)
    monkeypatch.setattr(review_event_worker_lifecycle, "_cloud_connection_is_ready", lambda _store: True)
    monkeypatch.setattr(review_event_worker_lifecycle, "user_health_report_due", lambda _home: False)

    review_event_worker_lifecycle._cloud_sync_sync_loop(
        store,
        stop_event,
        wake_event=threading.Event(),
        poll_interval=60,
        error_backoff=1,
    )

    assert len(calls) == 2
    assert 0.03 <= calls[1] - calls[0] < 0.5


def test_event_wake_does_not_postpone_health_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    stop_event = threading.Event()
    wake_event = threading.Event()
    calls: list[float] = []

    def sync_once(_store: GuardStore, _auth: dict[str, object]) -> dict[str, object]:
        calls.append(time.monotonic())
        if len(calls) == 1:
            threading.Timer(0.02, wake_event.set).start()
        elif len(calls) == 3:
            stop_event.set()
        return {"outbox": {"next_attempt_at": None}}

    sync = SimpleNamespace(
        DEFAULT_HEALTH_INTERVAL_SECONDS=0.06,
        _load_sync_state=lambda _store: {},
        _save_sync_state=lambda _store, _state: None,
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _resolve_live_request_sync_auth_context=lambda _store: {},
        sync_live_requests_once=sync_once,
        _LOGGER=logging.getLogger(__name__),
    )
    monkeypatch.setattr(review_event_worker_lifecycle, "_sync_module", lambda: sync)
    monkeypatch.setattr(review_event_worker_lifecycle, "_cloud_connection_is_ready", lambda _store: True)
    monkeypatch.setattr(review_event_worker_lifecycle, "user_health_report_due", lambda _home: False)

    review_event_worker_lifecycle._cloud_sync_sync_loop(
        store,
        stop_event,
        wake_event=wake_event,
        poll_interval=0.005,
        error_backoff=1,
    )

    assert len(calls) == 3
    assert calls[1] - calls[0] < 0.05
    assert 0.05 <= calls[2] - calls[0] < 0.2


def test_disconnected_cloud_clears_due_retry_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    stop_event = threading.Event()
    readiness = iter((True, False))
    network_calls = 0
    state_writes = 0

    def sync_once(_store: GuardStore, _auth: dict[str, object]) -> dict[str, object]:
        nonlocal network_calls
        network_calls += 1
        return {"outbox": {"next_attempt_at": "2026-08-24T14:00:00.010000+00:00"}}

    def save_state(_store: GuardStore, _state: dict[str, object]) -> None:
        nonlocal state_writes
        state_writes += 1

    sync = SimpleNamespace(
        DEFAULT_HEALTH_INTERVAL_SECONDS=30.0,
        _load_sync_state=lambda _store: {},
        _save_sync_state=save_state,
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _resolve_live_request_sync_auth_context=lambda _store: {},
        sync_live_requests_once=sync_once,
        _LOGGER=logging.getLogger(__name__),
    )
    monkeypatch.setattr(review_event_worker_lifecycle, "_sync_module", lambda: sync)
    monkeypatch.setattr(review_event_worker_lifecycle, "_cloud_connection_is_ready", lambda _store: next(readiness))
    monkeypatch.setattr(review_event_worker_lifecycle, "user_health_report_due", lambda _home: False)
    threading.Timer(0.05, stop_event.set).start()

    review_event_worker_lifecycle._cloud_sync_sync_loop(
        store, stop_event, wake_event=threading.Event(), poll_interval=0.005, error_backoff=1
    )

    assert network_calls == 1
    assert state_writes == 3


def test_cross_process_write_is_detected_by_read_only_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard"
    store = GuardStore(guard_home)
    _ = connect_store(store)
    writer = GuardStore(guard_home)
    stop_event = threading.Event()
    second_sync = threading.Event()
    network_calls = 0

    def sync_once(_store: GuardStore, _auth: dict[str, object]) -> None:
        nonlocal network_calls
        network_calls += 1
        if network_calls == 2:
            second_sync.set()
            stop_event.set()

    sync = SimpleNamespace(
        DEFAULT_HEALTH_INTERVAL_SECONDS=30.0,
        _load_sync_state=lambda _store: {},
        _save_sync_state=lambda _store, _state: None,
        _now=lambda: "2026-08-24T14:00:00+00:00",
        _resolve_live_request_sync_auth_context=lambda _store: {},
        sync_live_requests_once=sync_once,
        _LOGGER=logging.getLogger(__name__),
    )
    monkeypatch.setattr(review_event_worker_lifecycle, "_sync_module", lambda: sync)
    monkeypatch.setattr(review_event_worker_lifecycle, "_cloud_connection_is_ready", lambda _store: True)
    monkeypatch.setattr(review_event_worker_lifecycle, "user_health_report_due", lambda _home: False)

    worker = threading.Thread(
        target=review_event_worker_lifecycle._cloud_sync_sync_loop,
        kwargs={
            "store": store,
            "stop_event": stop_event,
            "wake_event": threading.Event(),
            "poll_interval": 0.01,
            "error_backoff": 1,
        },
    )
    worker.start()
    deadline = time.monotonic() + 1
    while network_calls < 1 and time.monotonic() < deadline:
        time.sleep(0.001)
    writer.add_approval_request(
        GuardApprovalRequest(
            request_id="cross-process",
            harness="codex",
            artifact_id="artifact-cross-process",
            artifact_name="Test action",
            artifact_hash="hash-cross-process",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("tool_action_request",),
            source_scope="project",
            config_path="/test/config.toml",
            review_command="hol-guard approvals approve cross-process",
            approval_url="http://127.0.0.1/requests/cross-process",
            action_identity="cross-process",
            queue_group_id="cross-process",
            trigger_summary="Review action",
            last_seen_at="2026-08-24T14:00:00+00:00",
        ),
        "2026-08-24T14:00:00+00:00",
    )

    assert second_sync.wait(timeout=0.5) is True
    worker.join(timeout=1)
    assert worker.is_alive() is False


def test_start_replaces_dead_watchdog_without_replacing_live_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    delivery_stop = threading.Event()
    delivery = threading.Thread(target=delivery_stop.wait)
    delivery.start()
    old_watchdog = threading.Thread(target=lambda: None)
    old_watchdog.start()
    old_watchdog.join()
    worker = LiveRequestSyncWorker(
        thread=delivery,
        stop_event=threading.Event(),
        wake_event=threading.Event(),
        watchdog_thread=old_watchdog,
    )
    started: list[threading.Thread] = []

    def start_watchdog(_store: GuardStore, current: LiveRequestSyncWorker) -> None:
        replacement = threading.Thread(target=current.stop_event.wait)
        current.watchdog_thread = replacement
        replacement.start()
        started.append(replacement)

    monkeypatch.setattr(review_event_worker_lifecycle, "_start_review_event_watchdog", start_watchdog)
    monkeypatch.setattr(
        review_event_worker_lifecycle,
        "_sync_module",
        lambda: SimpleNamespace(threading=threading),
    )

    try:
        assert review_event_worker_lifecycle.start_cloud_sync_sync_worker(store, worker) is worker
        assert worker.thread is delivery
        assert len(started) == 1 and started[0].is_alive()
    finally:
        worker.stop_event.set()
        delivery_stop.set()
        delivery.join()
        for thread in started:
            thread.join()


def test_watchdog_survives_transient_state_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    stop_event = threading.Event()
    checks = 0
    worker = LiveRequestSyncWorker(
        thread=threading.current_thread(),
        stop_event=stop_event,
        wake_event=threading.Event(),
    )

    def check(_store: GuardStore, _worker: LiveRequestSyncWorker) -> None:
        nonlocal checks
        checks += 1
        if checks == 1:
            raise OSError("temporary")
        stop_event.set()

    logger = SimpleNamespace(warning=lambda *_args: None)
    monkeypatch.setattr(review_event_worker_lifecycle, "_configured_seconds", lambda *_args: 0.001)
    monkeypatch.setattr(review_event_worker_lifecycle, "_record_stalled_heartbeat_if_needed", check)
    monkeypatch.setattr(review_event_worker_lifecycle, "_sync_module", lambda: SimpleNamespace(_LOGGER=logger))

    review_event_worker_lifecycle._watch_review_event_worker(store, worker)
    assert checks == 2
