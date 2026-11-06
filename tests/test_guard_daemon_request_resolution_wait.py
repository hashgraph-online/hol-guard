"""A hook's request read held open until the approval is decided."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon import request_resolution_wait as wait_module
from codex_plugin_scanner.guard.daemon.request_resolution_wait import (
    requested_resolution_wait_seconds,
    wait_for_request_resolution,
)
from codex_plugin_scanner.guard.review_event_wake import review_event_wake_signal


class _ScriptedStore:
    """The store surface the wait reads: its path and the request row."""

    def __init__(self, path: Path, request_id: str) -> None:
        self.path = path
        self.reads = 0
        self._lock = threading.Lock()
        self._row: dict[str, object] = {"request_id": request_id, "status": "pending"}

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._lock:
            self.reads += 1
            return dict(self._row) if request_id == self._row["request_id"] else None

    def resolve(self) -> None:
        with self._lock:
            self._row = {**self._row, "status": "resolved", "resolution_action": "allow"}


def test_wait_query_is_bounded_and_defaults_to_no_wait() -> None:
    assert requested_resolution_wait_seconds("") == 0.0
    assert requested_resolution_wait_seconds("wait_ms=soon") == 0.0
    assert requested_resolution_wait_seconds("wait_ms=-5") == 0.0
    assert requested_resolution_wait_seconds("wait_ms=250") == 0.25
    assert requested_resolution_wait_seconds("wait_ms=60000") == wait_module.MAX_RESOLUTION_WAIT_SECONDS
    assert requested_resolution_wait_seconds("wait_ms=" + "9" * 400) == wait_module.MAX_RESOLUTION_WAIT_SECONDS


def test_a_decision_committed_in_the_daemon_ends_the_wait_at_once(tmp_path: Path, monkeypatch) -> None:
    # A recheck interval longer than the test's patience proves the wake, not
    # the periodic read, ended the wait.
    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 30.0)
    store = _ScriptedStore(tmp_path / "guard.db", "req-wake")
    approval = store.get_approval_request("req-wake")
    assert approval is not None
    # Hold the signal the way a running daemon's sync worker does.
    signal = review_event_wake_signal(store.path)

    def decide() -> None:
        time.sleep(0.05)
        # A decision commit changes the outbox, which notifies the signal.
        store.resolve()
        signal.notify()

    decider = threading.Thread(target=decide)
    started = time.monotonic()
    decider.start()
    result = wait_for_request_resolution(store, "req-wake", approval, 5.0)
    elapsed = time.monotonic() - started
    decider.join()

    assert result is not None
    assert result["status"] == "resolved"
    assert elapsed < 2.0


def test_a_decision_without_a_wake_is_seen_on_the_next_recheck(tmp_path: Path, monkeypatch) -> None:
    store = _ScriptedStore(tmp_path / "guard.db", "req-recheck")
    approval = store.get_approval_request("req-recheck")
    assert approval is not None
    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 0.01)
    original_read = store.get_approval_request

    def read(request_id: str) -> dict[str, object] | None:
        row = original_read(request_id)
        if store.reads == 2:
            # Another process decided: the row changed but this daemon heard nothing.
            store.resolve()
        return row

    monkeypatch.setattr(store, "get_approval_request", read)

    result = wait_for_request_resolution(store, "req-recheck", approval, 5.0)

    assert result is not None
    assert result["status"] == "resolved"
    assert store.reads == 3


def test_a_request_still_pending_is_returned_at_the_deadline(tmp_path: Path, monkeypatch) -> None:
    store = _ScriptedStore(tmp_path / "guard.db", "req-deadline")
    approval = store.get_approval_request("req-deadline")
    assert approval is not None
    clock = [100.0]

    def monotonic() -> float:
        clock[0] += 0.3
        return clock[0]

    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 0.01)

    result = wait_for_request_resolution(store, "req-deadline", approval, 1.0, monotonic=monotonic)

    assert result is not None
    assert result["status"] == "pending"


def test_no_wait_and_settled_requests_answer_immediately(tmp_path: Path) -> None:
    store = _ScriptedStore(tmp_path / "guard.db", "req-immediate")
    approval = store.get_approval_request("req-immediate")
    assert approval is not None

    assert wait_for_request_resolution(store, "req-immediate", approval, 0.0) is approval
    settled = {**approval, "status": "resolved"}
    assert wait_for_request_resolution(store, "req-immediate", settled, 5.0) is settled
    assert store.reads == 1


def test_reads_beyond_the_held_limit_answer_at_once(tmp_path: Path, monkeypatch) -> None:
    # Every held read keeps a daemon request slot, so the rest are answered
    # immediately and their hooks poll instead.
    monkeypatch.setattr(wait_module, "_held_reads", threading.BoundedSemaphore(1))
    store = _ScriptedStore(tmp_path / "guard.db", "req-limit")
    approval = store.get_approval_request("req-limit")
    assert approval is not None
    assert wait_module._held_reads.acquire(blocking=False)
    try:
        started = time.monotonic()
        result = wait_for_request_resolution(store, "req-limit", approval, 5.0)
        assert time.monotonic() - started < 0.5
    finally:
        wait_module._held_reads.release()

    assert result is approval
    assert store.reads == 1
    # The slot is free again once the held read ends.
    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 0.01)
    clock = [0.0]

    def monotonic() -> float:
        clock[0] += 0.3
        return clock[0]

    wait_for_request_resolution(store, "req-limit", approval, 1.0, monotonic=monotonic)
    assert wait_module._held_reads.acquire(blocking=False)
    wait_module._held_reads.release()
