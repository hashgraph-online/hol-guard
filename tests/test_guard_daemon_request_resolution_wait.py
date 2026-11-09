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
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    review_request,
)


class _ScriptedStore:
    """The store surface the wait reads: its path and the request row."""

    def __init__(self, path: Path, request_id: str) -> None:
        self.path = path
        self.reads = 0
        self.status_reads = 0
        self._lock = threading.Lock()
        self._row: dict[str, object] = {"request_id": request_id, "status": "pending"}

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._lock:
            self.reads += 1
            return dict(self._row) if request_id == self._row["request_id"] else None

    def get_approval_request_status(self, request_id: str) -> str | None:
        with self._lock:
            self.status_reads += 1
            return str(self._row["status"]) if request_id == self._row["request_id"] else None

    def get_approval_request_statuses(self, request_ids: list[str]) -> dict[str, str]:
        statuses = {request_id: self.get_approval_request_status(request_id) for request_id in request_ids}
        return {request_id: status for request_id, status in statuses.items() if status is not None}

    def resolve(self) -> None:
        with self._lock:
            self._row = {**self._row, "status": "resolved", "resolution_action": "allow"}


class _BulkStore:
    """Several pending requests, counting single and shared status reads."""

    def __init__(self, path: Path, request_ids: list[str]) -> None:
        self.path = path
        self.status_reads = 0
        self.shared_reads = 0
        self._lock = threading.Lock()
        self._statuses = dict.fromkeys(request_ids, "pending")

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._lock:
            status = self._statuses.get(request_id)
        return None if status is None else {"request_id": request_id, "status": status}

    def get_approval_request_status(self, request_id: str) -> str | None:
        with self._lock:
            self.status_reads += 1
            return self._statuses.get(request_id)

    def get_approval_request_statuses(self, request_ids: list[str]) -> dict[str, str]:
        with self._lock:
            self.shared_reads += 1
            return {item: self._statuses[item] for item in request_ids if item in self._statuses}

    def resolve_all(self) -> None:
        with self._lock:
            self._statuses = dict.fromkeys(self._statuses, "resolved")


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
    original_status = store.get_approval_request_status

    def read_status(request_id: str) -> str | None:
        status = original_status(request_id)
        if store.status_reads == 2:
            # Another process decided: the row changed but this daemon heard nothing.
            store.resolve()
        return status

    monkeypatch.setattr(store, "get_approval_request_status", read_status)

    result = wait_for_request_resolution(store, "req-recheck", approval, 5.0)

    assert result is not None
    assert result["status"] == "resolved"
    assert store.status_reads == 3
    # The hook's own read, then the decided request.
    assert store.reads == 2


def test_wakes_while_pending_read_only_the_status(tmp_path: Path, monkeypatch) -> None:
    # A bulk approval wakes every held read once per review event. Those wakes
    # must not each build the full request, or the waiting hooks slow the
    # approvals they wait on.
    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 30.0)
    store = _ScriptedStore(tmp_path / "guard.db", "req-wakes")
    approval = store.get_approval_request("req-wakes")
    assert approval is not None
    signal = review_event_wake_signal(store.path)
    first_status_read = threading.Event()
    woken_status_read = threading.Event()
    read_status = store.get_approval_request_status

    def read_status_once_seen(request_id: str) -> str | None:
        status = read_status(request_id)
        if first_status_read.is_set():
            woken_status_read.set()
        first_status_read.set()
        return status

    monkeypatch.setattr(store, "get_approval_request_status", read_status_once_seen)

    def other_events_then_decide() -> None:
        # Start only once the wait has seen the request pending, so the wakes
        # below land on a held read rather than racing its first check, and
        # decide only after one of them has rechecked a still-pending request.
        assert first_status_read.wait(5.0)
        for _ in range(20):
            time.sleep(0.005)
            signal.notify()
        assert woken_status_read.wait(5.0)
        store.resolve()
        signal.notify()

    decider = threading.Thread(target=other_events_then_decide)
    decider.start()
    result = wait_for_request_resolution(store, "req-wakes", approval, 5.0)
    decider.join()

    assert result is not None
    assert result["status"] == "resolved"
    assert store.status_reads >= 3
    assert store.reads == 2


def test_held_reads_woken_together_share_one_status_read(tmp_path: Path, monkeypatch) -> None:
    # Every review event wakes every held read. In a bulk approval each wake
    # must cost one status read for all the waiting hooks, not one per hook.
    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 30.0)
    request_ids = [f"req-bulk-{index}" for index in range(6)]
    store = _BulkStore(tmp_path / "guard.db", request_ids)
    signal = review_event_wake_signal(store.path)
    results: dict[str, dict[str, object] | None] = {}

    def hold(request_id: str) -> None:
        approval = store.get_approval_request(request_id)
        assert approval is not None
        results[request_id] = wait_for_request_resolution(store, request_id, approval, 5.0)

    holders = [threading.Thread(target=hold, args=(request_id,)) for request_id in request_ids]
    for holder in holders:
        holder.start()
    deadline = time.monotonic() + 5.0
    while store.status_reads < len(request_ids) and time.monotonic() < deadline:
        time.sleep(0.005)
    assert store.status_reads == len(request_ids)

    wakes = 20
    for _ in range(wakes):
        signal.notify()
        time.sleep(0.005)
    store.resolve_all()
    signal.notify()
    for holder in holders:
        holder.join(5.0)

    assert {request_id: (result or {}).get("status") for request_id, result in results.items()} == dict.fromkeys(
        request_ids, "resolved"
    )
    # Each hook read its own status once, before it waited; every wake after
    # that was answered from at most one shared read. Each hook's first read
    # also raises a wake, for Cloud Review delivery.
    assert store.status_reads == len(request_ids)
    assert 1 <= store.shared_reads <= wakes + 1 + len(request_ids)


def test_a_shared_read_is_not_reused_for_a_later_wake(tmp_path: Path, monkeypatch) -> None:
    # A decision committed after a shared read must still end the wait it wakes.
    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 30.0)
    store = _BulkStore(tmp_path / "guard.db", ["req-late"])
    signal = review_event_wake_signal(store.path)
    approval = store.get_approval_request("req-late")
    assert approval is not None

    def events_then_decide() -> None:
        deadline = time.monotonic() + 5.0
        while store.status_reads < 1 and time.monotonic() < deadline:
            time.sleep(0.005)
        signal.notify()
        while store.shared_reads < 1 and time.monotonic() < deadline:
            time.sleep(0.005)
        store.resolve_all()
        signal.notify()

    decider = threading.Thread(target=events_then_decide)
    started = time.monotonic()
    decider.start()
    result = wait_for_request_resolution(store, "req-late", approval, 5.0)
    decider.join()

    assert result is not None
    assert result["status"] == "resolved"
    assert time.monotonic() - started < 2.0
    assert store.shared_reads == 2


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


def test_a_hooks_first_read_of_its_pending_request_wakes_cloud_review_delivery_once(
    tmp_path: Path, monkeypatch
) -> None:
    # The hook's process commits the request, so this daemon's sync worker
    # hears nothing until the hook asks about it.
    monkeypatch.setattr(wait_module, "RESOLUTION_RECHECK_SECONDS", 0.01)
    store = _ScriptedStore(tmp_path / "guard.db", "req-first-read")
    signal = review_event_wake_signal(store.path)
    approval = store.get_approval_request("req-first-read")
    assert approval is not None

    before = signal.generation()
    wait_for_request_resolution(store, "req-first-read", approval, 0.02)
    after_first = signal.generation()
    wait_for_request_resolution(store, "req-first-read", approval, 0.02)

    assert after_first == before + 1
    assert signal.generation() == after_first


def test_reads_that_cannot_need_delivery_do_not_wake_the_sync_worker(tmp_path: Path) -> None:
    store = _ScriptedStore(tmp_path / "guard.db", "req-quiet")
    signal = review_event_wake_signal(store.path)
    approval = store.get_approval_request("req-quiet")
    assert approval is not None
    before = signal.generation()

    # A read that asked for no wait is a dashboard read, not a waiting hook.
    wait_for_request_resolution(store, "req-quiet", approval, 0.0)
    store.resolve()
    resolved = store.get_approval_request("req-quiet")
    assert resolved is not None
    wait_for_request_resolution(store, "req-quiet", resolved, 0.5)

    assert signal.generation() == before


def test_the_record_of_woken_requests_stays_bounded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(wait_module, "MAX_WOKEN_REQUESTS", 2)
    monkeypatch.setattr(wait_module, "_woken_requests", wait_module.OrderedDict())
    signal_path = tmp_path / "guard.db"
    signal = review_event_wake_signal(signal_path)
    before = signal.generation()
    for request_id in ("req-a", "req-b", "req-c", "req-a"):
        store = _ScriptedStore(signal_path, request_id)
        approval = store.get_approval_request(request_id)
        assert approval is not None
        wait_for_request_resolution(store, request_id, approval, 0.01)

    # req-a was evicted by req-c, so its later read wakes again.
    assert signal.generation() == before + 4
    assert len(wait_module._woken_requests) == 2


def test_a_first_read_wakes_delivery_even_when_every_held_slot_is_busy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(wait_module, "_held_reads", threading.BoundedSemaphore(1))
    store = _ScriptedStore(tmp_path / "guard.db", "req-busy-wake")
    signal = review_event_wake_signal(store.path)
    approval = store.get_approval_request("req-busy-wake")
    assert approval is not None
    assert wait_module._held_reads.acquire(blocking=False)
    try:
        before = signal.generation()
        started = time.monotonic()
        result = wait_for_request_resolution(store, "req-busy-wake", approval, 5.0)
        elapsed = time.monotonic() - started
    finally:
        wait_module._held_reads.release()

    # The read is answered at once, yet the sync worker still hears about it.
    assert result == approval
    assert elapsed < 1.0
    assert signal.generation() == before + 1


def test_the_store_reads_a_request_status_without_its_review_payload(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("req-status"))

    assert store.get_approval_request_status("req-status") == "pending"
    request = store.get_approval_request("req-status")
    assert request is not None
    assert request["status"] == "pending"
    assert store.get_approval_request_status("req-missing") is None
    assert store.get_approval_request_statuses(["req-status", "req-missing"]) == {"req-status": "pending"}
    assert store.get_approval_request_statuses([]) == {}
