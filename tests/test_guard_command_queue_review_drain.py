from __future__ import annotations

import contextvars
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_capability, command_queue, command_queue_drain
from codex_plugin_scanner.guard.runtime.command_queue_state import (
    COMMAND_QUEUE_STATE_KEY,
    current_command_queue_lane,
    enter_command_queue_lane,
    load_command_queue_state,
    save_command_queue_state,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import EXACT_CLOUD_REVIEW_TRANSPORT
from tests.test_guard_command_queue import FakeStore, _context

_GENERIC_OPERATION = "guard.packageShims.status"


def _in_lane(slot: int, action):
    """Run ``action`` in a fresh context bound to drain ``slot``."""

    def run():
        enter_command_queue_lane(command_queue_drain.review_drain_lane(slot))
        return action()

    return contextvars.Context().run(run)


def _exact_job(job_id: str) -> dict[str, object]:
    return {"id": job_id, "_guardCommandTransport": EXACT_CLOUD_REVIEW_TRANSPORT}


def _capture_lease(monkeypatch: pytest.MonkeyPatch, operations: tuple[str, ...]) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(command_queue, "lease_ready_operations", lambda _store: operations)
    monkeypatch.setattr(command_queue, "_command_queue_lease_wait_ms", lambda: 25_000)

    def fake_lease_next_job(**kwargs: object) -> None:
        calls.append({"operations": kwargs["operations"], "wait_ms": kwargs["wait_ms"]})
        return None

    monkeypatch.setattr(command_queue, "lease_next_job", fake_lease_next_job)
    return calls


def test_main_lane_leases_every_ready_operation_with_the_long_poll(tmp_path: Path, monkeypatch) -> None:
    calls = _capture_lease(monkeypatch, (_GENERIC_OPERATION, EXACT_CLOUD_REVIEW_OPERATION))

    command_queue._lease_next_job(FakeStore(tmp_path / "guard-home"), {})

    assert calls == [{"operations": (_GENERIC_OPERATION, EXACT_CLOUD_REVIEW_OPERATION), "wait_ms": 25_000}]


def test_drain_lane_leases_exact_review_jobs_only_without_waiting(tmp_path: Path, monkeypatch) -> None:
    calls = _capture_lease(monkeypatch, (_GENERIC_OPERATION, EXACT_CLOUD_REVIEW_OPERATION))
    store = FakeStore(tmp_path / "guard-home")

    _in_lane(0, lambda: command_queue._lease_next_job(store, {}))

    assert calls == [{"operations": (EXACT_CLOUD_REVIEW_OPERATION,), "wait_ms": 0}]


def test_drain_lane_does_not_lease_when_exact_review_is_not_ready(tmp_path: Path, monkeypatch) -> None:
    calls = _capture_lease(monkeypatch, (_GENERIC_OPERATION,))
    store = FakeStore(tmp_path / "guard-home")

    assert _in_lane(0, lambda: command_queue._lease_next_job(store, {})) is None
    assert calls == []


def test_each_drain_lane_keeps_its_own_queue_state(tmp_path: Path) -> None:
    store = FakeStore(tmp_path / "guard-home")
    save_command_queue_state(store, {"state": "idle", "marker": "main"})

    def write_drain_state() -> None:
        state = load_command_queue_state(store)
        assert state.get("marker") is None
        state["marker"] = "drain-1"
        save_command_queue_state(store, state)

    _in_lane(1, write_drain_state)

    assert load_command_queue_state(store)["marker"] == "main"
    assert store.get_sync_payload(f"{COMMAND_QUEUE_STATE_KEY}.review_drain.1")["marker"] == "drain-1"
    assert current_command_queue_lane().is_drain is False


def _enable_queue(store: FakeStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(command_queue, "command_queue_should_poll", lambda _store: True)
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {"access_token": "token"},
    )
    monkeypatch.setattr(command_queue, "_retry_pending_result", lambda *_args: False)


def test_drain_lane_skips_auto_update_on_an_empty_lease(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lambda *_args: None)
    updates: list[str] = []
    monkeypatch.setattr(command_queue, "maybe_auto_update", lambda *_args: updates.append("main"))
    context = _context(tmp_path)

    drained = _in_lane(0, lambda: command_queue.poll_command_queue_once(store, context))
    assert drained["last_poll_was_empty"] is True
    assert updates == []

    command_queue.poll_command_queue_once(store, context)
    assert updates == ["main"]


@pytest.mark.parametrize(("job", "expected"), [(_exact_job("job-1"), ["start"]), ({"id": "job-2"}, [])])
def test_poll_once_starts_drains_when_it_leases_an_exact_review_job(
    tmp_path: Path, monkeypatch, job: dict[str, object], expected: list[str]
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lambda *_args: dict(job))
    events: list[str] = []

    def stop_after_lease(*_args: object) -> None:
        raise RuntimeError("stop after lease")

    monkeypatch.setattr(command_queue, "_heartbeat", stop_after_lease)

    with pytest.raises(RuntimeError, match="stop after lease"):
        command_queue.poll_command_queue_once(
            store,
            _context(tmp_path),
            on_exact_review_lease=lambda: events.append("start"),
        )

    assert events == expected


def test_poll_once_settles_the_leased_job_when_drains_fail_to_start(tmp_path: Path, monkeypatch, caplog) -> None:
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lambda *_args: _exact_job("job-1"))
    heartbeats: list[str] = []

    def stop_after_heartbeat(_auth_context: object, job: dict[str, object]) -> None:
        heartbeats.append(str(job["id"]))
        raise RuntimeError("stop after heartbeat")

    def fail_to_start() -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(command_queue, "_heartbeat", stop_after_heartbeat)

    with pytest.raises(RuntimeError, match="stop after heartbeat"):
        command_queue.poll_command_queue_once(store, _context(tmp_path), on_exact_review_lease=fail_to_start)

    assert heartbeats == ["job-1"]
    assert "Guard Review drain start failed" in caplog.text


def _run_drain_worker(tmp_path: Path, poll_once, *, format_error=str) -> None:
    contextvars.Context().run(
        command_queue_drain.drain_review_jobs,
        FakeStore(tmp_path / "guard-home"),
        _context(tmp_path),
        slot=0,
        stop_event=threading.Event(),
        poll_once=poll_once,
        format_error=format_error,
    )


@pytest.fixture
def no_retry_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(command_queue_drain, "REVIEW_DRAIN_RETRY_DELAYS_SECONDS", (0.0, 0.0, 0.0))


def test_drain_worker_stops_at_its_first_empty_lease(tmp_path: Path) -> None:
    statuses = [
        {"state": "idle", "last_poll_was_empty": False},
        {"state": "idle", "last_poll_was_empty": False},
        {"state": "idle", "last_poll_was_empty": True},
    ]
    lanes: list[str] = []

    def poll_once(_store: object, _context: object) -> dict[str, object]:
        lanes.append(current_command_queue_lane().state_key)
        return statuses[len(lanes) - 1]

    contextvars.Context().run(
        command_queue_drain.drain_review_jobs,
        FakeStore(tmp_path / "guard-home"),
        _context(tmp_path),
        slot=2,
        stop_event=threading.Event(),
        poll_once=poll_once,
        format_error=str,
    )

    assert lanes == [f"{COMMAND_QUEUE_STATE_KEY}.review_drain.2"] * 3


@pytest.mark.parametrize("state", ["error", "auth_expired", "disabled"])
def test_drain_worker_stops_on_a_state_a_retry_cannot_fix(tmp_path: Path, no_retry_delay, state: str) -> None:
    calls: list[int] = []

    def poll_once(_store: object, _context: object) -> dict[str, object]:
        calls.append(1)
        return {"state": state}

    _run_drain_worker(tmp_path, poll_once)

    assert calls == [1]


def test_drain_worker_retries_an_unsent_result_then_keeps_draining(tmp_path: Path, no_retry_delay) -> None:
    statuses = iter(
        [
            {"state": "result_pending"},
            {"state": "result_pending"},
            {"state": "idle", "last_poll_was_empty": False},
            {"state": "result_pending"},
            {"state": "idle", "last_poll_was_empty": True},
        ]
    )
    calls: list[int] = []

    def poll_once(_store: object, _context: object) -> dict[str, object]:
        calls.append(1)
        return next(statuses)

    _run_drain_worker(tmp_path, poll_once)

    assert len(calls) == 5


def test_drain_worker_gives_up_on_an_unsent_result_after_its_retries(tmp_path: Path, no_retry_delay) -> None:
    calls: list[int] = []

    def poll_once(_store: object, _context: object) -> dict[str, object]:
        calls.append(1)
        return {"state": "result_pending"}

    _run_drain_worker(tmp_path, poll_once)

    assert len(calls) == 1 + len(command_queue_drain.REVIEW_DRAIN_RETRY_DELAYS_SECONDS)


def test_drain_worker_logs_and_retries_an_error(tmp_path: Path, no_retry_delay, caplog) -> None:
    calls: list[int] = []

    def poll_once(_store: object, _context: object) -> dict[str, object]:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("upload failed")
        return {"state": "idle", "last_poll_was_empty": True}

    _run_drain_worker(tmp_path, poll_once, format_error=lambda error: f"redacted:{type(error).__name__}")

    assert len(calls) == 2
    assert "redacted:RuntimeError" in caplog.text
    assert "upload failed" not in caplog.text


def test_drain_worker_retry_wait_ends_on_stop(tmp_path: Path) -> None:
    stop_event = threading.Event()
    calls: list[int] = []

    def poll_once(_store: object, _context: object) -> dict[str, object]:
        calls.append(1)
        stop_event.set()
        return {"state": "result_pending"}

    started = time.monotonic()
    contextvars.Context().run(
        command_queue_drain.drain_review_jobs,
        FakeStore(tmp_path / "guard-home"),
        _context(tmp_path),
        slot=0,
        stop_event=stop_event,
        poll_once=poll_once,
        format_error=str,
    )

    assert calls == [1]
    assert time.monotonic() - started < 1


def test_pool_runs_one_worker_per_slot_and_restarts_finished_slots(tmp_path: Path) -> None:
    release = threading.Event()
    started = threading.Semaphore(0)
    lanes: list[str] = []
    lock = threading.Lock()

    def poll_once(_store: object, _context: object) -> dict[str, object]:
        with lock:
            lanes.append(current_command_queue_lane().state_key)
        started.release()
        release.wait(5)
        return {"state": "idle", "last_poll_was_empty": True}

    pool = command_queue_drain.ReviewDrainPool(
        FakeStore(tmp_path / "guard-home"),
        _context(tmp_path),
        stop_event=threading.Event(),
        poll_once=poll_once,
        format_error=str,
    )

    assert pool.start() == command_queue_drain.REVIEW_DRAIN_WORKERS
    for _ in range(command_queue_drain.REVIEW_DRAIN_WORKERS):
        assert started.acquire(timeout=5)
    assert pool.start() == 0
    release.set()
    for thread in pool._threads:
        assert thread is not None
        thread.join(5)

    assert sorted(lanes) == sorted(
        command_queue_drain.review_drain_lane(slot).state_key
        for slot in range(command_queue_drain.REVIEW_DRAIN_WORKERS)
    )
    assert pool.start() == command_queue_drain.REVIEW_DRAIN_WORKERS
    for thread in pool._threads:
        assert thread is not None
        thread.join(5)


def test_pool_does_not_start_after_stop(tmp_path: Path) -> None:
    stop_event = threading.Event()
    stop_event.set()
    pool = command_queue_drain.ReviewDrainPool(
        FakeStore(tmp_path / "guard-home"),
        _context(tmp_path),
        stop_event=stop_event,
        poll_once=lambda *_args: {},
        format_error=str,
    )

    assert pool.start() == 0


def test_pending_drain_result_is_found_for_restart(tmp_path: Path) -> None:
    store = FakeStore(tmp_path / "guard-home")
    assert command_queue_drain.review_drain_has_pending_result(store) is False

    store.set_sync_payload(
        command_queue_drain.review_drain_lane(1).state_key,
        {"state": "result_pending", "pending_result": {"job": {"id": "job-1"}, "payload": {}}},
        "2000-01-01T00:00:00+00:00",
    )

    assert command_queue_drain.review_drain_has_pending_result(store) is True


def test_unreadable_drain_lane_does_not_hide_another_lanes_pending_result(tmp_path: Path, caplog) -> None:
    store = FakeStore(tmp_path / "guard-home")
    store.set_sync_payload(
        command_queue_drain.review_drain_lane(2).state_key,
        {"state": "result_pending", "pending_result": {"job": {"id": "job-2"}, "payload": {}}},
        "2000-01-01T00:00:00+00:00",
    )
    broken_key = command_queue_drain.review_drain_lane(0).state_key
    read = store.get_sync_payload

    def get_sync_payload(state_key: str) -> object:
        if state_key == broken_key:
            raise ValueError("corrupt lane state")
        return read(state_key)

    store.get_sync_payload = get_sync_payload

    with caplog.at_level("WARNING"):
        assert command_queue_drain.review_drain_has_pending_result(store) is True
    assert "drain state unreadable: slot=0 error=ValueError" in caplog.text


def test_pool_start_survives_a_thread_that_cannot_start(tmp_path: Path, monkeypatch, caplog) -> None:
    def refuse(_self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    pool = command_queue_drain.ReviewDrainPool(
        FakeStore(tmp_path / "guard-home"),
        _context(tmp_path),
        stop_event=threading.Event(),
        poll_once=lambda *_args: {},
        format_error=str,
    )

    assert pool.start() == 0
    assert "Guard Review drain worker did not start" in caplog.text


@pytest.mark.parametrize("pending", [False, True])
def test_main_poll_restarts_drains_while_a_result_is_unsent(tmp_path: Path, monkeypatch, pending: bool) -> None:
    store = FakeStore(tmp_path / "guard-home")
    if pending:
        store.set_sync_payload(
            command_queue_drain.review_drain_lane(2).state_key,
            {"state": "result_pending", "pending_result": {"job": {"id": "job-1"}, "payload": {}}},
            "2000-01-01T00:00:00+00:00",
        )
    events: list[str] = []
    monkeypatch.setattr(command_queue_drain.ReviewDrainPool, "start", lambda _self: events.append("start") or 0)

    def poll_once(_store: object, _context: object, *, on_exact_review_lease) -> dict[str, object]:
        events.append("poll")
        on_exact_review_lease()
        return {"state": "idle"}

    poll = command_queue_drain.with_review_drains(
        store, _context(tmp_path), stop_event=threading.Event(), poll_once=poll_once, format_error=str
    )
    poll(store, _context(tmp_path))

    assert events == (["start", "poll", "start"] if pending else ["poll", "start"])


class _InterleavingStore(FakeStore):
    """Yield between reading and writing a row so unlocked writers would race."""

    def get_sync_payload(self, key: str) -> dict[str, object] | list[object] | None:
        payload = super().get_sync_payload(key)
        time.sleep(0.005)
        return payload


def test_parallel_replay_rows_are_all_kept(tmp_path: Path) -> None:
    store = _InterleavingStore(tmp_path / "guard-home")
    barrier = threading.Barrier(6)

    def consume(index: int) -> None:
        authorized = command_capability.AuthorizedCommandJob(
            identity={"id": f"job-{index}", "idempotencyKey": f"key-{index}", "expiresAt": "2999-01-01T00:00:00+00:00"},
            operation=EXACT_CLOUD_REVIEW_OPERATION,
            requires_local_approval=False,
        )
        barrier.wait(5)
        command_capability.mark_command_job_consumed(store, authorized, identity_digest=f"digest-{index}")

    threads = [threading.Thread(target=consume, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)

    rows = store.get_sync_payload(command_capability.COMMAND_REPLAY_STATE_KEY)
    assert isinstance(rows, dict)
    assert sorted(item["jobId"] for item in rows["items"]) == [f"job-{index}" for index in range(6)]
