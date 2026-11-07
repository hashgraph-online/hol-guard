from __future__ import annotations

import threading
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_queue, command_queue_drain, command_queue_state
from codex_plugin_scanner.guard.runtime.command_queue_state import (
    current_command_queue_lane,
    exact_lease_batch_limit,
    load_command_queue_state,
    record_exact_lease_batch_limit,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    EXACT_CLOUD_REVIEW_PROTOCOL_VERSION,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import lease_next_job, uses_exact_transport
from tests.test_guard_command_queue import FakeStore, _context
from tests.test_guard_command_queue_review_drain import _enable_queue, _exact_job

_EXACT_ONLY = (EXACT_CLOUD_REVIEW_OPERATION,)


def _item(lease_id: str, *, protocol: str = EXACT_CLOUD_REVIEW_PROTOCOL_VERSION) -> dict[str, object]:
    return {"id": f"job-{lease_id}", "leaseId": lease_id, "protocolVersion": protocol}


def _lease(response: dict[str, object] | Exception, **kwargs: object) -> tuple[object, list[dict[str, object]]]:
    requests: list[dict[str, object]] = []

    def exact_request(options: dict[str, object]) -> dict[str, object]:
        requests.append(dict(options))
        if isinstance(response, Exception):
            raise response
        return {"protocolVersion": EXACT_CLOUD_REVIEW_PROTOCOL_VERSION, **response}

    def queue_request(_options: dict[str, object]) -> dict[str, object]:
        raise AssertionError("an exact-only lease never reaches the generic route")

    item = lease_next_job(
        operations=_EXACT_ONLY, wait_ms=0, exact_request=exact_request, queue_request=queue_request, **kwargs
    )
    return item, requests


def test_lease_asks_for_one_job_when_nothing_takes_the_extras() -> None:
    _item_result, requests = _lease({"item": _item("a")}, max_jobs=4)

    assert requests[0]["max_jobs"] == 1


def test_lease_hands_over_distinct_current_extras_and_records_the_advertised_limit() -> None:
    extras: list[dict[str, object]] = []
    limits: list[int] = []
    first = _item("a")
    response = {
        "item": first,
        "items": [first, _item("b"), _item("b"), _item("c", protocol="old"), "not-a-job", _item("d")],
        "maxJobs": 4,
    }

    item, requests = _lease(response, max_jobs=4, on_extra_jobs=extras.extend, observe_lease_batch_limit=limits.append)

    assert requests[0]["max_jobs"] == 4
    assert item is not None and uses_exact_transport(item) and item["leaseId"] == "a"
    assert [job["leaseId"] for job in extras] == ["b", "d"]
    assert all(uses_exact_transport(job) for job in extras)
    assert limits == [4]


def test_lease_records_one_when_guard_cloud_does_not_advertise_a_batch() -> None:
    limits: list[int] = []

    _lease({"item": None}, max_jobs=1, on_extra_jobs=lambda _jobs: None, observe_lease_batch_limit=limits.append)

    assert limits == [1]


def test_rejected_batch_lease_falls_back_to_one_job() -> None:
    limits: list[int] = []
    error = urllib.error.HTTPError("https://cloud.invalid/lease", 400, "Bad Request", Message(), None)

    with pytest.raises(urllib.error.HTTPError):
        _lease(error, max_jobs=4, on_extra_jobs=lambda _jobs: None, observe_lease_batch_limit=limits.append)

    assert limits == [1]


def test_batch_limit_is_saved_only_when_it_changes(tmp_path: Path) -> None:
    store = FakeStore(tmp_path / "guard-home")
    state: dict[str, object] = {"state": "idle"}
    assert exact_lease_batch_limit(state) == 1

    record_exact_lease_batch_limit(store, state, 4)
    assert exact_lease_batch_limit(load_command_queue_state(store)) == 4

    store.set_sync_payload(current_command_queue_lane().state_key, {"state": "elsewhere"}, "2000-01-01T00:00:00+00:00")
    record_exact_lease_batch_limit(store, state, 4)
    assert load_command_queue_state(store).get("state") == "elsewhere"

    record_exact_lease_batch_limit(store, state, 1)
    assert exact_lease_batch_limit(load_command_queue_state(store)) == 1


def test_lease_payload_carries_the_batch_only_on_the_exact_route(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    monkeypatch.setattr(command_queue_state, "command_queue_oauth_target", lambda _store: ("machine", "workspace"))

    exact = command_queue_state.command_queue_lease_payload(store, operations=_EXACT_ONLY, wait_ms=0, max_jobs=4)
    generic = command_queue_state.command_queue_lease_payload(
        store, operations=("guard.packageShims.status",), wait_ms=0, max_jobs=4
    )

    assert exact["maxJobs"] == 4
    assert generic["maxJobs"] == 1


def _stop_after_heartbeat(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    heartbeats: list[str] = []

    def heartbeat(_auth_context: object, job: dict[str, object]) -> None:
        heartbeats.append(str(job["id"]))
        raise RuntimeError("stop after heartbeat")

    monkeypatch.setattr(command_queue, "_heartbeat", heartbeat)
    return heartbeats


@pytest.mark.parametrize(
    ("limit", "leased_extras", "expected_request", "more_may_be_ready"),
    [
        (None, [], (1, False), True),
        (4, [_exact_job("job-2"), _exact_job("job-3"), _exact_job("job-4")], (4, True), True),
        (4, [_exact_job("job-2")], (4, True), False),
    ],
)
def test_main_poll_requests_the_recorded_batch_and_hands_over_the_extras(
    tmp_path: Path,
    monkeypatch,
    limit: int | None,
    leased_extras: list[dict[str, object]],
    expected_request: tuple[int, bool],
    more_may_be_ready: bool,
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    if limit is not None:
        record_exact_lease_batch_limit(store, load_command_queue_state(store), limit)
    requests: list[tuple[int, bool]] = []

    def lease(*_args: object, max_jobs: int, on_extra_jobs) -> dict[str, object]:
        requests.append((max_jobs, on_extra_jobs is not None))
        if on_extra_jobs is not None and leased_extras:
            on_extra_jobs(list(leased_extras))
        return _exact_job("job-1")

    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lease)
    heartbeats = _stop_after_heartbeat(monkeypatch)
    batches: list[command_queue_drain.ReviewLeaseBatch] = []

    with pytest.raises(RuntimeError, match="stop after heartbeat"):
        command_queue.poll_command_queue_once(store, _context(tmp_path), on_exact_review_lease=batches.append)

    assert requests == [expected_request]
    assert heartbeats == ["job-1"]
    assert [job["id"] for job in batches[0].jobs] == [job["id"] for job in leased_extras]
    assert batches[0].more_may_be_ready is more_may_be_ready


def test_drain_poll_settles_a_handed_job_without_leasing(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)

    def lease(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a handed-over job is already leased")

    def pending(*_args: object) -> bool:
        raise AssertionError("a handed-over job settles before the lane's retry")

    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lease)
    monkeypatch.setattr(command_queue, "_retry_pending_result", pending)
    heartbeats = _stop_after_heartbeat(monkeypatch)

    with pytest.raises(RuntimeError, match="stop after heartbeat"):
        command_queue.poll_command_queue_once(store, _context(tmp_path), leased_item=_exact_job("job-2"))

    assert heartbeats == ["job-2"]


def _recording_pool(tmp_path: Path, polls: list[str], lock: threading.Lock) -> command_queue_drain.ReviewDrainPool:
    def poll_once(_store: object, _context: object, *, leased_item: dict[str, object] | None = None):
        with lock:
            polls.append(str(leased_item["id"]) if leased_item else "lease")
        if leased_item is not None:
            return {"state": "idle", "last_poll_was_empty": False}
        return {"state": "idle", "last_poll_was_empty": True}

    return command_queue_drain.ReviewDrainPool(
        FakeStore(tmp_path / "guard-home"),
        _context(tmp_path),
        stop_event=threading.Event(),
        poll_once=poll_once,
        format_error=str,
    )


def _join(pool: command_queue_drain.ReviewDrainPool) -> None:
    for thread in list(pool._threads):
        if thread is not None:
            thread.join(5)


def test_partial_batch_settles_its_jobs_without_another_lease(tmp_path: Path) -> None:
    polls: list[str] = []
    pool = _recording_pool(tmp_path, polls, threading.Lock())
    batch = command_queue_drain.ReviewLeaseBatch(
        jobs=(_exact_job("job-2"), _exact_job("job-3")), more_may_be_ready=False
    )

    assert pool.start(batch) == 2
    _join(pool)

    assert sorted(polls) == ["job-2", "job-3"]
    assert not pool.has_handoff()


def test_full_batch_settles_its_jobs_then_drains_by_leasing(tmp_path: Path) -> None:
    polls: list[str] = []
    pool = _recording_pool(tmp_path, polls, threading.Lock())
    batch = command_queue_drain.ReviewLeaseBatch(jobs=(_exact_job("job-2"),), more_may_be_ready=True)

    assert pool.start(batch) == command_queue_drain.REVIEW_DRAIN_WORKERS
    _join(pool)

    assert polls.count("job-2") == 1
    assert polls.count("lease") == command_queue_drain.REVIEW_DRAIN_WORKERS


def test_job_handed_over_while_a_worker_stops_is_still_settled(tmp_path: Path) -> None:
    polls: list[str] = []
    lock = threading.Lock()
    pool = _recording_pool(tmp_path, polls, lock)
    take_job = pool._take_job
    handed = threading.Event()

    def take_after_a_late_handoff(slot: int) -> object:
        job = take_job(slot)
        if job is command_queue_drain.STOP_DRAIN and not handed.is_set():
            # The worker has decided to stop; a job handed over now starts a worker of its own.
            handed.set()
            pool.start(command_queue_drain.ReviewLeaseBatch(jobs=(_exact_job("job-3"),), more_may_be_ready=False))
        return job

    pool._take_job = take_after_a_late_handoff  # type: ignore[method-assign]

    assert pool.start(command_queue_drain.ReviewLeaseBatch(jobs=(_exact_job("job-2"),), more_may_be_ready=False)) == 1
    for _ in range(3):
        _join(pool)

    assert sorted(polls) == ["job-2", "job-3"]
    assert not pool.has_handoff()


def test_main_poll_restarts_drains_for_a_job_still_waiting(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    starts: list[object] = []
    monkeypatch.setattr(command_queue_drain.ReviewDrainPool, "has_handoff", lambda _self: True)
    monkeypatch.setattr(
        command_queue_drain.ReviewDrainPool, "start", lambda _self, batch=None: starts.append(batch) or 0
    )

    def poll_once(_store: object, _context: object, *, on_exact_review_lease) -> dict[str, object]:
        return {"state": "idle"}

    poll = command_queue_drain.with_review_drains(
        store, _context(tmp_path), stop_event=threading.Event(), poll_once=poll_once, format_error=str
    )
    poll(store, _context(tmp_path))

    assert starts == [None]
