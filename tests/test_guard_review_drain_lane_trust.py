"""A drain worker reads its lane's state only while another writer could change it."""

from __future__ import annotations

import contextvars
import threading
from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_queue_drain
from tests.test_guard_command_queue import _context
from tests.test_guard_command_queue_lease_batch import _recording_pool
from tests.test_guard_command_queue_review_drain import _exact_job


def _drain_with_counted_reads(
    tmp_path: Path,
    statuses: list[dict[str, object]],
    *,
    during_poll=None,
) -> tuple[list[bool], list[str]]:
    lane_key = command_queue_drain.review_drain_lane(0).state_key
    reads: list[str] = []
    asked: list[bool] = []
    pool = _recording_pool(tmp_path, [], threading.Lock())
    read_payload = pool._store.get_sync_payload

    def counting_read(key: str) -> object:
        if key == lane_key:
            reads.append(key)
        return read_payload(key)

    pool._store.get_sync_payload = counting_read  # type: ignore[method-assign]
    jobs = [_exact_job("job-2"), _exact_job("job-3")]
    remaining = iter(statuses)

    def take_job(slot: int, *, lane_clear: bool = False) -> object:
        asked.append(lane_clear)
        if pool._take_job(slot, lane_clear=lane_clear) is None and jobs:
            return jobs.pop(0)
        return None

    def poll_once(*_args: object, **_kwargs: object) -> dict[str, object]:
        if during_poll is not None:
            during_poll(pool._store)
        return next(remaining)

    # Each worker enters its own lane for the rest of its context; a fresh
    # context keeps that lane from leaking into later tests on this thread.
    contextvars.Context().run(
        command_queue_drain.drain_review_jobs,
        pool._store,
        _context(tmp_path),
        slot=0,
        stop_event=threading.Event(),
        poll_once=poll_once,
        format_error=str,
        take_job=take_job,
        release=lambda _slot: True,
    )
    return asked, reads


_STATUSES = [
    {"state": "result_pending", "pending_result": {"job": {}, "payload": {}}},
    {"state": "idle", "last_poll_was_empty": False, "pending_result": None},
    {"state": "idle", "last_poll_was_empty": True, "pending_result": None},
]


def test_a_worker_reads_its_lane_state_only_until_a_poll_reports_it_clear(tmp_path: Path) -> None:
    asked, reads = _drain_with_counted_reads(tmp_path, _STATUSES)

    # The first turn and the turn after an unsent result read the lane; the
    # turn after an idle poll trusts it.
    assert asked == [False, False, True]
    assert len(reads) == 2


def test_a_worker_left_from_a_stopped_pool_keeps_the_lane_read(tmp_path: Path) -> None:
    lane = command_queue_drain._lane_writer_key
    writer_entered = threading.Event()
    release_writer = threading.Event()

    def old_pool_worker(store: object) -> None:
        with command_queue_drain._LANE_WRITERS.writing(lane(store, 0)):  # type: ignore[arg-type]
            writer_entered.set()
            release_writer.wait(5)

    def start_old_writer(store: object) -> None:
        if not writer_entered.is_set():
            threading.Thread(target=old_pool_worker, args=(store,), daemon=True).start()
            writer_entered.wait(5)

    try:
        asked, reads = _drain_with_counted_reads(tmp_path, _STATUSES, during_poll=start_old_writer)
    finally:
        release_writer.set()

    # A worker from the stopped pool could still save an unsent result to this
    # lane, so an idle poll never lets a handed job skip the lane read.
    assert asked == [False, False, False]
    assert len(reads) == 3


def test_a_writer_that_came_and_went_since_the_poll_keeps_the_lane_read(tmp_path: Path) -> None:
    lane = command_queue_drain._lane_writer_key
    polls = {"count": 0}

    def brief_writer(store: object) -> None:
        polls["count"] += 1
        if polls["count"] == 2:
            # After this worker's second poll started, another writer enters
            # and leaves; what it saved is newer than that poll's status.
            def write() -> None:
                with command_queue_drain._LANE_WRITERS.writing(lane(store, 0)):  # type: ignore[arg-type]
                    pass

            thread = threading.Thread(target=write)
            thread.start()
            thread.join(5)

    asked, reads = _drain_with_counted_reads(tmp_path, _STATUSES, during_poll=brief_writer)

    assert asked == [False, False, False]
    assert len(reads) == 3


def test_a_lane_reported_clear_takes_the_handed_job_without_reading_its_state(tmp_path: Path) -> None:
    pool = _recording_pool(tmp_path, [], threading.Lock())
    pool._handoff.jobs.append(_exact_job("job-2"))

    def unreadable(_key: str) -> object:
        raise AssertionError("lane state read")

    pool._store.get_sync_payload = unreadable  # type: ignore[method-assign]

    job = pool._take_job(0, lane_clear=True)

    assert isinstance(job, dict) and job["id"] == "job-2"
