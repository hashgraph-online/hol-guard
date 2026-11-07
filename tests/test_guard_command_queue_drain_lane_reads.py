"""A drain worker rereads its lane only when its last poll left a result unsent."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_queue_drain
from tests.test_guard_command_queue import FakeStore, _context
from tests.test_guard_command_queue_review_drain import _exact_job


def _counting_drain(
    tmp_path: Path, statuses: dict[str, dict[str, object]]
) -> tuple[list[str], list[str], command_queue_drain.ReviewDrainPool]:
    """A one-slot pool whose polls return ``statuses[job id]`` and that counts lane reads."""

    store = FakeStore(tmp_path / "guard-home")
    reads: list[str] = []
    settled: list[str] = []
    read = store.get_sync_payload

    def counting(key: str) -> object:
        reads.append(key)
        return read(key)

    store.get_sync_payload = counting  # type: ignore[method-assign]

    def poll_once(_store: object, _context: object, *, leased_item=None, on_exact_review_lease=None):
        if leased_item is None:
            return {"state": "idle", "last_poll_was_empty": True, "pending_result": None}
        settled.append(str(leased_item["id"]))
        return statuses[str(leased_item["id"])]

    pool = command_queue_drain.ReviewDrainPool(
        store, _context(tmp_path), stop_event=threading.Event(), poll_once=poll_once, format_error=str
    )
    pool._handoff.may_lease = True
    return reads, settled, pool


def _drain_slot_zero(tmp_path: Path, pool: command_queue_drain.ReviewDrainPool) -> None:
    worker = threading.Thread(
        target=command_queue_drain.drain_review_jobs,
        kwargs={
            "store": pool._store,
            "context": _context(tmp_path),
            "slot": 0,
            "stop_event": threading.Event(),
            "poll_once": pool._poll_once,
            "format_error": str,
            "take_job": pool._take_job,
            "release": pool._release,
        },
        daemon=True,
    )
    worker.start()
    worker.join(5)
    assert not worker.is_alive()


def test_a_drain_worker_reads_its_lane_once_while_its_polls_report_no_unsent_result(tmp_path: Path) -> None:
    clear = {"state": "idle", "last_poll_was_empty": False, "pending_result": None}
    reads, settled, pool = _counting_drain(tmp_path, {"job-1": clear, "job-2": clear, "job-3": clear})
    pool._handoff.jobs.extend([_exact_job("job-1"), _exact_job("job-2"), _exact_job("job-3")])

    _drain_slot_zero(tmp_path, pool)

    assert settled == ["job-1", "job-2", "job-3"]
    # Each poll already read the lane and found no result waiting, so only
    # the first turn reads it again before taking a job.
    assert reads.count(command_queue_drain.review_drain_lane(0).state_key) == 1


def test_a_drain_worker_reads_its_lane_again_after_a_poll_left_a_result_unsent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(command_queue_drain, "REVIEW_DRAIN_RETRY_DELAYS_SECONDS", (0.0, 0.0))
    clear = {"state": "idle", "last_poll_was_empty": False, "pending_result": None}
    unsent = {"state": "result_pending", "last_poll_was_empty": False, "pending_result": {"job": {"id": "job-1"}}}
    reads, settled, pool = _counting_drain(tmp_path, {"job-1": unsent, "job-2": clear})
    pool._handoff.jobs.extend([_exact_job("job-1"), _exact_job("job-2")])

    _drain_slot_zero(tmp_path, pool)

    assert settled == ["job-1", "job-2"]
    assert reads.count(command_queue_drain.review_drain_lane(0).state_key) == 2
