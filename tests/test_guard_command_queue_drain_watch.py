"""A full lease batch leaves one drain worker free to watch for more jobs."""

from __future__ import annotations

import threading
from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_queue_drain
from tests.test_guard_command_queue_lease_batch import _recording_pool, _settle
from tests.test_guard_command_queue_review_drain import _exact_job


def test_a_full_batch_leaves_one_worker_free_to_watch(tmp_path: Path) -> None:
    # Every drain worker but one takes a job from a full batch. The rest of the
    # bulk approval lands while they settle, and the free worker takes it.
    polls: list[str] = []
    lock = threading.Lock()
    hits = [command_queue_drain.ReviewLeaseBatch(jobs=(), more_may_be_ready=False)]
    pool = _recording_pool(tmp_path, polls, lock, hits)
    handed = command_queue_drain.REVIEW_LEASE_BATCH_SIZE - 1
    jobs = tuple(_exact_job(f"job-{index}") for index in range(2, 2 + handed))
    settling = threading.Event()
    waited: list[bool] = []
    original_take_job = pool._take_job

    def take_job(slot: int, *, lane_clear: bool = False) -> object:
        job = original_take_job(slot, lane_clear=lane_clear)
        if isinstance(job, dict):
            # Each handed job is still settling when the watch begins.
            waited.append(settling.wait(2))
        elif isinstance(job, command_queue_drain.ReviewWatch):
            settling.set()
        return job

    pool._take_job = take_job  # type: ignore[method-assign]
    pool.start(command_queue_drain.ReviewLeaseBatch(jobs=jobs, more_may_be_ready=True))
    _settle(pool, polls, sorted([*(str(job["id"]) for job in jobs), "watch", "watch"]))

    assert handed < command_queue_drain.REVIEW_DRAIN_WORKERS
    assert waited and all(waited)
    assert polls.count("watch") >= 1
    assert sorted(str(job["id"]) for job in jobs) == sorted(poll for poll in polls if poll.startswith("job-"))
    assert not pool.has_handoff()
