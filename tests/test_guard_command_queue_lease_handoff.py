from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_queue, command_queue_drain
from codex_plugin_scanner.guard.runtime.command_queue_state import (
    load_command_queue_state,
    record_exact_lease_batch_limit,
)
from tests.test_guard_command_queue import FakeStore, _context
from tests.test_guard_command_queue_lease_batch import _stop_after_heartbeat
from tests.test_guard_command_queue_review_drain import _enable_queue, _exact_job


@pytest.mark.parametrize("failing_step", ["_resolve_command_queue_auth_context", "_record_leased_job"])
def test_a_failure_after_a_batch_lease_still_hands_every_leased_job_over(
    tmp_path: Path, monkeypatch, failing_step: str
) -> None:
    # The jobs are leased to this device: a step failing before any of them
    # runs must not leave them to wait out their lease.
    store = FakeStore(tmp_path / "guard-home")
    _enable_queue(store, monkeypatch)
    record_exact_lease_batch_limit(store, load_command_queue_state(store), 4)
    extras = [_exact_job("job-2"), _exact_job("job-3")]

    def lease(*_args: object, max_jobs: int, on_extra_jobs) -> dict[str, object]:
        on_extra_jobs(list(extras))
        return _exact_job("job-1")

    monkeypatch.setattr(command_queue, "_lease_job_with_401_retry", lease)
    calls = {"count": 0}
    original = getattr(command_queue, failing_step)

    def fail_after_the_lease(*args: object, **kwargs: object) -> object:
        calls["count"] += 1
        # The auth context also resolves once before the lease.
        if failing_step == "_resolve_command_queue_auth_context" and calls["count"] == 1:
            return original(*args, **kwargs)
        raise RuntimeError("failed after the lease")

    monkeypatch.setattr(command_queue, failing_step, fail_after_the_lease)
    heartbeats = _stop_after_heartbeat(monkeypatch)
    batches: list[command_queue_drain.ReviewLeaseBatch] = []

    with pytest.raises(RuntimeError, match="failed after the lease"):
        command_queue.poll_command_queue_once(store, _context(tmp_path), on_exact_review_lease=batches.append)

    assert heartbeats == []
    assert [[job["id"] for job in batch.jobs] for batch in batches] == [["job-2", "job-3"], ["job-1"]]
