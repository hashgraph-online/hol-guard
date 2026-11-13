"""Missing proofs fetched together stop early once one fetch fails."""

from __future__ import annotations

import functools
import threading
import time

import pytest

from codex_plugin_scanner.guard.catalog_delivery import active_security


def test_a_failed_fetch_cancels_the_ones_not_started():
    # An outage must not wait out every queued download before it reports.
    started = []
    lock = threading.Lock()
    release = threading.Event()

    def failing():
        with lock:
            started.append("failing")
        raise ValueError("active_security_required_proofs_unavailable")

    def slow(index):
        with lock:
            started.append(index)
        release.wait(5)

    tasks = [failing] + [functools.partial(slow, index) for index in range(31)]
    timer = threading.Timer(0.5, release.set)
    timer.start()
    with pytest.raises(ValueError, match="active_security_required_proofs_unavailable"):
        active_security._fetch_together(tasks)
    timer.cancel()
    # The failed task, then at most one wave: its worker can pick up one more
    # task before the rest are cancelled. Without cancelling, all 32 start.
    assert len(started) <= active_security.FETCH_WORKERS + 1


def test_queued_fetches_skip_once_one_failed():
    # Quick tasks keep every worker taking queued work; none may start a
    # download after the failure is known.
    started = []
    lock = threading.Lock()

    def failing():
        raise ValueError("active_security_required_proofs_unavailable")

    def quick(index):
        with lock:
            started.append(index)
        time.sleep(0.02)

    tasks = [failing] + [functools.partial(quick, index) for index in range(63)]
    with pytest.raises(ValueError, match="active_security_required_proofs_unavailable"):
        active_security._fetch_together(tasks)
    assert len(started) <= active_security.FETCH_WORKERS
