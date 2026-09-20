"""HGP-163: worker interval configuration cannot hot-loop."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.cloud_review_sync_worker import (
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)
from codex_plugin_scanner.guard.runtime.cloud_review_worker_timing import cloud_review_worker_timing
from codex_plugin_scanner.guard.store import GuardStore


def test_valid_environment_intervals_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", "2.5")
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_ERROR_BACKOFF", "10")
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_ERROR_BACKOFF_BASE", "1")
    timing = cloud_review_worker_timing(
        poll_interval=None, error_backoff=None, default_poll=30, default_backoff=30, default_base=1
    )
    assert (timing.poll_interval, timing.error_backoff, timing.error_backoff_base) == (2.5, 10, 1)
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", "999999")
    bounded = cloud_review_worker_timing(
        poll_interval=None, error_backoff=None, default_poll=30, default_backoff=30, default_base=1
    )
    assert bounded.poll_interval == 30


def test_bad_env_does_not_kill_startup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", "nan")
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_ERROR_BACKOFF", "-5")
    worker = start_cloud_sync_sync_worker(GuardStore(tmp_path / "guard-home"))
    try:
        assert worker is not None
        assert worker.thread.is_alive()
        worker.stop_event.set()
        worker.wake_signal.notify()
        worker.thread.join(timeout=2.0)
        assert not worker.thread.is_alive()
    finally:
        stop_cloud_sync_sync_worker(worker)
