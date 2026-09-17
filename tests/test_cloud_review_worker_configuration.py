"""Invalid worker configuration cannot kill startup or create unbounded waits."""

from __future__ import annotations

import math
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker as workers
from tests.test_guard_cloud_review_sync_worker import Store


@pytest.mark.parametrize(
    "name,argument,default",
    [
        ("GUARD_CLOUD_REVIEW_POLL_INTERVAL", "poll_interval", 30.0),
        ("GUARD_CLOUD_REVIEW_ERROR_BACKOFF", "error_backoff", 30.0),
        ("GUARD_CLOUD_REVIEW_ERROR_BACKOFF_BASE", "error_backoff_base", 1.0),
    ],
)
@pytest.mark.parametrize("value", ["not-a-number", "0", "-1", "NaN", "inf", "1e100", "0.000001"])
def test_invalid_environment_uses_safe_default_before_thread_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    name: str,
    argument: str,
    default: float,
    value: str,
) -> None:
    captured: dict[str, object] = {}

    class Thread:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def start(self) -> None:
            captured["started"] = True

    monkeypatch.setenv(name, value)
    monkeypatch.setattr(workers.threading, "Thread", Thread)
    result = workers.start_cloud_sync_sync_worker(Store(tmp_path))
    assert result is not None
    assert captured["started"] is True
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs[argument] == default
    assert name in caplog.text
    assert "not-a-number" not in caplog.text


@pytest.mark.parametrize("argument", ["poll_interval", "error_backoff"])
@pytest.mark.parametrize("value", [0.0, -2.0, math.nan, math.inf])
def test_invalid_explicit_intervals_do_not_fall_through_to_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argument: str, value: float
) -> None:
    captured: dict[str, object] = {}

    class Thread:
        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

        def start(self) -> None:
            pass

    monkeypatch.setenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", "7")
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_ERROR_BACKOFF", "8")
    monkeypatch.setattr(workers.threading, "Thread", Thread)
    workers.start_cloud_sync_sync_worker(Store(tmp_path), **{argument: value})
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs[argument] == 30.0


def test_maximum_wait_stops_promptly_when_woken(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = Store(tmp_path)
    monkeypatch.setattr(store, "get_cloud_sync_profile", lambda: {})
    worker = workers.start_cloud_sync_sync_worker(store, poll_interval=3600, error_backoff=3600)
    assert worker is not None
    started = time.monotonic()
    try:
        stopped = workers.stop_cloud_sync_sync_worker(worker)
        assert stopped is None
        assert time.monotonic() - started < 1.5
    finally:
        workers.stop_cloud_sync_sync_worker(worker)
