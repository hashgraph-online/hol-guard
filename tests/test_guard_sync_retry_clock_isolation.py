"""Retry fixtures leave unrelated worker clocks unchanged."""

from __future__ import annotations

import threading
import time

import pytest

from codex_plugin_scanner.guard.runtime import runner
from tests import test_guard_sync_http_error_message as retry_cases


@pytest.mark.parametrize(
    "case_name",
    [
        "test_urlopen_json_retries_cloudflare_502_with_default_retry_after",
        "test_urlopen_retries_cloudflare_524_with_retry_after_header",
    ],
)
def test_retry_fixtures_do_not_capture_an_unrelated_worker_sleep(
    monkeypatch: pytest.MonkeyPatch, case_name: str
) -> None:
    original_sleep = time.sleep
    original_urlopen = runner.managed_urlopen
    worker_finished = threading.Event()
    worker_started = False

    def unrelated_worker() -> None:
        time.sleep(0)
        worker_finished.set()

    def urlopen_with_worker(*args, **kwargs):
        nonlocal worker_started
        if not worker_started:
            worker_started = True
            worker = threading.Thread(target=unrelated_worker)
            worker.start()
            worker.join(timeout=2)
            assert worker_finished.is_set()
        return original_urlopen(*args, **kwargs)

    monkeypatch.setattr(runner, "managed_urlopen", urlopen_with_worker)
    getattr(retry_cases, case_name)(monkeypatch)

    assert worker_finished.is_set()
    assert time.sleep is original_sleep
