"""Readiness must not expose an empty or partially buffered process identity."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from tests import owned_daemon_test_support as support
from tests.test_runtime_transition_configured_inverse import DAEMON_PROCESS


def test_readiness_is_invisible_until_the_complete_pid_is_published(tmp_path: Path, monkeypatch) -> None:
    ready = tmp_path / "owned-daemon-ready-0"
    before_publish, release = Event(), Event()
    replace = support.os.replace

    def pause_before_publication(source, destination):
        pending = Path(source)
        assert pending.read_text(encoding="ascii") == "12345"
        assert not ready.exists()
        if os.name != "nt":
            assert pending.stat().st_mode & 0o777 == 0o600
        before_publish.set()
        assert release.wait(5), "test publisher was not released"
        replace(source, destination)

    monkeypatch.setattr(support.os, "replace", pause_before_publication)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(support.publish_ready_pid, ready, 12345)
        try:
            assert before_publish.wait(5), "publisher did not reach the atomic handoff"
            assert not ready.exists()
        finally:
            release.set()
        future.result(timeout=5)
    assert ready.read_text(encoding="ascii") == "12345"
    assert list(tmp_path.iterdir()) == [ready]


def test_failed_publication_does_not_leave_a_ready_marker_or_temporary_file(tmp_path: Path, monkeypatch) -> None:
    ready = tmp_path / "owned-daemon-ready-0"

    def fail(*_args):
        raise OSError("injected publication failure")

    monkeypatch.setattr(support.os, "replace", fail)
    with pytest.raises(OSError, match="injected publication failure"):
        support.publish_ready_pid(ready, 12345)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("pid", [0, -1, True, "12345"])
def test_invalid_pid_cannot_create_a_ready_marker(tmp_path: Path, pid) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        support.publish_ready_pid(tmp_path / "ready", pid)
    assert list(tmp_path.iterdir()) == []


def test_real_daemon_fixture_uses_atomic_publication_after_startup() -> None:
    assert "from tests.owned_daemon_test_support import publish_ready_pid" in DAEMON_PROCESS
    assert DAEMON_PROCESS.index("daemon.start()") < DAEMON_PROCESS.index("publish_ready_pid(ready, os.getpid())")
    assert "with ready.open" not in DAEMON_PROCESS
