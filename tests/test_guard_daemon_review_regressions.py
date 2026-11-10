from __future__ import annotations

import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_daemon_manage as daemon_manager


def test_recovery_worker_thread_lock_timeout_is_bounded(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    with daemon_manager._guard_daemon_recovery_lock(guard_home):  # pyright: ignore[reportPrivateUsage]
        started = time.monotonic()
        with (
            pytest.raises(RuntimeError, match="recovery ownership"),
            daemon_manager._guard_daemon_recovery_lock(  # pyright: ignore[reportPrivateUsage]
                guard_home,
                timeout_seconds=0.02,
            ),
        ):
            pass
        assert time.monotonic() - started < 0.5


def test_recovery_worker_file_lock_timeout_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(daemon_manager, "_try_lock_daemon_file", lambda _handle: False)
    started = time.monotonic()
    with (
        pytest.raises(RuntimeError, match="recovery ownership"),
        daemon_manager._guard_daemon_recovery_lock(  # pyright: ignore[reportPrivateUsage]
            guard_home,
            timeout_seconds=0.02,
        ),
    ):
        pass
    assert time.monotonic() - started < 0.5
