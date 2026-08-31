# pyright: reportPrivateUsage=false

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_stop_during_capacity_activation_prevents_successful_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    runner = daemon._server.hook_process_runner
    original_enable_full_capacity = runner.enable_full_capacity
    activation_entered = threading.Event()
    release_activation = threading.Event()
    start_errors: list[BaseException] = []
    stop_errors: list[BaseException] = []

    def delayed_enable_full_capacity() -> None:
        activation_entered.set()
        assert release_activation.wait(timeout=10)
        original_enable_full_capacity()

    def start_daemon() -> None:
        try:
            daemon.start()
        except BaseException as error:
            start_errors.append(error)

    def stop_daemon() -> None:
        try:
            daemon.stop()
        except BaseException as error:
            stop_errors.append(error)

    monkeypatch.setattr(runner, "enable_full_capacity", delayed_enable_full_capacity)
    starter = threading.Thread(target=start_daemon)
    stopper = threading.Thread(target=stop_daemon)
    try:
        starter.start()
        assert activation_entered.wait(timeout=10)
        stopper.start()
        assert daemon._shutdown_started.wait(timeout=10)
        release_activation.set()
        starter.join(timeout=30)
        stopper.join(timeout=30)

        assert not starter.is_alive()
        assert not stopper.is_alive()
        assert stop_errors == []
        assert len(start_errors) == 1
        assert str(start_errors[0]) == "Guard daemon stopped during startup"
        assert daemon._thread is None
        assert daemon._owner_lock is None
        assert runner.stats()["workers"] == 0
    finally:
        release_activation.set()
        daemon.stop()
