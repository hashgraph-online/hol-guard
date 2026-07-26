# pyright: reportPrivateUsage=false

from __future__ import annotations

import gc
import threading
import weakref
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_serve_thread_start_failure_rolls_back_initialized_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def empty_inventory(_guard_home: Path) -> list[tuple[int, int]]:
        return []

    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        empty_inventory,
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    port = daemon.port
    real_thread = threading.Thread
    begin_service = daemon._begin_service
    started_threads: list[threading.Thread] = []

    class FailedServeThread:
        def start(self) -> None:
            raise RuntimeError("injected serve thread exhaustion")

    def failed_thread_factory(*, target: object, daemon: bool) -> FailedServeThread:
        del target, daemon
        return FailedServeThread()

    def begin_then_fail_serve_thread() -> None:
        begin_service()
        started_threads.extend(
            thread
            for thread in (
                daemon._watchdog_thread,
                daemon._bundle_refresh_thread,
                daemon._aibom_refresh_thread,
                daemon._headless_cloud_sync_thread,
                daemon._command_activity_maintenance_thread,
                daemon._server.runtime_heartbeat._thread,
                daemon._server.unclassified_watchdog_thread,
                daemon._server.approval_attention._thread,
            )
            if thread is not None
        )
        monkeypatch.setattr(
            threading,
            "Thread",
            failed_thread_factory,
        )

    monkeypatch.setattr(daemon, "_begin_service", begin_then_fail_serve_thread)
    with pytest.raises(RuntimeError, match="injected serve thread exhaustion"):
        daemon.start()

    assert daemon._thread is None
    assert started_threads
    assert all(not thread.is_alive() for thread in started_threads)
    assert daemon._owner_lock is None
    assert daemon._server.hook_process_runner.stats()["workers"] == 0
    assert daemon._server.runtime_heartbeat._thread is None
    assert daemon._server.unclassified_watchdog_thread is None
    assert daemon._server.approval_attention._thread is None
    assert store.get_runtime_state() is None

    replacement = daemon_manager.acquire_guard_daemon_owner_lock(store.guard_home)
    daemon_manager.release_guard_daemon_owner_lock(replacement)

    monkeypatch.setattr(threading, "Thread", real_thread)
    monkeypatch.setattr(daemon, "_begin_service", begin_service)
    replacement = GuardDaemonServer(
        store,
        host="127.0.0.1",
        port=port,
        idle_timeout_seconds=0,
    )
    try:
        replacement.start()
        assert replacement._thread is not None
        assert replacement._thread.is_alive()
    finally:
        replacement.stop()


def test_uncontained_service_blocks_replacement_until_retry_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    port = daemon.port
    daemon_ref = weakref.ref(daemon)
    runner = daemon._server.hook_process_runner
    close_runner = daemon._server.hook_process_runner.close_contained
    monkeypatch.setattr(runner, "close_contained", lambda: False)
    daemon._begin_service()
    assert not daemon._finish_service()

    key = daemon._quarantine_key(store.guard_home)
    assert daemon._owner_lock is not None
    assert daemon._quarantined_services[key] is daemon
    del daemon
    gc.collect()

    assert daemon_ref() is not None
    with pytest.raises(RuntimeError, match="already active"):
        _ = daemon_manager.acquire_guard_daemon_owner_lock(store.guard_home)
    with pytest.raises(RuntimeError, match="remains quarantined"):
        _ = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)

    monkeypatch.setattr(runner, "close_contained", close_runner)
    replacement = GuardDaemonServer(store, host="127.0.0.1", port=port, idle_timeout_seconds=0)
    try:
        quarantined = daemon_ref()
        if quarantined is not None:
            assert quarantined._owner_lock is None
        assert key not in GuardDaemonServer._quarantined_services
        replacement_owner = daemon_manager.acquire_guard_daemon_owner_lock(store.guard_home)
        daemon_manager.release_guard_daemon_owner_lock(replacement_owner)
    finally:
        replacement._server.server_close()
