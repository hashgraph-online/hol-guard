# pyright: reportPrivateUsage=false

from __future__ import annotations

import gc
import socket
import threading
import weakref
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_daemon_start_preserves_deferred_hook_worker_backfill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    runner = daemon._server.hook_process_runner
    enable_full_capacity = runner.enable_full_capacity
    calls: list[dict[str, float]] = []

    def recording_enable_full_capacity(**kwargs: float) -> None:
        calls.append(kwargs)
        enable_full_capacity(**kwargs)

    monkeypatch.setattr(runner, "enable_full_capacity", recording_enable_full_capacity)
    try:
        daemon.start()
        assert calls == [{}]
    finally:
        daemon.stop()


def test_daemon_start_waits_for_serve_loop_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    original_serve_forever = daemon._serve_forever
    serve_thread_entered = threading.Event()
    release_serve_thread = threading.Event()
    start_errors: list[BaseException] = []

    def delayed_serve_forever() -> None:
        serve_thread_entered.set()
        assert release_serve_thread.wait(timeout=5)
        original_serve_forever()

    def start_daemon() -> None:
        try:
            daemon.start()
        except BaseException as error:
            start_errors.append(error)

    monkeypatch.setattr(daemon, "_serve_forever", delayed_serve_forever)
    starter = threading.Thread(target=start_daemon)
    try:
        starter.start()
        assert serve_thread_entered.wait(timeout=10)
        assert starter.is_alive()
        release_serve_thread.set()
        starter.join(timeout=10)
        assert not starter.is_alive()
        assert start_errors == []
    finally:
        release_serve_thread.set()
        daemon.stop()


def test_occupied_port_preserves_bind_error_during_partial_server_cleanup(tmp_path: Path) -> None:
    diagnostics_threads_before = {
        thread.ident
        for thread in threading.enumerate()
        if thread.name == "guard-daemon-diagnostics" and thread.is_alive()
    }
    executor_threads_before = {
        thread.ident for thread in threading.enumerate() if thread.name.startswith("guard-http-")
    }
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]

    try:
        with pytest.raises(OSError) as error:
            _ = GuardDaemonServer(
                GuardStore(tmp_path / "guard-home"),
                host="127.0.0.1",
                port=port,
                idle_timeout_seconds=0,
            )
    finally:
        listener.close()

    assert "request_executors_stopped" not in str(error.value)
    assert not any(
        thread.ident not in diagnostics_threads_before
        and thread.name == "guard-daemon-diagnostics"
        and thread.is_alive()
        for thread in threading.enumerate()
    )
    assert not any(
        thread.ident not in executor_threads_before and thread.name.startswith("guard-http-") and thread.is_alive()
        for thread in threading.enumerate()
    )


def test_executor_construction_failure_rolls_back_threads_before_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    executor_threads_before = {
        thread.ident for thread in threading.enumerate() if thread.name.startswith("guard-http-")
    }
    real_executor = daemon_server_module._BoundedRequestExecutor
    construction_count = 0

    def fail_second_executor(
        *,
        name: str,
        workers: int,
        queue_limit: int,
        run: Callable[[socket.socket, tuple[str, int]], None],
        discard: Callable[[socket.socket], None],
    ) -> object:
        nonlocal construction_count
        construction_count += 1
        if construction_count == 2:
            raise RuntimeError("injected control executor exhaustion")
        return real_executor(
            name=name,
            workers=workers,
            queue_limit=queue_limit,
            run=run,
            discard=discard,
        )

    monkeypatch.setattr(daemon_server_module, "_BoundedRequestExecutor", fail_second_executor)

    with pytest.raises(RuntimeError, match="injected control executor exhaustion"):
        _ = GuardDaemonServer(
            GuardStore(tmp_path / "guard-home"),
            host="127.0.0.1",
            port=port,
            idle_timeout_seconds=0,
        )

    assert not any(
        thread.ident not in executor_threads_before and thread.name.startswith("guard-http-") and thread.is_alive()
        for thread in threading.enumerate()
    )
    replacement = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        replacement.bind(("127.0.0.1", port))
    finally:
        replacement.close()


def test_executor_worker_start_failure_rolls_back_started_threads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor_threads_before = {
        thread.ident for thread in threading.enumerate() if thread.name.startswith("guard-http-")
    }
    real_start = threading.Thread.start
    guard_http_start_count = 0

    def fail_third_guard_http_start(thread: threading.Thread) -> None:
        nonlocal guard_http_start_count
        if thread.name.startswith("guard-http-"):
            guard_http_start_count += 1
            if guard_http_start_count == 3:
                raise RuntimeError("injected HTTP worker exhaustion")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_third_guard_http_start)

    with pytest.raises(RuntimeError, match="injected HTTP worker exhaustion"):
        _ = GuardDaemonServer(
            GuardStore(tmp_path / "guard-home"),
            host="127.0.0.1",
            port=0,
            idle_timeout_seconds=0,
        )

    assert not any(
        thread.ident not in executor_threads_before and thread.name.startswith("guard-http-") and thread.is_alive()
        for thread in threading.enumerate()
    )


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
