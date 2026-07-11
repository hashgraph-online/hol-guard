"""Focused lifecycle coverage for daemon-owned cloud workers."""

from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import server as daemon_server_module


def test_finish_service_stops_cloud_workers_and_allows_restart(monkeypatch, tmp_path: Path) -> None:
    stopped: list[tuple[str, object]] = []
    command_worker = object()
    live_request_worker = object()
    store = SimpleNamespace(
        guard_home=tmp_path,
        clear_runtime_state=lambda *, session_id: None,
    )
    service = object.__new__(daemon_server_module.GuardDaemonServer)
    service._shutdown_started = threading.Event()
    service._command_queue_worker = command_worker
    service._live_request_sync_worker = live_request_worker
    service._server = SimpleNamespace(
        runtime_session_id="runtime-session",
        server_address=("127.0.0.1", 4781),
        store=store,
    )
    service.port = 4781
    service._thread = threading.current_thread()

    monkeypatch.setattr(
        daemon_server_module,
        "stop_command_queue_worker",
        lambda worker: stopped.append(("command", worker)),
    )
    monkeypatch.setattr(
        daemon_server_module,
        "stop_cloud_sync_sync_worker",
        lambda worker: stopped.append(("live-request", worker)),
    )
    monkeypatch.setattr(
        daemon_server_module,
        "clear_guard_daemon_state_if_current",
        lambda *_args, **_kwargs: None,
    )

    service._finish_service()

    assert stopped == [
        ("command", command_worker),
        ("live-request", live_request_worker),
    ]
    assert service._thread is threading.current_thread()
    assert service._shutdown_started.is_set()
