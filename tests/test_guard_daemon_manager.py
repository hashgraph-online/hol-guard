"""Focused tests for Guard daemon startup coordination."""

from __future__ import annotations

import threading
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


def test_ensure_guard_daemon_reuses_inflight_pid_before_respawning(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    responses = iter((None, None, "http://127.0.0.1:5409"))

    monkeypatch.setattr(
        daemon_manager_module,
        "load_guard_daemon_url",
        lambda _guard_home: next(responses, "http://127.0.0.1:5409"),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_load_state",
        lambda _guard_home: {
            "pid": 12345,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        },
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not spawn a new daemon")),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5409"


def test_ensure_guard_daemon_serializes_parallel_start_attempts(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_commands: list[list[str]] = []
    launched_event = threading.Event()
    barrier = threading.Barrier(8)

    def fake_load_guard_daemon_url(_guard_home):
        if launched_event.is_set():
            return "http://127.0.0.1:5410"
        return None

    def fake_popen(command, **_kwargs):
        launched_commands.append(list(command))
        launched_event.set()
        return SimpleNamespace()

    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5410])
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)

    results: list[str] = []
    failures: list[str] = []

    def worker() -> None:
        try:
            barrier.wait()
            results.append(daemon_manager_module.ensure_guard_daemon(guard_home))
        except Exception as exc:  # pragma: no cover - test assertion path
            failures.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert failures == []
    assert results == ["http://127.0.0.1:5410"] * 8
    assert len(launched_commands) == 1
    assert launched_commands[0][-2:] == ["--port", "5410"]
