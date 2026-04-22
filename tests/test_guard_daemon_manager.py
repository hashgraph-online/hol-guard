"""Focused tests for Guard daemon startup coordination."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


def test_ensure_guard_daemon_reuses_inflight_pid_before_respawning(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    responses = iter((None, None, "http://127.0.0.1:5409"))

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
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
            "source_root": daemon_manager_module._current_guard_daemon_source_root(),
            "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
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
    launched_envs: list[dict[str, str]] = []
    launched_event = threading.Event()
    barrier = threading.Barrier(8)

    def fake_load_guard_daemon_url(_guard_home):
        if launched_event.is_set():
            return "http://127.0.0.1:5410"
        return None

    def fake_popen(command, **_kwargs):
        launched_commands.append(list(command))
        launched_envs.append(dict(_kwargs["env"]))
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
    assert launched_envs[0]["PYTHONPATH"].split(daemon_manager_module.os.pathsep)[0] == (
        daemon_manager_module._current_guard_daemon_source_root()
    )


def test_ensure_guard_daemon_advances_ports_after_early_process_exit(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_commands: list[list[str]] = []
    poll_count = {"value": 0}

    class FakeProcess:
        def __init__(self, *, alive: bool) -> None:
            self._alive = alive

        def poll(self) -> int | None:
            if self._alive:
                return None
            return 1

    def fake_load_guard_daemon_url(_guard_home):
        if poll_count["value"] < 4:
            poll_count["value"] += 1
            return None
        return "http://127.0.0.1:5411"

    def fake_popen(command, **_kwargs):
        launched_commands.append(list(command))
        return FakeProcess(alive=len(launched_commands) > 1)

    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5410, 5411])
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5411"
    assert [command[-1] for command in launched_commands] == ["5410", "5411"]


def test_ensure_guard_daemon_retires_stale_daemon_from_different_source_root(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_commands: list[list[str]] = []
    killed: list[int] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5412"
        return None

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(
        daemon_manager_module,
        "_load_state",
        lambda _guard_home: {
            "pid": 98765,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "source_root": "/tmp/older-source-root",
            "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
        },
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, _signal: killed.append(pid))
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5412])
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5412"
    assert killed == [98765, 98765]
    assert launched_commands[0][-2:] == ["--port", "5412"]


def test_ensure_guard_daemon_reaps_stale_ephemeral_daemon_states(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-1" / "test-stale" / "home"
    stale_guard_home.mkdir(parents=True)
    stale_state_path = stale_guard_home / "daemon-state.json"
    stale_state_path.write_text(
        json.dumps(
            {
                "pid": 11111,
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            }
        ),
        encoding="utf-8",
    )
    fresh_guard_home = tmp_path / "pytest-of-user" / "pytest-2" / "test-fresh" / "home"
    fresh_guard_home.mkdir(parents=True)
    fresh_state_path = fresh_guard_home / "daemon-state.json"
    fresh_state_path.write_text(
        json.dumps(
            {
                "pid": 22222,
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            }
        ),
        encoding="utf-8",
    )
    launched_commands: list[list[str]] = []
    killed: list[int] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5413"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(
        daemon_manager_module,
        "_candidate_ports",
        lambda _guard_home: [5413],
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_state_path_age_seconds",
        lambda path: 60.0 if path == stale_state_path else 0.0,
    )
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, _signal: killed.append(pid))
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5413"
    assert killed == [11111, 11111]
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == {}
    assert json.loads(fresh_state_path.read_text(encoding="utf-8"))["pid"] == 22222


def test_ensure_guard_daemon_reaps_stale_ephemeral_processes_without_state_file(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-9" / "test-stale" / "home"
    stale_guard_home.mkdir(parents=True)
    launched_commands: list[list[str]] = []
    killed: list[int] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5414"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5414])
    monkeypatch.setattr(daemon_manager_module, "_ephemeral_guard_daemon_state_paths", lambda _temp_root: [])
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_ephemeral_guard_daemon_processes",
        lambda: [(33333, stale_guard_home, 60.0)],
    )
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_matches_command", lambda _pid: True)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, _signal: killed.append(pid))
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5414"
    assert killed == [33333, 33333]
    assert json.loads((stale_guard_home / "daemon-state.json").read_text(encoding="utf-8")) == {}
