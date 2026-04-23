"""Focused tests for Guard daemon startup coordination."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
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

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)

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

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)

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
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
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


def test_ensure_guard_daemon_spawns_with_current_package_import_path(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    responses = iter((None, None, "http://127.0.0.1:5412"))
    captured_env: dict[str, str] = {}

    def fake_load_guard_daemon_url(_guard_home):
        return next(responses, "http://127.0.0.1:5412")

    def fake_popen(_command, **kwargs):
        captured_env.update(kwargs.get("env", {}))
        return SimpleNamespace(poll=lambda: None)

    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_load_state", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5412])
    monkeypatch.setattr(daemon_manager_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5412"
    assert str(Path(daemon_manager_module.__file__).resolve().parents[3]) in captured_env["PYTHONPATH"].split(
        os.pathsep
    )


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
    monkeypatch.setattr(
        daemon_manager_module,
        "_runtime_state_age_seconds",
        lambda guard_home: 60.0 if guard_home == stale_guard_home else None,
    )
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    pid_running = {"value": True}

    def fake_pid_is_running(_pid):
        return pid_running["value"]

    def fake_kill(pid, _signal):
        killed.append(pid)
        pid_running["value"] = False

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", fake_pid_is_running)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", fake_kill)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5413"
    assert killed == [11111]
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == {}
    assert json.loads(fresh_state_path.read_text(encoding="utf-8"))["pid"] == 22222


def test_ensure_guard_daemon_keeps_ephemeral_state_with_recent_runtime_heartbeat(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    active_guard_home = tmp_path / "pytest-of-user" / "pytest-3" / "test-active" / "home"
    active_guard_home.mkdir(parents=True)
    active_state_path = active_guard_home / "daemon-state.json"
    active_state_path.write_text(
        json.dumps(
            {
                "pid": 44444,
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
            return "http://127.0.0.1:5415"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5415])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home: 1.0)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, _signal: killed.append(pid))
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5415"
    assert killed == []
    assert json.loads(active_state_path.read_text(encoding="utf-8"))["pid"] == 44444


def test_ensure_guard_daemon_does_not_clobber_unowned_ephemeral_state_files(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    foreign_guard_home = tmp_path / "pytest-of-user" / "pytest-7" / "test-foreign" / "home"
    foreign_guard_home.mkdir(parents=True)
    foreign_state_path = foreign_guard_home / "daemon-state.json"
    foreign_state_path.write_text('"not-json-dict"', encoding="utf-8")
    launched_commands: list[list[str]] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5416"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5416])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5416"
    assert foreign_state_path.read_text(encoding="utf-8") == '"not-json-dict"'


def test_ensure_guard_daemon_keeps_stale_state_when_pid_no_longer_matches_guard_home(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    stale_guard_home = tmp_path / "pytest-of-user" / "pytest-8" / "test-reused-pid" / "home"
    stale_guard_home.mkdir(parents=True)
    stale_state_path = stale_guard_home / "daemon-state.json"
    stale_payload = {
        "pid": 66666,
        "guard_home": str(stale_guard_home),
        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "source_root": daemon_manager_module._current_guard_daemon_source_root(),
        "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
    }
    stale_state_path.write_text(json.dumps(stale_payload), encoding="utf-8")
    launched_commands: list[list[str]] = []

    def fake_load_guard_daemon_url(_guard_home):
        if launched_commands:
            return "http://127.0.0.1:5417"
        return None

    monkeypatch.setattr(daemon_manager_module, "_LAST_EPHEMERAL_REAP_AT", 0.0)
    monkeypatch.setattr(daemon_manager_module.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", fake_load_guard_daemon_url)
    monkeypatch.setattr(daemon_manager_module, "_candidate_ports", lambda _guard_home: [5417])
    monkeypatch.setattr(daemon_manager_module, "_state_path_age_seconds", lambda _path: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home: 60.0)
    monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: False,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5417"
    assert json.loads(stale_state_path.read_text(encoding="utf-8")) == stale_payload


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
    monkeypatch.setattr(daemon_manager_module, "_runtime_state_age_seconds", lambda _guard_home: None)
    pid_running = {"value": True}

    def fake_pid_is_running(_pid):
        return pid_running["value"]

    def fake_kill(pid, _signal):
        killed.append(pid)
        pid_running["value"] = False

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", fake_pid_is_running)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: True,
    )
    monkeypatch.setattr(daemon_manager_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(daemon_manager_module.os, "kill", fake_kill)
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda command, **_kwargs: launched_commands.append(list(command)) or SimpleNamespace(),
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5414"
    assert killed == [33333]
    assert json.loads((stale_guard_home / "daemon-state.json").read_text(encoding="utf-8")) == {}


def test_retire_guard_daemon_process_skips_recycled_pid_for_different_guard_home(tmp_path, monkeypatch):
    killed: list[int] = []
    payload = {
        "pid": 55555,
        "guard_home": str(tmp_path / "expected-home"),
    }

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: False,
    )
    monkeypatch.setattr(daemon_manager_module.os, "kill", lambda pid, _signal: killed.append(pid))

    retired = daemon_manager_module._retire_guard_daemon_process(payload)

    assert retired is False
    assert killed == []


def test_ephemeral_guard_daemon_state_paths_only_scan_pytest_roots_and_honor_limit(tmp_path, monkeypatch):
    pytest_root = tmp_path / "pytest-of-user"
    first_state = pytest_root / "pytest-1" / "case-a" / "home" / "daemon-state.json"
    second_state = pytest_root / "pytest-2" / "case-b" / "home" / "daemon-state.json"
    third_state = pytest_root / "pytest-3" / "case-c" / "home" / "daemon-state.json"
    ignored_state = tmp_path / "unrelated-tool" / "daemon-state.json"
    for path in (first_state, second_state, third_state, ignored_state):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(daemon_manager_module, "_EPHEMERAL_GUARD_DAEMON_MAX_STATES", 2)

    results = daemon_manager_module._ephemeral_guard_daemon_state_paths(tmp_path)

    assert results == [first_state, second_state]
    assert ignored_state not in results


def test_guard_daemon_pid_matches_command_validates_guard_home_on_windows(tmp_path, monkeypatch):
    expected_guard_home = tmp_path / "guard home"
    command = (
        f'python -m codex_plugin_scanner.cli guard daemon --serve --guard-home "{expected_guard_home}" --port 4781'
    )

    monkeypatch.setattr(daemon_manager_module.os, "name", "nt")
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=command),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_home_from_command",
        lambda _command: expected_guard_home,
    )

    assert daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=expected_guard_home,
    )
    assert not daemon_manager_module._guard_daemon_pid_matches_command(
        12345,
        expected_guard_home=tmp_path / "other-home",
    )
