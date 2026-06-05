"""Focused tests for Guard daemon startup coordination."""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


def _disable_daemon_adoption(monkeypatch) -> None:
    monkeypatch.setattr(daemon_manager_module, "_adopt_existing_guard_daemon", lambda _guard_home: None)


def _disable_duplicate_retire(monkeypatch) -> None:
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_duplicate_guard_daemons",
        lambda _guard_home, *, keep_port: None,
    )


def test_write_guard_daemon_state_keeps_auth_token_out_of_state_file(tmp_path):
    guard_home = tmp_path / "guard-home"

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")

    state_path = daemon_manager_module._state_path(guard_home)
    token_path = daemon_manager_module._auth_token_path(guard_home)
    state_payload = json.loads(state_path.read_text(encoding="utf-8"))

    assert state_payload["port"] == 4781
    assert "auth_token" not in state_payload
    assert daemon_manager_module.load_guard_daemon_auth_token(guard_home) == "secret-token"
    assert token_path.read_text(encoding="utf-8") == "secret-token"
    assert stat.S_IMODE(state_path.stat().st_mode) & 0o077 == 0
    assert stat.S_IMODE(token_path.stat().st_mode) & 0o077 == 0


def test_clear_guard_daemon_state_preserves_auth_token_file(tmp_path):
    guard_home = tmp_path / "guard-home"

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")
    daemon_manager_module.clear_guard_daemon_state(guard_home)

    assert json.loads(daemon_manager_module._state_path(guard_home).read_text(encoding="utf-8")) == {}
    assert daemon_manager_module._auth_token_path(guard_home).read_text(encoding="utf-8") == "secret-token"


def test_load_guard_daemon_url_rejects_live_port_when_state_pid_is_not_guard_daemon(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    other_guard_home = tmp_path / "other-guard-home"
    daemon_manager_module.write_guard_daemon_state(guard_home, 4833, "secret-token")

    class FakeResponse:
        status = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "ok": True,
                    "tables": ["guard_connect_states"],
                    "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "guard_home": str(other_guard_home),
                }
            ).encode("utf-8")

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: False,
    )
    monkeypatch.setattr(
        daemon_manager_module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(),
    )

    assert daemon_manager_module.load_guard_daemon_url(guard_home) is None


def test_load_guard_daemon_url_accepts_matching_healthz_guard_home_for_in_process_daemon(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    daemon_manager_module.write_guard_daemon_state(guard_home, 4833, "secret-token")
    requested_urls: list[str] = []
    requested_headers: list[dict[str, str]] = []

    class FakeResponse:
        status = 200

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "ok": True,
                    "tables": ["guard_connect_states"],
                    "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                    "guard_home": str(guard_home),
                }
            ).encode("utf-8")

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_pid_matches_command",
        lambda _pid, expected_guard_home=None: False,
    )

    def fake_urlopen(request, *_args, **_kwargs):
        requested_urls.append(request.full_url if hasattr(request, "full_url") else str(request))
        if hasattr(request, "header_items"):
            requested_headers.append(dict(request.header_items()))
        else:
            requested_headers.append({})
        return FakeResponse()

    monkeypatch.setattr(daemon_manager_module.urllib.request, "urlopen", fake_urlopen)

    assert daemon_manager_module.load_guard_daemon_url(guard_home) == "http://127.0.0.1:4833"
    assert requested_urls == [
        "http://127.0.0.1:4833/healthz",
        "http://127.0.0.1:4833/v1/healthz/details",
    ]
    assert requested_headers[0] == {}
    assert requested_headers[1]["X-guard-token"] == "secret-token"


def test_write_guard_daemon_state_hardens_permissions_on_open_descriptor(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    fchmod_calls: list[tuple[int, int]] = []

    def fake_fchmod(descriptor: int, mode: int) -> None:
        fchmod_calls.append((descriptor, mode))

    monkeypatch.setattr(daemon_manager_module.os, "fchmod", fake_fchmod)

    daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "secret-token")

    assert len(fchmod_calls) == 2
    assert all(mode == 0o600 for _, mode in fchmod_calls)


def test_healthz_payload_is_current_accepts_redacted_public_healthz() -> None:
    payload = json.dumps(
        {
            "ok": True,
            "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
        }
    )

    assert daemon_manager_module._healthz_payload_is_current(payload) is True


def test_guard_daemon_url_port_rejects_invalid_port_text() -> None:
    assert daemon_manager_module._guard_daemon_url_port("http://127.0.0.1:not-a-port") is None


def test_guard_daemon_port_from_command_supports_equals_syntax() -> None:
    command = (
        "python -m codex_plugin_scanner.cli guard daemon --serve "
        "--guard-home /tmp/guard-home --port=5474"
    )
    assert daemon_manager_module._guard_daemon_port_from_command(command) == 5474


def test_ensure_guard_daemon_reuses_inflight_pid_before_respawning(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    responses = iter((None, None, "http://127.0.0.1:5409"))

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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


def test_ensure_guard_daemon_adopts_running_guard_daemon_before_respawning(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home: None)
    monkeypatch.setattr(daemon_manager_module, "_adoptable_guard_daemon_ports", lambda _guard_home: [5474])
    monkeypatch.setattr(
        daemon_manager_module,
        "_initialize_existing_guard_daemon",
        lambda _guard_home, port: {"url": f"http://127.0.0.1:{port}", "auth_token": "secret-token"},
    )
    monkeypatch.setattr(
        daemon_manager_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not spawn a new daemon")),
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home: [(111, 5474)],
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5474"
    assert daemon_manager_module.load_guard_daemon_auth_token(guard_home) == "secret-token"
    state_payload = json.loads(daemon_manager_module._state_path(guard_home).read_text(encoding="utf-8"))
    assert state_payload["port"] == 5474
    assert state_payload["pid"] == 111


def test_adopt_existing_guard_daemon_skips_scan_on_windows(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"

    monkeypatch.setattr(daemon_manager_module.os, "name", "nt", raising=False)
    monkeypatch.setattr(
        daemon_manager_module,
        "_initialize_existing_guard_daemon",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not attempt adoption")),
    )

    url = daemon_manager_module._adopt_existing_guard_daemon(guard_home)

    assert url is None


def test_ensure_guard_daemon_retires_duplicate_ports_for_same_guard_home(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    killed: list[int] = []

    monkeypatch.setattr(daemon_manager_module, "_reap_stale_ephemeral_guard_daemons", lambda **_kwargs: None)
    monkeypatch.setattr(daemon_manager_module, "load_guard_daemon_url", lambda _guard_home: "http://127.0.0.1:5474")
    monkeypatch.setattr(
        daemon_manager_module,
        "_running_guard_daemon_processes_for_guard_home",
        lambda _guard_home: [(111, 5474), (222, 5475)],
    )
    monkeypatch.setattr(
        daemon_manager_module,
        "_retire_guard_daemon_pid",
        lambda pid, *, expected_guard_home=None: killed.append(pid) or True,
    )

    url = daemon_manager_module.ensure_guard_daemon(guard_home)

    assert url == "http://127.0.0.1:5474"
    assert killed == [222]


def test_ensure_guard_daemon_serializes_parallel_start_attempts(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    launched_commands: list[list[str]] = []
    launched_envs: list[dict[str, str]] = []
    launched_event = threading.Event()
    barrier = threading.Barrier(8)

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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

    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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
    _disable_daemon_adoption(monkeypatch)
    _disable_duplicate_retire(monkeypatch)
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


def test_guard_daemon_start_lock_prevents_concurrent_starts(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)

    events: list[str] = []
    errors: list[Exception] = []
    t1_entered = threading.Event()
    release_holder = threading.Event()

    def holder() -> None:
        try:
            with daemon_manager_module._guard_daemon_start_lock(guard_home):
                events.append("t1-entered")
                t1_entered.set()
                release_holder.wait(timeout=5)
                events.append("t1-exited")
        except Exception as exc:
            errors.append(exc)

    def waiter() -> None:
        try:
            with daemon_manager_module._guard_daemon_start_lock(guard_home):
                events.append("t2-entered")
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=holder)
    t1.start()
    t1_entered.wait(timeout=5)
    t2 = threading.Thread(target=waiter)
    t2.start()
    release_holder.set()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not errors, f"Lock worker raised: {errors}"
    assert events.index("t1-exited") < events.index("t2-entered"), (
        "Second thread entered before first released the lock"
    )


def test_guard_daemon_start_lock_file_created_and_released(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    lock_path = guard_home / "daemon-start.lock"

    assert not lock_path.exists()

    with daemon_manager_module._guard_daemon_start_lock(guard_home):
        assert lock_path.exists()

    assert lock_path.exists()


def test_guard_daemon_start_lock_recovers_after_exception(tmp_path):
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)

    raised = False
    try:
        with daemon_manager_module._guard_daemon_start_lock(guard_home):
            raised = True
            raise RuntimeError("simulated crash")
    except RuntimeError:
        pass

    assert raised

    acquired = False
    with daemon_manager_module._guard_daemon_start_lock(guard_home):
        acquired = True
    assert acquired, "Lock was not released after exception; stale lock not recoverable"
