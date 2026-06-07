"""Tests for dashboard-triggered Guard updates."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.cli.update_commands import build_guard_update_status_payload
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.dashboard_update import (
    build_dashboard_update_runner_command,
    build_dashboard_update_runner_popen_kwargs,
    dashboard_update_runner_script,
    merge_dashboard_update_progress,
    schedule_guard_dashboard_update,
)
from codex_plugin_scanner.guard.store import GuardStore


def _store(tmp_path: Path) -> GuardStore:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return GuardStore(guard_home)


def _get_json(daemon: GuardDaemonServer, path: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        headers={"X-Guard-Token": daemon._server.auth_token},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    assert isinstance(payload, dict)
    return payload


def _post_json(daemon: GuardDaemonServer, path: str) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=b"{}",
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert isinstance(payload, dict)
            return response.status, payload
    except urllib.error.HTTPError as error:
        payload = json.loads(error.read().decode("utf-8"))
        assert isinstance(payload, dict)
        return error.code, payload


def test_build_guard_update_status_payload_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._current_version",
        lambda: "1.2.3",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._installer_kind",
        lambda: "pip",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._direct_url_payload",
        lambda: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._version_check_payload",
        lambda current_version: {
            "source": "pypi",
            "status": "stale",
            "current_version": current_version,
            "latest_version": "1.2.4",
            "update_available": True,
        },
    )

    payload = build_guard_update_status_payload()

    assert payload["current_version"] == "1.2.3"
    assert payload["latest_version"] == "1.2.4"
    assert payload["auto_updatable"] is True
    assert payload["update_available"] is True


def test_daemon_update_status_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.build_guard_update_status_payload",
        lambda: {
            "current_version": "9.9.9",
            "latest_version": "9.9.9",
            "installer": "pip",
            "version_check": {
                "source": "pypi",
                "status": "current",
                "current_version": "9.9.9",
                "latest_version": "9.9.9",
                "update_available": False,
            },
            "auto_updatable": True,
            "update_available": False,
            "blocked_reason": None,
        },
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        payload = _get_json(daemon, "/v1/update/status")
    finally:
        daemon.stop()

    assert payload["current_version"] == "9.9.9"
    assert payload["update_available"] is False


def test_daemon_update_schedule_route(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    scheduled: dict[str, object] = {}

    def fake_schedule(guard_home: Path, daemon_pid: int, daemon_port: int) -> dict[str, object]:
        scheduled["guard_home"] = guard_home
        scheduled["daemon_pid"] = daemon_pid
        scheduled["daemon_port"] = daemon_port
        return {"scheduled": True, "message": "scheduled"}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.build_guard_update_status_payload",
        lambda: {
            "current_version": "1.0.0",
            "latest_version": "1.0.1",
            "installer": "pip",
            "version_check": {
                "source": "pypi",
                "status": "stale",
                "current_version": "1.0.0",
                "latest_version": "1.0.1",
                "update_available": True,
            },
            "auto_updatable": True,
            "update_available": True,
            "blocked_reason": None,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.schedule_guard_dashboard_update",
        fake_schedule,
    )

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _post_json(daemon, "/v1/update")
    finally:
        daemon.stop()

    assert status == 200
    assert payload["scheduled"] is True
    assert scheduled["guard_home"] == store.guard_home
    assert isinstance(scheduled["daemon_pid"], int)
    assert isinstance(scheduled["daemon_port"], int)


def test_daemon_update_schedule_rejects_non_updatable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.build_guard_update_status_payload",
        lambda: {
            "current_version": "1.0.0",
            "latest_version": "1.0.0",
            "installer": "pip",
            "version_check": {
                "source": "pypi",
                "status": "current",
                "current_version": "1.0.0",
                "latest_version": "1.0.0",
                "update_available": False,
            },
            "auto_updatable": True,
            "update_available": False,
            "blocked_reason": None,
        },
    )
    schedule_mock = MagicMock()
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.schedule_guard_dashboard_update",
        schedule_mock,
    )

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _post_json(daemon, "/v1/update")
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "update_not_available"
    schedule_mock.assert_not_called()


def test_schedule_guard_dashboard_update_spawns_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeProcess:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            captured["command"] = command
            captured["kwargs"] = kwargs

            self.pid = 4243

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update.subprocess.Popen",
        FakeProcess,
    )

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    result = schedule_guard_dashboard_update(guard_home, daemon_pid=4242, daemon_port=8787)

    assert result["scheduled"] is True
    command = captured["command"]
    assert isinstance(command, list)
    assert "-m" not in command
    runner_script = dashboard_update_runner_script()
    assert str(runner_script) in command
    if sys.version_info >= (3, 11):
        assert command[1] == "-P"
        assert command[2] == str(runner_script)
    else:
        assert command[1] == str(runner_script)
    assert "--guard-home" in command
    assert str(guard_home.resolve()) in command
    assert "--daemon-pid" in command
    assert "4242" in command
    assert "--daemon-port" in command
    assert "8787" in command
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs.get("cwd") == str(guard_home.resolve())


def test_runner_command_avoids_module_shadowing_from_cwd(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    command = build_dashboard_update_runner_command(
        guard_home.resolve(),
        daemon_pid=99,
        daemon_port=1234,
    )
    assert "-m" not in command
    assert "codex_plugin_scanner.guard.daemon.dashboard_update_runner" not in command
    runner_script = dashboard_update_runner_script()
    assert str(runner_script) in command
    assert runner_script.is_file()


def test_runner_env_ignores_inherited_pythonpath(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evil_root = tmp_path / "evil-repo" / "src"
    evil_root.mkdir(parents=True)
    monkeypatch.setenv("PYTHONPATH", str(evil_root))
    env = build_dashboard_update_runner_popen_kwargs(tmp_path / "guard-home")["env"]
    assert isinstance(env, dict)
    pythonpath = str(env.get("PYTHONPATH", ""))
    assert str(evil_root) not in pythonpath.split(os.pathsep)
    assert str(dashboard_update_runner_script().resolve().parents[3]) in pythonpath
    if sys.version_info >= (3, 11):
        assert env.get("PYTHONSAFEPATH") == "1"


def test_merge_dashboard_update_progress_includes_lock_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            self.pid = 5151

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update.subprocess.Popen",
        FakeProcess,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update.build_guard_update_status_payload",
        lambda: {
            "current_version": "2.0.508",
            "latest_version": "2.0.509",
            "installer": "pipx",
            "version_check": {
                "source": "pypi",
                "status": "stale",
                "current_version": "2.0.508",
                "latest_version": "2.0.509",
                "update_available": True,
            },
            "auto_updatable": True,
            "update_available": True,
            "blocked_reason": None,
        },
    )

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    schedule_guard_dashboard_update(guard_home, daemon_pid=5150, daemon_port=5474)
    payload = merge_dashboard_update_progress(
        guard_home,
        {"current_version": "2.0.508", "update_available": True},
    )

    assert payload["update_in_progress"] is True
    assert payload["previous_version"] == "2.0.508"
    assert payload["target_version"] == "2.0.509"
    assert payload["daemon_port"] == 5474


def test_dashboard_update_runner_retires_all_daemons_before_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    calls: list[str] = []

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner.time.sleep",
        lambda _seconds: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner.retire_all_guard_daemons_for_home",
        lambda _home, **kwargs: calls.append("retire") or [],
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner.clear_guard_daemon_state",
        lambda _home: calls.append("clear_state"),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner.repair_approval_center_locator",
        lambda _home: calls.append("repair_locator") or {"repaired": True, "cleared": []},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner.run_guard_update",
        lambda **kwargs: ({"status": "updated"}, 0),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner.ensure_guard_daemon_after_update",
        lambda _home: calls.append("ensure") or "http://127.0.0.1:5474",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner.clear_dashboard_update_lock",
        lambda _home: calls.append("clear_lock"),
    )

    from codex_plugin_scanner.guard.daemon.dashboard_update_runner import main

    exit_code = main(
        [
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "5150",
            "--daemon-port",
            "5474",
        ]
    )

    assert exit_code == 0
    assert calls == [
        "retire",
        "clear_state",
        "repair_locator",
        "retire",
        "clear_state",
        "ensure",
        "clear_lock",
    ]
