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
    merge_dashboard_update_outcome,
    merge_dashboard_update_progress,
    schedule_guard_dashboard_update,
    write_dashboard_update_outcome,
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


def _post_json_body(daemon: GuardDaemonServer, path: str, body: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(body).encode("utf-8"),
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

    def fake_schedule(
        guard_home: Path,
        daemon_pid: int,
        daemon_port: int,
        **kwargs: object,
    ) -> dict[str, object]:
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
        "codex_plugin_scanner.guard.daemon.dashboard_update._pid_is_running",
        lambda pid: pid == 5151,
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
        "codex_plugin_scanner.guard.daemon.dashboard_update_runner._retire_guard_daemon_pid",
        lambda pid, **kwargs: calls.append(f"retire_pid:{pid}"),
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
        lambda _home, **kwargs: calls.append(f"ensure:{kwargs.get('preferred_port')}") or "http://127.0.0.1:5474",
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
        "retire_pid:5150",
        "clear_state",
        "repair_locator",
        "retire",
        "retire_pid:5150",
        "clear_state",
        "ensure:5474",
        "clear_lock",
    ]


def test_status_payload_exposes_recovery_for_local_folder_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._current_version",
        lambda: "1.0.0",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._installer_kind",
        lambda: "pipx",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._direct_url_payload",
        lambda: {"url": "file:///home/me/hol-guard", "dir_info": {}},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._local_source_install_payload",
        lambda direct_url: {
            "kind": "local_path",
            "url": "file:///home/me/hol-guard",
            "path": "/home/me/hol-guard",
            "path_exists": True,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._version_check_payload",
        lambda current_version: {
            "source": "pypi",
            "status": "current",
            "current_version": current_version,
            "latest_version": current_version,
            "update_available": False,
        },
    )

    payload = build_guard_update_status_payload()

    assert payload["auto_updatable"] is False
    assert payload["recovery_reinstall_available"] is True
    assert payload["recovery_reinstall_command"] == "pipx install --force hol-guard"


def test_status_payload_blocks_python_incompatible_latest_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._current_version",
        lambda: "2.0.789",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._installer_kind",
        lambda: "pipx",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._direct_url_payload",
        lambda: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._latest_version_from_pypi",
        lambda: "2.0.807",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._latest_version_python_requirements",
        lambda latest: (">=3.10,<3.14",),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._latest_compatible_release_version",
        lambda current, runtime: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._runtime_python_version",
        lambda: "3.14.0",
    )

    payload = build_guard_update_status_payload()

    assert payload["auto_updatable"] is False
    assert payload["update_available"] is False
    assert payload["python_update_required"] is True
    assert "requires Python >=3.10,<3.14" in str(payload["blocked_reason"])


def test_status_payload_hides_recovery_for_editable_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._current_version",
        lambda: "1.0.0",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._installer_kind",
        lambda: "pipx",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._direct_url_payload",
        lambda: {"url": "file:///home/me/hol-guard", "dir_info": {"editable": True}},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._local_source_install_payload",
        lambda direct_url: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._version_check_payload",
        lambda current_version: {
            "source": "pypi",
            "status": "current",
            "current_version": current_version,
            "latest_version": current_version,
            "update_available": False,
        },
    )

    payload = build_guard_update_status_payload()

    assert payload["auto_updatable"] is False
    assert payload["recovery_reinstall_available"] is False
    assert payload["recovery_reinstall_command"] is None


def test_status_payload_hides_auto_update_for_local_wheel_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._current_version",
        lambda: "1.0.0",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._installer_kind",
        lambda: "pipx",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._direct_url_payload",
        lambda: {"url": "file:///home/me/dist/hol_guard-1.0.0-py3-none-any.whl", "archive_info": {"hash": "sha256:abc"}},
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._local_source_install_payload",
        lambda direct_url: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._local_archive_install_payload",
        lambda direct_url: {
            "kind": "local_archive",
            "archive_type": "wheel",
            "url": "file:///home/me/dist/hol_guard-1.0.0-py3-none-any.whl",
            "path": "/home/me/dist/hol_guard-1.0.0-py3-none-any.whl",
            "path_exists": True,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._version_check_payload",
        lambda current_version: {
            "source": "pypi",
            "status": "current",
            "current_version": current_version,
            "latest_version": current_version,
            "update_available": False,
        },
    )

    payload = build_guard_update_status_payload()

    assert payload["auto_updatable"] is False
    assert payload["recovery_reinstall_available"] is True
    assert "local wheel" in str(payload["blocked_reason"])


def test_daemon_update_schedules_recovery_reinstall_for_local_folder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    scheduled: dict[str, object] = {}

    def fake_schedule(guard_home, daemon_pid, daemon_port, **kwargs):
        scheduled["guard_home"] = guard_home
        scheduled["daemon_pid"] = daemon_pid
        scheduled["daemon_port"] = daemon_port
        scheduled["force_pypi_reinstall"] = kwargs.get("force_pypi_reinstall")
        return {"scheduled": True, "message": "reinstall scheduled"}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.build_guard_update_status_payload",
        lambda: {
            "current_version": "1.0.0",
            "latest_version": "1.0.0",
            "installer": "pipx",
            "version_check": {
                "source": "pypi",
                "status": "current",
                "current_version": "1.0.0",
                "latest_version": "1.0.0",
                "update_available": False,
            },
            "auto_updatable": False,
            "update_available": False,
            "blocked_reason": "This install was set up from a local folder.",
            "recovery_reinstall_available": True,
            "recovery_reinstall_command": "pipx install --force hol-guard",
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.schedule_guard_dashboard_update",
        fake_schedule,
    )

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _post_json_body(daemon, "/v1/update", {"force_pypi_reinstall": True})
    finally:
        daemon.stop()

    assert status == 200
    assert payload["scheduled"] is True
    assert scheduled["force_pypi_reinstall"] is True


def test_daemon_update_recovery_reinstall_rejected_for_editable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.build_guard_update_status_payload",
        lambda: {
            "current_version": "1.0.0",
            "latest_version": "1.0.0",
            "installer": "pipx",
            "version_check": {
                "source": "pypi",
                "status": "current",
                "current_version": "1.0.0",
                "latest_version": "1.0.0",
                "update_available": False,
            },
            "auto_updatable": False,
            "update_available": False,
            "blocked_reason": "This install was set up from local source code.",
            "recovery_reinstall_available": False,
            "recovery_reinstall_command": None,
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
        status, payload = _post_json_body(daemon, "/v1/update", {"force_pypi_reinstall": True})
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "update_not_supported"
    schedule_mock.assert_not_called()


def test_daemon_update_recovery_reinstall_rejected_when_python_incompatible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.build_guard_update_status_payload",
        lambda: {
            "current_version": "2.0.789",
            "latest_version": "2.0.807",
            "installer": "pipx",
            "version_check": {
                "source": "pypi",
                "status": "python_incompatible",
                "current_version": "2.0.789",
                "latest_version": "2.0.807",
                "update_available": True,
                "required_python": ">=3.10,<3.14",
                "runtime_python": "3.14.0",
            },
            "auto_updatable": False,
            "update_available": False,
            "blocked_reason": "HOL Guard 2.0.807 requires Python >=3.10,<3.14.",
            "python_update_required": True,
            "recovery_reinstall_available": True,
            "recovery_reinstall_command": "pipx install --force hol-guard",
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
        status, payload = _post_json_body(daemon, "/v1/update", {"force_pypi_reinstall": True})
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "update_not_supported"
    assert "requires Python" in str(payload["message"])
    schedule_mock.assert_not_called()


def test_runner_command_appends_force_pypi_reinstall_flag(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    command = build_dashboard_update_runner_command(
        guard_home.resolve(),
        daemon_pid=99,
        daemon_port=1234,
        force_pypi_reinstall=True,
    )
    assert "--force-pypi-reinstall" in command

    command_without = build_dashboard_update_runner_command(
        guard_home.resolve(),
        daemon_pid=99,
        daemon_port=1234,
    )
    assert "--force-pypi-reinstall" not in command_without


def test_merge_dashboard_update_outcome_suppresses_repeat_update_button(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    write_dashboard_update_outcome(
        guard_home,
        {
            "status": "stale",
            "current_version": "2.0.741",
            "resulting_version": "2.0.741",
            "version_check": {"latest_version": "2.0.743", "update_available": True},
            "retry_command": "pipx install --force hol-guard",
            "message": "HOL Guard 2.0.741 is behind PyPI 2.0.743 after the update attempt.",
        },
    )

    payload = merge_dashboard_update_outcome(
        guard_home,
        {
            "current_version": "2.0.741",
            "latest_version": "2.0.743",
            "update_available": True,
            "auto_updatable": True,
        },
    )

    assert payload["update_suppressed"] is True
    assert payload["retry_command"] == "pipx install --force hol-guard"
    assert "behind PyPI 2.0.743" in str(payload["update_attempt_message"])


def test_merge_dashboard_update_outcome_clears_when_install_is_current(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    write_dashboard_update_outcome(
        guard_home,
        {
            "status": "stale",
            "current_version": "2.0.741",
            "resulting_version": "2.0.741",
            "version_check": {"latest_version": "2.0.743"},
            "retry_command": "pipx install --force hol-guard",
        },
    )

    payload = merge_dashboard_update_outcome(
        guard_home,
        {
            "current_version": "2.0.743",
            "latest_version": "2.0.743",
            "update_available": False,
            "auto_updatable": True,
        },
    )

    assert "update_suppressed" not in payload
    assert not (guard_home / "dashboard-update-outcome.json").exists()
