"""Tests for dashboard-triggered Guard updates."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.update_commands import build_guard_update_status_payload
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import dashboard_update as dashboard_update_module
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
from tests.update_context_test_support import build_legacy_status_distribution


@pytest.fixture(autouse=True)
def _use_legacy_status_distribution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._status_installed_distribution",
        build_legacy_status_distribution,
    )


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
        lambda current_version, **_kwargs: {
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
            captured["reservation_at_spawn"] = dashboard_update_module.read_dashboard_update_lock(guard_home)

            self.pid = 4243

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.dashboard_update.subprocess.Popen",
        FakeProcess,
    )
    monkeypatch.setattr(
        dashboard_update_module,
        "build_guard_update_status_payload",
        lambda: {"current_version": "2.0.1", "latest_version": "2.0.2"},
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
    assert Path(command[0]).is_absolute()
    assert command[1:4] == ["-I", "-S", "-c"]
    assert "-P" not in command
    assert command[4] == dashboard_update_module._DASHBOARD_UPDATE_RUNNER_BOOTSTRAP
    assert command[5] == str(Path(sys.prefix).resolve())
    assert command[6] == str(Path(sys.exec_prefix).resolve())
    trusted_import_paths = json.loads(command[7])
    assert str(runner_script.parents[3]) in trusted_import_paths
    assert all(Path(path).is_absolute() for path in trusted_import_paths)
    assert command[8] == str(runner_script)
    assert "--guard-home" in command
    assert str(guard_home.resolve()) in command
    assert "--daemon-pid" in command
    assert "4242" in command
    assert "--daemon-port" in command
    assert "8787" in command
    assert "--update-token" in command
    update_token = command[command.index("--update-token") + 1]
    assert isinstance(update_token, str)
    assert len(update_token) == 64
    reservation = captured["reservation_at_spawn"]
    assert isinstance(reservation, dict)
    assert reservation["token"] == update_token
    assert reservation["state"] == "reserved"
    assert "runner_pid" not in reservation
    if os.name != "nt":
        lock_mode = stat.S_IMODE(dashboard_update_module.dashboard_update_lock_path(guard_home).stat().st_mode)
        assert lock_mode == 0o600
    kwargs = captured["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs.get("cwd") == str(guard_home.resolve())


def test_schedule_guard_dashboard_update_allows_only_one_concurrent_installer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    spawned_commands: list[list[str]] = []
    nested_result: dict[str, object] = {}

    class FakeProcess:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            spawned_commands.append(command)
            nested_result.update(schedule_guard_dashboard_update(guard_home, daemon_pid=6002, daemon_port=5475))
            self.pid = 6001

    monkeypatch.setattr(dashboard_update_module.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(
        dashboard_update_module,
        "build_guard_update_status_payload",
        lambda: {"current_version": "2.0.1", "latest_version": "2.0.2"},
    )

    result = schedule_guard_dashboard_update(guard_home, daemon_pid=6000, daemon_port=5474)

    assert result["scheduled"] is True
    assert nested_result == {
        "scheduled": False,
        "error": "update_in_progress",
        "message": "Guard is already updating on this machine.",
    }
    assert len(spawned_commands) == 1


def test_schedule_guard_dashboard_update_does_not_recreate_lock_after_fast_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()

    class FastProcess:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            token = command[command.index("--update-token") + 1]
            reservation = dashboard_update_module.read_dashboard_update_lock(guard_home)
            assert reservation is not None
            assert reservation["state"] == "reserved"
            assert dashboard_update_module.claim_dashboard_update_lock(guard_home, token=token) is True
            claimed = dashboard_update_module.read_dashboard_update_lock(guard_home)
            assert claimed is not None
            assert claimed["runner_pid"] == os.getpid()
            assert dashboard_update_module.clear_dashboard_update_lock(guard_home, token=token) is True
            self.pid = 6101

    monkeypatch.setattr(dashboard_update_module.subprocess, "Popen", FastProcess)
    monkeypatch.setattr(
        dashboard_update_module,
        "build_guard_update_status_payload",
        lambda: {"current_version": "2.0.1", "latest_version": "2.0.2"},
    )

    result = schedule_guard_dashboard_update(guard_home, daemon_pid=6100, daemon_port=5474)

    assert result["scheduled"] is True
    assert dashboard_update_module.dashboard_update_lock_path(guard_home).exists() is False


def test_dashboard_update_lock_can_only_be_claimed_and_cleared_by_its_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()

    class FakeProcess:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            self.pid = 6201

    monkeypatch.setattr(dashboard_update_module.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(
        dashboard_update_module,
        "build_guard_update_status_payload",
        lambda: {"current_version": "2.0.1", "latest_version": "2.0.2"},
    )
    schedule_guard_dashboard_update(guard_home, daemon_pid=6200, daemon_port=5474)
    reservation = dashboard_update_module.read_dashboard_update_lock(guard_home)
    assert reservation is not None
    token = reservation["token"]
    assert isinstance(token, str)

    assert dashboard_update_module.claim_dashboard_update_lock(guard_home, token="wrong-token") is False
    assert dashboard_update_module.clear_dashboard_update_lock(guard_home, token="wrong-token") is False
    assert dashboard_update_module.claim_dashboard_update_lock(guard_home, token=token) is True
    claimed = dashboard_update_module.read_dashboard_update_lock(guard_home)
    assert claimed is not None
    assert claimed["state"] == "running"
    assert claimed["runner_pid"] == os.getpid()
    assert dashboard_update_module.clear_dashboard_update_lock(guard_home, token="wrong-token") is False
    assert dashboard_update_module.clear_dashboard_update_lock(guard_home, token=token) is True
    assert dashboard_update_module.dashboard_update_lock_path(guard_home).exists() is False


def test_schedule_guard_dashboard_update_clears_reservation_when_spawn_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()

    def fail_spawn(command: list[str], **kwargs: object) -> None:
        raise OSError("spawn failed")

    monkeypatch.setattr(dashboard_update_module.subprocess, "Popen", fail_spawn)
    monkeypatch.setattr(
        dashboard_update_module,
        "build_guard_update_status_payload",
        lambda: {"current_version": "2.0.1", "latest_version": "2.0.2"},
    )

    with pytest.raises(OSError, match="spawn failed"):
        schedule_guard_dashboard_update(guard_home, daemon_pid=6300, daemon_port=5474)

    assert dashboard_update_module.dashboard_update_lock_path(guard_home).exists() is False


def test_dashboard_update_stale_window_exceeds_two_ten_minute_attempts(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    lock_path = dashboard_update_module.dashboard_update_lock_path(guard_home)
    token = "a" * 64
    twenty_one_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=21)
    lock_path.write_text(
        json.dumps({"token": token, "state": "reserved", "started_at": twenty_one_minutes_ago.isoformat()}),
        encoding="utf-8",
    )

    assert dashboard_update_module._DASHBOARD_UPDATE_STALE_SECONDS > 2 * 10 * 60
    assert dashboard_update_module.dashboard_update_in_progress(guard_home) is True
    assert lock_path.exists() is True

    expired_at = datetime.now(timezone.utc) - timedelta(
        seconds=dashboard_update_module._DASHBOARD_UPDATE_STALE_SECONDS + 1
    )
    lock_path.write_text(
        json.dumps({"token": token, "state": "reserved", "started_at": expired_at.isoformat()}),
        encoding="utf-8",
    )
    assert dashboard_update_module.dashboard_update_in_progress(guard_home) is False
    assert lock_path.exists() is False


def test_dashboard_update_reclaims_lock_for_dead_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    lock_path = dashboard_update_module.dashboard_update_lock_path(guard_home)
    lock_path.write_text(
        json.dumps(
            {
                "token": "b" * 64,
                "state": "running",
                "runner_pid": 6401,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(dashboard_update_module, "_pid_is_running", lambda pid: False)

    assert dashboard_update_module.dashboard_update_in_progress(guard_home) is False
    assert lock_path.exists() is False


def test_dashboard_windows_pid_probe_never_uses_os_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = MagicMock(return_value=True)
    monkeypatch.setattr(dashboard_update_module.os, "name", "nt")
    monkeypatch.setattr(dashboard_update_module, "windows_process_is_running", probe)
    monkeypatch.setattr(
        dashboard_update_module.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(AssertionError("Windows liveness probes must be non-destructive")),
    )

    assert dashboard_update_module._pid_is_running(5432) is True
    probe.assert_called_once_with(5432)


def test_runner_command_avoids_module_shadowing_from_cwd(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    command = build_dashboard_update_runner_command(
        guard_home.resolve(),
        daemon_pid=99,
        daemon_port=1234,
        update_token="a" * 64,
    )
    assert "-m" not in command
    assert "codex_plugin_scanner.guard.daemon.dashboard_update_runner" not in command
    runner_script = dashboard_update_runner_script()
    assert str(runner_script) in command
    assert runner_script.is_file()
    assert command[1:4] == ["-I", "-S", "-c"]
    assert "-P" not in command


def test_runner_env_ignores_inherited_pythonpath(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evil_root = tmp_path / "evil-repo" / "src"
    evil_root.mkdir(parents=True)
    monkeypatch.setenv("PYTHONPATH", str(evil_root))
    hostile_values = {
        "PYTHONHOME": str(evil_root),
        "PYTHONBREAKPOINT": "evil.module.hook",
        "PYTHONINSPECT": "1",
        "PYTHONIOENCODING": "utf-7",
        "PYTHONPLATLIBDIR": str(evil_root),
        "PYTHONSTARTUP": str(evil_root / "startup.py"),
        "PYTHONUSERBASE": str(evil_root / "user-site"),
        "PYTHONWARNINGS": "error",
        "PIP_CONFIG_FILE": str(evil_root / "pip.conf"),
        "PIP_CERT": str(evil_root / "certificate.pem"),
        "PIP_INDEX_URL": "https://evil.example/simple",
        "PIPX_HOME": str(evil_root / "pipx"),
        "PIPX_DEFAULT_PYTHON": str(evil_root / "python"),
        "UV_CONFIG_FILE": str(evil_root / "uv.toml"),
        "UV_INDEX_URL": "https://evil.example/simple",
        "UV_PROJECT": str(evil_root),
        "UV_PYTHON": str(evil_root / "python"),
        "VIRTUAL_ENV": str(evil_root / ".venv"),
        "CONDA_PREFIX": str(evil_root / "conda"),
        "CONDA_PYTHON_EXE": str(evil_root / "conda" / "python"),
        "LD_PRELOAD": str(evil_root / "inject.so"),
        "LD_LIBRARY_PATH": str(evil_root),
        "DYLD_INSERT_LIBRARIES": str(evil_root / "inject.dylib"),
        "DYLD_LIBRARY_PATH": str(evil_root),
        "HTTP_PROXY": "http://evil.example:8080",
        "HTTPS_PROXY": "http://evil.example:8080",
        "REQUESTS_CA_BUNDLE": str(evil_root / "certificate.pem"),
        "SSL_CERT_FILE": str(evil_root / "certificate.pem"),
    }
    for key, value in hostile_values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("UNRELATED_RUNNER_SECRET", "must-not-cross-boundary")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    popen_kwargs = build_dashboard_update_runner_popen_kwargs(tmp_path / "guard-home")
    env = popen_kwargs["env"]
    popen_kwargs["log_handle"].close()
    assert isinstance(env, dict)
    assert "PYTHONPATH" not in env
    assert not set(hostile_values).intersection(env)
    assert "UNRELATED_RUNNER_SECRET" not in env
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == str(tmp_path / "home")


def test_runner_log_is_private_and_truncated_for_each_attempt(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    log_path = guard_home / "dashboard-update.log"
    log_path.write_text("prior attempt output", encoding="utf-8")
    if os.name != "nt":
        log_path.chmod(0o666)

    popen_kwargs = build_dashboard_update_runner_popen_kwargs(guard_home)
    log_handle = popen_kwargs["log_handle"]
    try:
        assert log_path.read_text(encoding="utf-8") == ""
        if os.name != "nt":
            assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
        log_handle.write("current attempt")
        log_handle.flush()
    finally:
        log_handle.close()

    assert log_path.read_text(encoding="utf-8") == "current attempt"


def test_runner_bootstrap_ignores_project_import_hooks_and_uses_guard_owned_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_root = tmp_path / "trusted-root"
    trusted_package = trusted_root / "codex_plugin_scanner"
    runner_script = trusted_package / "guard" / "daemon" / "dashboard_update_runner.py"
    runner_script.parent.mkdir(parents=True)
    (trusted_package / "__init__.py").write_text("SOURCE = 'trusted'\n", encoding="utf-8")
    observed_path = tmp_path / "runner-observed.json"
    runner_script.write_text(
        "\n".join(
            [
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                "import codex_plugin_scanner",
                f"Path({str(observed_path)!r}).write_text(json.dumps({{",
                "    'cwd': os.getcwd(),",
                "    'source': codex_plugin_scanner.SOURCE,",
                "    'pythonpath': os.environ.get('PYTHONPATH'),",
                "    'pip_index': os.environ.get('PIP_INDEX_URL'),",
                "    'prefix': sys.prefix,",
                "    'exec_prefix': sys.exec_prefix,",
                "    'isolated': sys.flags.isolated,",
                "    'no_site': sys.flags.no_site,",
                "    'site_loaded': 'site' in sys.modules,",
                "    'sys_path': sys.path,",
                "}), encoding='utf-8')",
                "",
            ]
        ),
        encoding="utf-8",
    )

    evil_root = tmp_path / "project" / "python"
    evil_package = evil_root / "codex_plugin_scanner"
    evil_package.mkdir(parents=True)
    evil_import_marker = tmp_path / "evil-package-imported"
    evil_site_marker = tmp_path / "evil-sitecustomize-imported"
    (evil_package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(evil_import_marker)!r}).write_text('owned')\nSOURCE = 'evil'\n",
        encoding="utf-8",
    )
    (evil_root / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(evil_site_marker)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(evil_root))
    monkeypatch.setenv("PIP_INDEX_URL", "https://evil.example/simple")
    monkeypatch.setattr(dashboard_update_module, "dashboard_update_runner_script", lambda: runner_script)

    guard_home = tmp_path / "guard-home"
    command = build_dashboard_update_runner_command(
        guard_home,
        daemon_pid=42,
        daemon_port=4781,
        update_token="a" * 64,
    )
    popen_kwargs = build_dashboard_update_runner_popen_kwargs(guard_home)
    log_handle = popen_kwargs["log_handle"]
    try:
        result = subprocess.run(
            command,
            cwd=popen_kwargs["cwd"],
            env=popen_kwargs["env"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    finally:
        log_handle.close()

    assert result.returncode == 0, result.stderr
    assert evil_import_marker.exists() is False
    assert evil_site_marker.exists() is False
    observed = json.loads(observed_path.read_text(encoding="utf-8"))
    assert observed["cwd"] == str(guard_home.resolve())
    assert observed["source"] == "trusted"
    assert observed["pythonpath"] is None
    assert observed["pip_index"] is None
    assert observed["prefix"] == str(Path(sys.prefix).resolve())
    assert observed["exec_prefix"] == str(Path(sys.exec_prefix).resolve())
    assert observed["isolated"] == 1
    assert observed["no_site"] == 1
    assert observed["site_loaded"] is False
    assert str(trusted_root) in observed["sys_path"]
    assert str(evil_root) not in observed["sys_path"]
    assert "" not in observed["sys_path"]
    assert str(guard_home.resolve()) not in observed["sys_path"]


def test_real_runner_imports_with_no_site_and_explicit_trusted_paths(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    command = build_dashboard_update_runner_command(
        guard_home,
        daemon_pid=42,
        daemon_port=4781,
        update_token="a" * 64,
    )
    command.append("--help")
    popen_kwargs = build_dashboard_update_runner_popen_kwargs(guard_home)
    log_handle = popen_kwargs["log_handle"]
    try:
        result = subprocess.run(
            command,
            cwd=popen_kwargs["cwd"],
            env=popen_kwargs["env"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    finally:
        log_handle.close()

    assert result.returncode == 0, result.stderr
    assert "--update-token" in result.stdout


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


def test_merge_dashboard_update_progress_fail_closes_for_fresh_partial_lock(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    dashboard_update_module.dashboard_update_lock_path(guard_home).write_bytes(b"{")

    payload = merge_dashboard_update_progress(
        guard_home,
        {"current_version": "2.0.508", "update_available": True},
    )

    assert dashboard_update_module.dashboard_update_in_progress(guard_home) is True
    assert payload["update_in_progress"] is True
    assert "target_version" not in payload


def test_dashboard_update_runner_preserves_state_for_trusted_successful_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update_runner as runner_module

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state_text = json.dumps({"pid": 5150, "port": 5474, "guard_home": str(guard_home.resolve())})
    state_path = guard_home / "daemon-state.json"
    state_path.write_text(state_text, encoding="utf-8")
    update_token = "c" * 64
    calls: list[str] = []
    update_kwargs: dict[str, object] = {}

    monkeypatch.setattr(runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        runner_module,
        "claim_dashboard_update_lock",
        lambda _home, *, token: calls.append(f"claim:{token}") or True,
    )
    monkeypatch.setattr(
        runner_module,
        "retire_all_guard_daemons_for_home",
        lambda _home, **kwargs: calls.append("retire") or [],
    )
    monkeypatch.setattr(
        runner_module,
        "_retire_guard_daemon_pid",
        lambda pid, **kwargs: calls.append(f"retire_pid:{pid}") or True,
    )
    monkeypatch.setattr(runner_module, "guard_daemon_retirement_is_complete", lambda _home: True)

    def fake_run_guard_update(**kwargs: object) -> tuple[dict[str, object], int]:
        assert state_path.read_text(encoding="utf-8") == state_text
        calls.append("run_update")
        update_kwargs.update(kwargs)
        return {"status": "updated", "daemon_refresh": {"status": "restarted"}}, 0

    monkeypatch.setattr(runner_module.update_commands, "run_guard_update", fake_run_guard_update)
    isolated_refresh = MagicMock()
    legacy_restart = MagicMock()
    monkeypatch.setattr(runner_module.update_commands, "refresh_guard_daemon_after_update", isolated_refresh)
    monkeypatch.setattr(runner_module, "ensure_guard_daemon_after_update", legacy_restart)
    monkeypatch.setattr(
        runner_module,
        "clear_dashboard_update_lock",
        lambda _home, *, token: calls.append(f"clear_lock:{token}") or True,
    )

    exit_code = runner_module.main(
        [
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "5150",
            "--daemon-port",
            "5474",
            "--update-token",
            update_token,
        ]
    )

    assert exit_code == 0
    assert update_kwargs["guard_home"] == guard_home.resolve()
    runner_context = cast(HarnessContext, update_kwargs["context"])
    runner_store = cast(GuardStore, update_kwargs["store"])
    assert runner_context.guard_home == guard_home.resolve()
    assert runner_context.workspace_dir is None
    assert runner_store.guard_home == guard_home.resolve()
    assert isinstance(update_kwargs["now"], str)
    assert state_path.read_text(encoding="utf-8") == state_text
    isolated_refresh.assert_not_called()
    legacy_restart.assert_not_called()
    assert calls == [
        f"claim:{update_token}",
        "retire",
        "retire_pid:5150",
        "run_update",
        f"clear_lock:{update_token}",
    ]


def test_dashboard_update_runner_blocks_install_when_daemon_retirement_is_unproven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update_runner as runner_module

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    update_token = "9" * 64
    written_payload: dict[str, object] = {}
    run_update = MagicMock()
    isolated_refresh = MagicMock(return_value=({"status": "restarted"}, None))

    monkeypatch.setattr(runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runner_module, "claim_dashboard_update_lock", lambda _home, *, token: True)
    monkeypatch.setattr(runner_module, "retire_all_guard_daemons_for_home", lambda _home: [])
    monkeypatch.setattr(runner_module, "_retire_guard_daemon_pid", lambda _pid, **_kwargs: False)
    monkeypatch.setattr(runner_module, "guard_daemon_retirement_is_complete", lambda _home: False)
    monkeypatch.setattr(runner_module.update_commands, "run_guard_update", run_update)
    monkeypatch.setattr(runner_module.update_commands, "refresh_guard_daemon_after_update", isolated_refresh)
    monkeypatch.setattr(
        runner_module,
        "write_dashboard_update_outcome",
        lambda _home, payload: written_payload.update(payload),
    )
    monkeypatch.setattr(runner_module, "clear_dashboard_update_lock", MagicMock(return_value=True))

    exit_code = runner_module.main(
        [
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "5150",
            "--daemon-port",
            "5474",
            "--update-token",
            update_token,
        ]
    )

    assert exit_code == 1
    run_update.assert_not_called()
    isolated_refresh.assert_called_once()
    assert written_payload["status"] == "failed"
    assert "could not be retired safely" in str(written_payload["message"])


def test_dashboard_update_runner_exit_zero_requires_embedded_daemon_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update_runner as runner_module

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    update_token = "f" * 64
    written_payload: dict[str, object] = {}
    monkeypatch.setattr(runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runner_module, "claim_dashboard_update_lock", lambda _home, *, token: True)
    monkeypatch.setattr(runner_module, "retire_all_guard_daemons_for_home", lambda _home, **kwargs: [])
    monkeypatch.setattr(runner_module, "_retire_guard_daemon_pid", lambda pid, **kwargs: True)
    monkeypatch.setattr(runner_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(
        runner_module.update_commands,
        "run_guard_update",
        lambda **kwargs: ({"status": "skipped"}, 0),
    )
    isolated_refresh = MagicMock(return_value=({"status": "restarted"}, "restarted"))
    legacy_restart = MagicMock()
    monkeypatch.setattr(runner_module.update_commands, "refresh_guard_daemon_after_update", isolated_refresh)
    monkeypatch.setattr(runner_module, "ensure_guard_daemon_after_update", legacy_restart)
    monkeypatch.setattr(
        runner_module,
        "write_dashboard_update_outcome",
        lambda _home, payload: written_payload.update(payload),
    )
    monkeypatch.setattr(runner_module, "clear_dashboard_update_lock", MagicMock(return_value=True))

    exit_code = runner_module.main(
        [
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "5200",
            "--daemon-port",
            "5524",
            "--update-token",
            update_token,
        ]
    )

    assert exit_code == 1
    isolated_refresh.assert_called_once()
    legacy_restart.assert_not_called()
    assert written_payload["status"] == "failed"
    assert "fresh interpreter" in str(written_payload["message"])


def test_dashboard_update_runner_missing_embedded_restart_uses_legacy_only_after_isolated_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update_runner as runner_module

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    update_token = "1" * 64
    written_payload: dict[str, object] = {}
    monkeypatch.setattr(runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runner_module, "claim_dashboard_update_lock", lambda _home, *, token: True)
    monkeypatch.setattr(runner_module, "retire_all_guard_daemons_for_home", lambda _home, **kwargs: [])
    monkeypatch.setattr(runner_module, "_retire_guard_daemon_pid", lambda pid, **kwargs: True)
    monkeypatch.setattr(runner_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(
        runner_module.update_commands,
        "run_guard_update",
        lambda **kwargs: ({"status": "updated", "daemon_refresh": {"status": "not_running"}}, 0),
    )
    isolated_refresh = MagicMock(return_value=(None, "isolated refresh failed"))
    legacy_restart = MagicMock()
    monkeypatch.setattr(runner_module.update_commands, "refresh_guard_daemon_after_update", isolated_refresh)
    monkeypatch.setattr(runner_module, "ensure_guard_daemon_after_update", legacy_restart)
    monkeypatch.setattr(
        runner_module,
        "write_dashboard_update_outcome",
        lambda _home, payload: written_payload.update(payload),
    )
    monkeypatch.setattr(runner_module, "clear_dashboard_update_lock", MagicMock(return_value=True))

    exit_code = runner_module.main(
        [
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "5201",
            "--daemon-port",
            "5525",
            "--update-token",
            update_token,
        ]
    )

    assert exit_code == 1
    isolated_refresh.assert_called_once()
    legacy_restart.assert_called_once_with(
        guard_home,
        home_dir=Path.home().resolve(),
        preferred_port=5525,
    )
    assert written_payload["status"] == "failed"
    assert "fresh interpreter" in str(written_payload["message"])


@pytest.mark.parametrize(
    "failure_detail",
    [
        {"message": "Installer rejected https://token:super-secret@example.invalid/package.whl"},
        {"error": {"authorization": "Bearer super-secret"}},
    ],
)
def test_dashboard_update_runner_failure_stderr_never_renders_payload_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_detail: dict[str, object],
) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update_runner as runner_module

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    update_token = "d" * 64
    monkeypatch.setattr(runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runner_module, "claim_dashboard_update_lock", lambda _home, *, token: True)
    monkeypatch.setattr(runner_module, "retire_all_guard_daemons_for_home", lambda _home, **kwargs: [])
    monkeypatch.setattr(runner_module, "_retire_guard_daemon_pid", lambda pid, **kwargs: True)
    monkeypatch.setattr(runner_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(
        runner_module.update_commands,
        "run_guard_update",
        lambda **kwargs: ({"status": "failed", **failure_detail}, 1),
    )
    isolated_refresh = MagicMock(return_value=({"status": "restarted"}, "restarted"))
    legacy_restart = MagicMock()
    clear_lock = MagicMock(return_value=True)
    monkeypatch.setattr(runner_module.update_commands, "refresh_guard_daemon_after_update", isolated_refresh)
    monkeypatch.setattr(runner_module, "ensure_guard_daemon_after_update", legacy_restart)
    monkeypatch.setattr(runner_module, "clear_dashboard_update_lock", clear_lock)

    exit_code = runner_module.main(
        [
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "5250",
            "--daemon-port",
            "5574",
            "--update-token",
            update_token,
        ]
    )

    assert exit_code == 1
    isolated_refresh.assert_called_once()
    refresh_context = cast(HarnessContext, isolated_refresh.call_args.args[0])
    assert refresh_context.guard_home == guard_home.resolve()
    legacy_restart.assert_not_called()
    clear_lock.assert_called_once_with(guard_home.resolve(), token=update_token)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Guard update failed. Review the dashboard update status for details.\n"
    assert "super-secret" not in captured.err


def test_dashboard_update_runner_failure_uses_availability_fallback_only_after_isolated_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.daemon import dashboard_update_runner as runner_module

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    update_token = "e" * 64
    monkeypatch.setattr(runner_module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(runner_module, "claim_dashboard_update_lock", lambda _home, *, token: True)
    monkeypatch.setattr(runner_module, "retire_all_guard_daemons_for_home", lambda _home, **kwargs: [])
    monkeypatch.setattr(runner_module, "_retire_guard_daemon_pid", lambda pid, **kwargs: True)
    monkeypatch.setattr(runner_module, "guard_daemon_retirement_is_complete", lambda _home: True)
    monkeypatch.setattr(
        runner_module.update_commands,
        "run_guard_update",
        lambda **kwargs: ({"status": "failed", "message": "installer failed"}, 1),
    )
    isolated_refresh = MagicMock(return_value=(None, "isolated refresh failed"))
    legacy_restart = MagicMock(return_value="http://127.0.0.1:5674")
    monkeypatch.setattr(runner_module.update_commands, "refresh_guard_daemon_after_update", isolated_refresh)
    monkeypatch.setattr(runner_module, "ensure_guard_daemon_after_update", legacy_restart)
    monkeypatch.setattr(runner_module, "clear_dashboard_update_lock", MagicMock(return_value=True))

    exit_code = runner_module.main(
        [
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            "5350",
            "--daemon-port",
            "5674",
            "--update-token",
            update_token,
        ]
    )

    assert exit_code == 1
    isolated_refresh.assert_called_once()
    legacy_restart.assert_called_once_with(
        guard_home.resolve(),
        home_dir=Path.home().resolve(),
        preferred_port=5674,
    )


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
        lambda current_version, **_kwargs: {
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
    assert payload["recovery_reinstall_command"] == "hol-guard update --force-pypi-reinstall"


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
        lambda current_version, **_kwargs: {
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
        lambda: {
            "url": "file:///home/me/dist/hol_guard-1.0.0-py3-none-any.whl",
            "archive_info": {"hash": "sha256:abc"},
        },
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
        lambda current_version, **_kwargs: {
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


def test_status_payload_hides_auto_update_for_missing_local_wheel_install(
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
        lambda: {
            "url": "file:///home/me/dist/hol_guard-1.0.0-py3-none-any.whl",
            "archive_info": {"hash": "sha256:abc"},
        },
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
            "path_exists": False,
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_commands._version_check_payload",
        lambda current_version, **_kwargs: {
            "source": "pypi",
            "status": "stale",
            "current_version": current_version,
            "latest_version": "1.0.1",
            "update_available": True,
        },
    )

    payload = build_guard_update_status_payload()

    assert payload["auto_updatable"] is False
    assert payload["recovery_reinstall_available"] is True
    assert "source file is no longer available" in str(payload["blocked_reason"])


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
        update_token="a" * 64,
        force_pypi_reinstall=True,
    )
    assert "--force-pypi-reinstall" in command

    command_without = build_dashboard_update_runner_command(
        guard_home.resolve(),
        daemon_pid=99,
        daemon_port=1234,
        update_token="a" * 64,
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
