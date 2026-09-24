"""Local project-folder picker for workspace audit."""

from __future__ import annotations

import subprocess
import threading
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.project_folder_picker import (
    ProjectFolderPickerBusyError,
    ProjectFolderPickerUnavailableError,
    choose_project_folder,
    interpret_project_folder_picker_result,
    project_folder_picker_command,
)
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request
from tests.test_guard_phase06_workspace_audit import _seed_premium_entitlement


def test_linux_folder_picker_prefers_zenity_then_kdialog() -> None:
    zenity = project_folder_picker_command("linux", which=lambda name: "/usr/bin/zenity" if name == "zenity" else None)
    assert zenity is not None
    assert zenity[0] == "/usr/bin/zenity"
    kdialog = project_folder_picker_command(
        "linux",
        which=lambda name: "/usr/bin/kdialog" if name == "kdialog" else None,
    )
    assert kdialog is not None
    assert kdialog[0] == "/usr/bin/kdialog"
    assert project_folder_picker_command("linux", which=lambda _name: None) is None


def test_folder_picker_reports_busy_and_missing_linux_dialog(monkeypatch: pytest.MonkeyPatch) -> None:
    def runner(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        with pytest.raises(ProjectFolderPickerBusyError):
            choose_project_folder(
                runner=lambda *_a, **_k: subprocess.CompletedProcess(args=["picker"], returncode=0, stdout="/workspace/other"),
                platform_name="darwin",
            )
        return subprocess.CompletedProcess(args=["picker"], returncode=0, stdout="/workspace/app\n", stderr="")

    assert choose_project_folder(runner=runner, platform_name="darwin") == "/workspace/app"
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.project_folder_picker.project_folder_picker_command",
        lambda *_args, **_kwargs: None,
    )
    with pytest.raises(ProjectFolderPickerUnavailableError):
        choose_project_folder(platform_name="linux")


def test_macos_folder_picker_uses_choose_folder() -> None:
    command = project_folder_picker_command("darwin")
    assert command is not None
    assert command[0] == "/usr/bin/osascript"
    assert "choose folder" in command[-1]


def test_folder_picker_cancel_returns_none() -> None:
    assert (
        interpret_project_folder_picker_result(
            returncode=1,
            stdout="",
            stderr="User canceled.",
        )
        is None
    )


def test_folder_picker_failure_is_unavailable() -> None:
    with pytest.raises(ProjectFolderPickerUnavailableError):
        interpret_project_folder_picker_result(
            returncode=1,
            stdout="",
            stderr="osascript is broken",
        )


def test_macos_cancel_code_returns_none() -> None:
    assert (
        interpret_project_folder_picker_result(
            returncode=1,
            stdout="",
            stderr="execution error: User canceled. (-128)",
        )
        is None
    )


@pytest.mark.parametrize("stderr", ["cannot open display", "Failed to open display"])
def test_linux_dialog_display_failure_is_unavailable(stderr: str) -> None:
    with pytest.raises(ProjectFolderPickerUnavailableError):
        interpret_project_folder_picker_result(
            returncode=1,
            stdout="",
            stderr=stderr,
            treat_exit_one_as_cancel=True,
        )


def test_linux_dialog_cancel_ignores_gtk_warnings() -> None:
    assert (
        interpret_project_folder_picker_result(
            returncode=1,
            stdout="",
            stderr="(zenity:1234): Gtk-WARNING **: 12:00:00.000: GtkDialog mapped without a transient parent",
            treat_exit_one_as_cancel=True,
        )
        is None
    )


def test_windows_picker_writes_utf8() -> None:
    command = project_folder_picker_command("win32")
    assert command is not None
    assert "OutputEncoding" in command[-1]
    assert "UTF8" in command[-1]


def test_missing_picker_executable_is_unavailable() -> None:
    def runner(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("powershell")

    with pytest.raises(ProjectFolderPickerUnavailableError):
        choose_project_folder(runner=runner, platform_name="win32")


def test_choose_project_folder_uses_injected_runner() -> None:
    def runner(*_args, **_kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=["picker"], returncode=0, stdout="/workspace/app\n", stderr="")

    assert choose_project_folder(runner=runner, platform_name="darwin") == "/workspace/app"


def test_daemon_choose_folder_returns_a_validated_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "project"
    selected.mkdir()
    monkeypatch.setattr(daemon_server, "choose_project_folder", lambda: str(selected))
    store_home = tmp_path / "guard-home"
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(store_home)
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/choose-folder",
                token=_dashboard_token_for(store),
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["cancelled"] is False
    assert payload["workspace_dir"] == str(selected.resolve())


def test_daemon_choose_folder_reports_cancel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "choose_project_folder", lambda: None)
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/choose-folder",
                token=_dashboard_token_for(store),
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["cancelled"] is True
    assert payload["workspace_dir"] is None


def test_daemon_answers_health_while_folder_picker_is_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    release = threading.Event()

    def blocked_picker() -> None:
        started.set()
        assert release.wait(timeout=5)

    monkeypatch.setattr(daemon_server, "choose_project_folder", blocked_picker)
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    result: dict[str, object] = {}

    def choose() -> None:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/choose-folder",
                token=_dashboard_token_for(store),
                payload={},
            ),
        )
        result["status"] = status
        result["payload"] = payload

    worker = threading.Thread(target=choose)
    worker.start()
    try:
        assert started.wait(timeout=5)
        with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=2) as response:
            assert response.status == 200
    finally:
        release.set()
        worker.join(timeout=5)
        daemon.stop()

    assert not worker.is_alive()
    assert result["status"] == 200
    assert result["payload"]["cancelled"] is True


@pytest.mark.parametrize(
    ("error", "status_code", "code"),
    [
        (daemon_server.ProjectFolderPickerBusyError(), 409, "folder_picker_busy"),
        (daemon_server.ProjectFolderPickerUnavailableError(), 503, "folder_picker_unavailable"),
    ],
)
def test_daemon_choose_folder_reports_picker_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    code: str,
) -> None:
    def raise_picker() -> str:
        raise error

    monkeypatch.setattr(daemon_server, "choose_project_folder", raise_picker)
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/choose-folder",
                token=_dashboard_token_for(store),
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == status_code
    assert payload["error"] == code


def test_daemon_choose_folder_rejects_an_unusable_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "choose_project_folder", lambda: "/definitely/not/a/project-folder")
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/choose-folder",
                token=_dashboard_token_for(store),
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "workspace_dir_invalid"
