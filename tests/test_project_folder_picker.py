"""Local project-folder picker for workspace audit."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.project_folder_picker import (
    ProjectFolderPickerUnavailableError,
    choose_project_folder,
    interpret_project_folder_picker_result,
    project_folder_picker_command,
)
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request
from tests.test_guard_phase06_workspace_audit import _seed_premium_entitlement


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
