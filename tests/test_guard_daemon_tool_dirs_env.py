"""The daemon asks the shim resident to look past its launcher's PATH for package managers."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager
from codex_plugin_scanner.guard.native_shim_admin import _facts

_MARKER = "HOL_GUARD_SHIM_TOOL_DIRS"


@pytest.mark.parametrize("frozen", [False, True])
def test_daemon_launch_environment_turns_tool_directory_discovery_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, frozen: bool
) -> None:
    monkeypatch.setattr(manager.sys, "frozen", frozen, raising=False)
    monkeypatch.delenv(_MARKER, raising=False)

    child_env = manager._daemon_launcher_env(home_dir=tmp_path)

    assert child_env[_MARKER] == "1"


def test_a_launching_shell_cannot_turn_discovery_off_for_the_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_MARKER, "0")

    assert manager._daemon_launcher_env(home_dir=tmp_path)[_MARKER] == "1"


def test_the_marker_reaches_the_shim_resident_without_a_full_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_MARKER, "1")
    monkeypatch.setenv("SECRET_TOKEN", "not-forwarded")

    environ = _facts(full_environment=False, shim_dir=tmp_path)["environ"]

    assert isinstance(environ, dict)
    assert environ[_MARKER] == "1"
    assert "SECRET_TOKEN" not in environ


def test_an_ordinary_process_does_not_send_the_marker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_MARKER, raising=False)

    environ = _facts(full_environment=False, shim_dir=tmp_path)["environ"]

    assert isinstance(environ, dict)
    assert _MARKER not in environ
