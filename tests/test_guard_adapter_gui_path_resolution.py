"""Command lookup when Guard runs with the bare PATH a GUI launcher provides."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import (
    _command_available,
    _resolve_command,
    _which_from_user_directories,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="launchd and desktop PATH defaults are POSIX-only")

LAUNCHD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def _install(directory: Path, name: str, *, mode: int = 0o755) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    executable = directory / name
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(mode)
    return executable


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    return home_dir


def test_launchd_path_finds_cli_in_user_install_directory(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".bun" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is True
    assert _which_from_user_directories("guardtestcli") == str(executable)


def test_launchd_path_never_changes_the_launch_executable(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install(home / ".bun" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _resolve_command("guardtestcli") is None


def test_lookup_uses_the_harness_home_not_the_process_home(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(home / ".bun" / "bin", "guardtestcli")
    other_home = tmp_path / "other-home"
    executable = _install(other_home / ".local" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _which_from_user_directories("guardtestcli", other_home) == str(executable)
    assert _command_available("guardtestcli", tmp_path / "empty-home") is False


def test_launchd_path_finds_cli_in_its_own_installer_directory(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".guardtestcli" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _which_from_user_directories("guardtestcli") == str(executable)


def test_launchd_path_prefers_newest_nvm_node(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    versions = home / ".nvm" / "versions" / "node"
    _install(versions / "v9.11.2" / "bin", "guardtestcli")
    newest = _install(versions / "v25.2.1" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _which_from_user_directories("guardtestcli") == str(newest)


def test_terminal_path_is_not_widened(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install(home / ".bun" / "bin", "guardtestcli")
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", f"{empty}{os.pathsep}{LAUNCHD_PATH}")

    assert _command_available("guardtestcli") is False


@pytest.mark.parametrize("path_value", ["", os.pathsep, os.pathsep * 3])
def test_empty_path_is_not_widened(home: Path, monkeypatch: pytest.MonkeyPatch, path_value: str) -> None:
    _install(home / ".bun" / "bin", "guardtestcli")
    monkeypatch.setenv("PATH", path_value)

    assert _which_from_user_directories("guardtestcli") is None


def test_writable_install_directory_is_ignored(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".bun" / "bin", "guardtestcli")
    executable.parent.chmod(executable.parent.stat().st_mode | stat.S_IWOTH)
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is False


def test_non_executable_file_is_ignored(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install(home / ".local" / "bin", "guardtestcli", mode=0o644)
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is False


def test_world_writable_entrypoint_in_private_directory_is_found(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _install(home / ".bun" / "bin", "guardtestcli", mode=0o777)
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _which_from_user_directories("guardtestcli") == str(executable)


def test_symlink_into_writable_directory_is_ignored(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _install(tmp_path / "shared", "guardtestcli")
    target.parent.chmod(0o777)
    link_directory = home / ".bun" / "bin"
    link_directory.mkdir(parents=True)
    (link_directory / "guardtestcli").symlink_to(target)
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is False


def test_symlink_loop_is_ignored(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = home / ".bun" / "bin"
    directory.mkdir(parents=True)
    (directory / "guardtestcli").symlink_to(directory / "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _command_available("guardtestcli") is False


def test_extra_directory_follows_the_same_rules(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installer_directory = home / ".guardtestcli-code" / "bin"
    executable = _install(installer_directory, "guardtestcli")
    monkeypatch.setenv("PATH", LAUNCHD_PATH)

    assert _which_from_user_directories("guardtestcli", home, (installer_directory,)) == str(executable)

    installer_directory.chmod(0o777)
    assert _command_available("guardtestcli", home, (installer_directory,)) is False


def test_extra_directory_is_searched_under_a_terminal_path(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install(home / ".bun" / "bin", "guardtestcli")
    installer_directory = home / ".guardtestcli-code" / "bin"
    executable = _install(installer_directory, "guardtestcli")
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", f"{empty}{os.pathsep}{LAUNCHD_PATH}")

    assert _which_from_user_directories("guardtestcli", home) is None
    assert _which_from_user_directories("guardtestcli", home, (installer_directory,)) == str(executable)
