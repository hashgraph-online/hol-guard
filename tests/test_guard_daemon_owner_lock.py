"""Cross-runtime daemon ownership coverage."""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import manager


@pytest.mark.skipif(os.name == "nt", reason="POSIX process inventory")
def test_procfs_process_inventory_entries_reach_the_ownership_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command_line = shlex.join(
        (
            "python",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "daemon",
            "--serve",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--port",
            "4781",
        )
    )
    monkeypatch.setattr(manager.posix_processes, "posix_process_inventory", lambda: [(4242, command_line)])

    assert manager._guard_daemon_process_inventory_for_guard_home(tmp_path / "guard-home") == [(4242, 4781)]


def test_daemon_owner_lock_rejects_second_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
    owner = manager.acquire_guard_daemon_owner_lock(guard_home)

    with pytest.raises(RuntimeError, match="already active"):
        manager.acquire_guard_daemon_owner_lock(guard_home)

    manager.release_guard_daemon_owner_lock(owner)
    replacement = manager.acquire_guard_daemon_owner_lock(guard_home)
    manager.release_guard_daemon_owner_lock(replacement)


def test_daemon_owner_lock_rejects_existing_same_home_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: [(4242, 5474)],
    )

    with pytest.raises(RuntimeError, match="already active"):
        manager.acquire_guard_daemon_owner_lock(tmp_path / "guard-home")


def test_daemon_owner_lock_ignores_windows_venv_launcher_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(manager, "_windows_venv_launcher_parent_pid", lambda: 4242)
    monkeypatch.setattr(
        manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: [(4242, 5474)],
    )

    owner = manager.acquire_guard_daemon_owner_lock(tmp_path / "guard-home")
    manager.release_guard_daemon_owner_lock(owner)


def test_daemon_owner_lock_still_rejects_a_competing_daemon_beside_the_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(manager, "_windows_venv_launcher_parent_pid", lambda: 4242)
    monkeypatch.setattr(
        manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _home: [(4242, 5474), (9999, 5474)],
    )

    with pytest.raises(RuntimeError, match="already active"):
        manager.acquire_guard_daemon_owner_lock(tmp_path / "guard-home")


def test_windows_venv_launcher_parent_matches_only_the_same_daemon_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_command = (
        '"C:\\Python\\python.exe" -c bootstrap '
        '"C:\\guard" "C:\\guard" [] '
        "codex_plugin_scanner.cli guard daemon --serve "
        "--guard-home C:\\guard-home --home C:\\guard --port 5474"
    )
    launcher_command = daemon_command.replace("C:\\Python\\python.exe", "C:\\venv\\Scripts\\python.exe")
    commands = {10: daemon_command, 20: launcher_command, 30: "hol-guard.exe command test"}
    monkeypatch.setattr(
        manager,
        "os",
        SimpleNamespace(name="nt", getpid=lambda: 10, getppid=lambda: 20),
    )
    monkeypatch.setattr(
        manager.windows_processes,
        "windows_process_command_line",
        lambda pid, **_kwargs: commands.get(pid),
    )
    monkeypatch.setattr(
        manager,
        "windows_command_line_to_argv",
        lambda command: [part.strip('"') for part in shlex.split(command, posix=False)],
    )

    assert manager._windows_venv_launcher_parent_pid() == 20

    monkeypatch.setattr(manager.os, "getppid", lambda: 30)
    assert manager._windows_venv_launcher_parent_pid() is None
