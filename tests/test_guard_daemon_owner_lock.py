"""Cross-runtime daemon ownership coverage."""

from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager


def test_linux_process_inventory_uses_bounded_procfs_without_ps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc_root = tmp_path / "proc"
    daemon_process = proc_root / "4242"
    daemon_process.mkdir(parents=True)
    command_parts = (
        b"python",
        b"-m",
        b"codex_plugin_scanner.cli",
        b"guard",
        b"daemon",
        b"--serve",
        b"--guard-home",
        b"/guard-home",
        b"--port",
        b"4781",
    )
    (daemon_process / "cmdline").write_bytes(b"\0".join(command_parts) + b"\0")
    read_proc_entries = manager._linux_proc_process_entries
    monkeypatch.setattr(manager.sys, "platform", "linux")
    monkeypatch.setattr(manager, "_trusted_posix_ps_path", lambda: None)
    monkeypatch.setattr(
        manager,
        "_linux_proc_process_entries",
        lambda: read_proc_entries(proc_root),
    )

    assert manager._guard_daemon_process_inventory_for_guard_home(Path("/guard-home")) == [(4242, 4781)]


def test_linux_proc_process_inventory_fails_closed_when_budget_is_exceeded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proc_root = tmp_path / "proc"
    process_dir = proc_root / "4242"
    process_dir.mkdir(parents=True)
    (process_dir / "cmdline").write_bytes(b"x" * 17)
    monkeypatch.setattr(manager, "_GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES", 16)

    assert manager._linux_proc_process_entries(proc_root) is None


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
    monkeypatch.setattr(manager.os, "name", "nt")
    monkeypatch.setattr(manager.os, "getpid", lambda: 10)
    monkeypatch.setattr(manager.os, "getppid", lambda: 20)
    monkeypatch.setattr(
        manager.windows_processes,
        "windows_process_command_line",
        lambda pid, **_kwargs: commands.get(pid),
    )
    monkeypatch.setattr(
        manager,
        "_split_process_command",
        lambda command: shlex.split(command, posix=False),
    )

    assert manager._windows_venv_launcher_parent_pid() == 20

    monkeypatch.setattr(manager.os, "getppid", lambda: 30)
    assert manager._windows_venv_launcher_parent_pid() is None
