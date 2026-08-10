"""Frozen daemon process-inventory and runtime-identity coverage."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import frozen_daemon_runtime
from codex_plugin_scanner.guard.daemon import manager


def _daemon_command(executable: Path, guard_home: Path, home: Path, *, port: int = 4781) -> str:
    return (
        f"{executable} daemon --serve --guard-home {guard_home} "
        f"--home {home} --port {port}"
    )


def test_frozen_runtime_proves_same_executable_bootloader_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "Application Support" / "hol-guard"
    executable.parent.mkdir()
    executable.write_bytes(b"guard")
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    guard_home.mkdir(parents=True)
    command = _daemon_command(executable, guard_home, home)

    monkeypatch.setattr(frozen_daemon_runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(executable))
    monkeypatch.setattr(frozen_daemon_runtime.os, "getpid", lambda: 4243)
    monkeypatch.setattr(frozen_daemon_runtime.os, "getppid", lambda: 4242)
    monkeypatch.setattr(manager, "_guard_daemon_command_for_pid", lambda pid: command if pid == 4242 else None)

    assert frozen_daemon_runtime._trusted_frozen_bootloader_parent_pid(guard_home) == 4242


def test_frozen_runtime_rejects_different_parent_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "hol-guard"
    executable.write_bytes(b"guard")
    other_executable = tmp_path / "other-hol-guard"
    other_executable.write_bytes(b"other")
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    guard_home.mkdir(parents=True)
    command = _daemon_command(other_executable, guard_home, home)

    monkeypatch.setattr(frozen_daemon_runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(executable))
    monkeypatch.setattr(frozen_daemon_runtime.os, "getpid", lambda: 4243)
    monkeypatch.setattr(frozen_daemon_runtime.os, "getppid", lambda: 4242)
    monkeypatch.setattr(manager, "_guard_daemon_command_for_pid", lambda pid: command if pid == 4242 else None)

    assert frozen_daemon_runtime._trusted_frozen_bootloader_parent_pid(guard_home) is None


def test_frozen_inventory_filters_only_proven_bootloader_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / ".hol-guard"
    monkeypatch.setattr(
        frozen_daemon_runtime,
        "_trusted_frozen_bootloader_parent_pid",
        lambda _guard_home: 4242,
    )

    assert frozen_daemon_runtime._filter_frozen_bootloader_parent(
        guard_home,
        [(4242, 4781), (4243, 4781), (9000, 4782)],
    ) == [(4243, 4781), (9000, 4782)]


def test_frozen_runtime_source_root_uses_stable_executable_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "hol-guard"
    executable.write_bytes(b"signed-core")
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(executable))

    assert frozen_daemon_runtime._frozen_runtime_source_root() == str(executable.resolve())


def test_frozen_runtime_fingerprint_binds_exact_executable_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "hol-guard"
    payload = b"signed-core-bytes"
    executable.write_bytes(payload)
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(executable))
    monkeypatch.setattr(frozen_daemon_runtime, "_frozen_runtime_fingerprint_cache", None)

    assert frozen_daemon_runtime._frozen_runtime_fingerprint() == hashlib.sha256(payload).hexdigest()


def test_frozen_runtime_forces_fresh_pyinstaller_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = manager._guard_daemon_process_inventory_for_guard_home
    monkeypatch.setattr(frozen_daemon_runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(frozen_daemon_runtime, "_frozen_runtime_installed", False)
    monkeypatch.delenv("PYINSTALLER_RESET_ENVIRONMENT", raising=False)

    frozen_daemon_runtime.install_frozen_daemon_runtime()

    assert frozen_daemon_runtime.os.environ["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", inventory)


def test_non_frozen_runtime_does_not_patch_daemon_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = manager._guard_daemon_process_inventory_for_guard_home
    monkeypatch.setattr(frozen_daemon_runtime.sys, "frozen", False, raising=False)
    monkeypatch.delenv("PYINSTALLER_RESET_ENVIRONMENT", raising=False)

    frozen_daemon_runtime.install_frozen_daemon_runtime()

    assert manager._guard_daemon_process_inventory_for_guard_home is inventory
    assert "PYINSTALLER_RESET_ENVIRONMENT" not in frozen_daemon_runtime.os.environ
