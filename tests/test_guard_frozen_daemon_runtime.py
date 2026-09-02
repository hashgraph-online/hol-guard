"""Frozen daemon process-inventory and runtime-identity coverage."""

from __future__ import annotations

import hashlib
import runpy
import sys
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard import frozen_daemon_runtime
from codex_plugin_scanner.guard.daemon import manager

ROOT = Path(__file__).resolve().parents[1]
FROZEN_ENTRYPOINT = ROOT / "scripts" / "mdm" / "hol-guard-entry.py"


def _daemon_command(executable: Path, guard_home: Path, home: Path, *, port: int = 4781) -> str:
    return f"{executable} daemon --serve --guard-home {guard_home} --home {home} --port {port}"


def test_frozen_entrypoint_dispatches_multiprocessing_before_guard_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    multiprocessing = ModuleType("multiprocessing")
    daemon_runtime = ModuleType("codex_plugin_scanner.guard.frozen_daemon_runtime")
    codex_runtime = ModuleType("codex_plugin_scanner.guard.frozen_codex_runtime")
    cli = ModuleType("codex_plugin_scanner.cli")

    multiprocessing.__dict__["freeze_support"] = lambda: events.append("freeze-support")
    daemon_runtime.__dict__["install_frozen_daemon_runtime"] = lambda: events.append("daemon-runtime")
    codex_runtime.__dict__["install_frozen_codex_runtime"] = lambda: events.append("codex-runtime")
    codex_runtime.__dict__["run_frozen_internal_command"] = lambda: events.append("private-command")
    cli.__dict__["main"] = lambda: events.append("public-cli") or 0
    monkeypatch.setitem(sys.modules, "multiprocessing", multiprocessing)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.guard.frozen_daemon_runtime", daemon_runtime)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.guard.frozen_codex_runtime", codex_runtime)
    monkeypatch.setitem(sys.modules, "codex_plugin_scanner.cli", cli)

    with pytest.raises(SystemExit) as exit_info:
        _ = runpy.run_path(str(FROZEN_ENTRYPOINT), run_name="__main__")

    assert exit_info.value.code == 0
    assert events == [
        "freeze-support",
        "daemon-runtime",
        "codex-runtime",
        "private-command",
        "public-cli",
    ]


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


def test_frozen_runtime_accepts_same_release_from_same_macos_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = tmp_path / "desktop-core"
    peer = tmp_path / "managed-core"
    current.write_bytes(b"desktop-wrapper")
    peer.write_bytes(b"managed-wrapper")
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(current))
    monkeypatch.setattr(frozen_daemon_runtime, "_cached_macos_signing_team", lambda _path: "TEAM123")
    monkeypatch.setattr(frozen_daemon_runtime, "_frozen_runtime_state_matcher", lambda _payload: False)

    assert frozen_daemon_runtime._frozen_runtime_state_matches(
        {
            "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": manager.__version__,
            "source_root": str(peer),
            "runtime_fingerprint": hashlib.sha256(peer.read_bytes()).hexdigest(),
        }
    )


def test_frozen_runtime_rejects_same_release_from_different_macos_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = tmp_path / "desktop-core"
    peer = tmp_path / "untrusted-core"
    current.write_bytes(b"desktop-wrapper")
    peer.write_bytes(b"different-wrapper")
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(current))
    monkeypatch.setattr(
        frozen_daemon_runtime,
        "_cached_macos_signing_team",
        lambda path: "TEAM123" if path == current else "OTHER456",
    )
    monkeypatch.setattr(frozen_daemon_runtime, "_frozen_runtime_state_matcher", lambda _payload: False)

    assert not frozen_daemon_runtime._frozen_runtime_state_matches(
        {
            "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": manager.__version__,
            "source_root": str(peer),
            "runtime_fingerprint": hashlib.sha256(peer.read_bytes()).hexdigest(),
        }
    )


def test_frozen_runtime_rejects_same_team_peer_with_mismatched_fingerprint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = tmp_path / "desktop-core"
    peer = tmp_path / "managed-core"
    current.write_bytes(b"desktop-wrapper")
    peer.write_bytes(b"managed-wrapper")
    monkeypatch.setattr(frozen_daemon_runtime.sys, "executable", str(current))
    monkeypatch.setattr(frozen_daemon_runtime, "_cached_macos_signing_team", lambda _path: "TEAM123")
    monkeypatch.setattr(frozen_daemon_runtime, "_frozen_runtime_state_matcher", lambda _payload: False)

    assert not frozen_daemon_runtime._frozen_runtime_state_matches(
        {
            "compatibility_version": manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": manager.__version__,
            "source_root": str(peer),
            "runtime_fingerprint": hashlib.sha256(b"other-bytes").hexdigest(),
        }
    )


def test_frozen_runtime_caches_verified_team_until_executable_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "managed-core"
    executable.write_bytes(b"first")
    calls: list[Path] = []

    def verify(path: Path, *, deep: bool = False) -> str:
        assert deep is True
        calls.append(path)
        return "TEAM123"

    frozen_daemon_runtime._signing_team_cache.clear()
    monkeypatch.setattr(frozen_daemon_runtime, "verified_macos_signing_team", verify)

    assert frozen_daemon_runtime._cached_macos_signing_team(executable) == "TEAM123"
    assert frozen_daemon_runtime._cached_macos_signing_team(executable) == "TEAM123"
    executable.write_bytes(b"second-version")
    assert frozen_daemon_runtime._cached_macos_signing_team(executable) == "TEAM123"
    assert calls == [executable, executable]


def test_frozen_runtime_consumes_pyinstaller_reset_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = manager._guard_daemon_process_inventory_for_guard_home
    source_root = manager._current_guard_daemon_source_root
    fingerprint = manager._current_guard_daemon_runtime_fingerprint
    state_matcher = manager._guard_daemon_state_matches_current_runtime
    monkeypatch.setattr(frozen_daemon_runtime.sys, "frozen", True, raising=False)
    monkeypatch.setattr(frozen_daemon_runtime, "_frozen_runtime_installed", False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "1")

    try:
        frozen_daemon_runtime.install_frozen_daemon_runtime()

        assert "PYINSTALLER_RESET_ENVIRONMENT" not in frozen_daemon_runtime.os.environ
    finally:
        manager._guard_daemon_process_inventory_for_guard_home = inventory
        manager._current_guard_daemon_source_root = source_root
        manager._current_guard_daemon_runtime_fingerprint = fingerprint
        manager._guard_daemon_state_matches_current_runtime = state_matcher


def test_frozen_daemon_launcher_preserves_pyinstaller_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(manager.sys, "frozen", True, raising=False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "untrusted-parent-value")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    child_env = manager._daemon_launcher_env(home_dir=tmp_path)

    assert child_env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert child_env["HOL_GUARD_DESKTOP"] == "1"


def test_frozen_daemon_launcher_preserves_persistent_desktop_runtime_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_owner = tmp_path / "desktop-core" / "bin" / "hol-guard"
    runtime_owner.parent.mkdir(parents=True)
    runtime_owner.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(manager.sys, "frozen", True, raising=False)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_RUNTIME_OWNER", str(runtime_owner))

    child_env = manager._daemon_launcher_env(home_dir=tmp_path)

    assert child_env["HOL_GUARD_DESKTOP_RUNTIME_OWNER"] == str(runtime_owner)


def test_non_frozen_daemon_launcher_drops_desktop_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(manager.sys, "frozen", False, raising=False)
    monkeypatch.setenv("PYINSTALLER_RESET_ENVIRONMENT", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    child_env = manager._daemon_launcher_env(home_dir=tmp_path)

    assert "PYINSTALLER_RESET_ENVIRONMENT" not in child_env
    assert "HOL_GUARD_DESKTOP" not in child_env


def test_non_frozen_runtime_does_not_patch_daemon_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    inventory = manager._guard_daemon_process_inventory_for_guard_home
    monkeypatch.setattr(frozen_daemon_runtime.sys, "frozen", False, raising=False)
    monkeypatch.delenv("PYINSTALLER_RESET_ENVIRONMENT", raising=False)

    frozen_daemon_runtime.install_frozen_daemon_runtime()

    assert manager._guard_daemon_process_inventory_for_guard_home is inventory
    assert "PYINSTALLER_RESET_ENVIRONMENT" not in frozen_daemon_runtime.os.environ
