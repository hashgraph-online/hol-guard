from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge
from codex_plugin_scanner.guard.stable_guard_cli import prune_safe_cli_executable


def _versioned_core(tmp_path: Path) -> tuple[Path, Path]:
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.86" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("binary", encoding="utf-8")
    versioned.chmod(0o755)
    shim = core_dir / "current-hol-guard"
    shim.write_text("#!/bin/sh\n", encoding="utf-8")
    shim.chmod(0o755)
    return versioned, shim


def test_prune_safe_cli_executable_rewrites_versioned_desktop_core(tmp_path: Path) -> None:
    versioned, shim = _versioned_core(tmp_path)
    assert prune_safe_cli_executable(str(versioned)) == str(shim)


def test_prune_safe_cli_executable_keeps_non_desktop_cli(tmp_path: Path) -> None:
    launcher = tmp_path / "hol-guard"
    launcher.write_text("binary", encoding="utf-8")
    launcher.chmod(0o755)
    assert prune_safe_cli_executable(str(launcher)) == str(launcher)


def test_frozen_bounded_hook_command_bakes_current_hol_guard_shim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    versioned, shim = _versioned_core(tmp_path)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_trusted_desktop_hook_proxy_command",
        lambda executable, config: None,
    )
    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable=str(versioned),
        package_root=tmp_path,
        guard_home=tmp_path / "guard-home",
        cli_args=(
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ),
        harness="grok",
        timeout_seconds=25,
    )
    assert command[0] == str(shim)
    assert command[1] == "__guard-bounded-hook"
    config = json.loads(command[2])
    assert config["python_executable"] == str(shim)
    assert config["frozen_launcher"] is True


def test_unfrozen_bounded_hook_command_keeps_python_interpreter(
    tmp_path: Path,
) -> None:
    versioned, shim = _versioned_core(tmp_path)
    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable=str(versioned),
        package_root=tmp_path,
        guard_home=tmp_path / "guard-home",
        cli_args=(
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ),
        harness="grok",
        timeout_seconds=25,
    )
    assert command[0] == str(versioned)
    assert command[1] == "-I"
    assert command[2] == "-c"
    config = json.loads(command[4])
    assert config["python_executable"] == str(versioned)
    assert config["frozen_launcher"] is False
    assert str(shim) not in command


def test_prune_safe_cli_executable_ignores_unix_shim_on_windows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.sys.platform",
        "win32",
    )
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.86" / "hol-guard.exe"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("binary", encoding="utf-8")
    unix_shim = core_dir / "current-hol-guard"
    unix_shim.write_text("#!/bin/sh\n", encoding="utf-8")
    unix_shim.chmod(0o755)
    assert prune_safe_cli_executable(str(versioned)) == str(versioned)


def test_prune_safe_cli_executable_prefers_windows_cmd_shim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.sys.platform",
        "win32",
    )
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.86" / "hol-guard.exe"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("binary", encoding="utf-8")
    unix_shim = core_dir / "current-hol-guard"
    unix_shim.write_text("#!/bin/sh\n", encoding="utf-8")
    unix_shim.chmod(0o755)
    cmd_shim = core_dir / "current-hol-guard.cmd"
    cmd_shim.write_text("@echo off\n", encoding="utf-8")
    cmd_shim.chmod(0o755)
    assert prune_safe_cli_executable(str(versioned)) == str(cmd_shim)
