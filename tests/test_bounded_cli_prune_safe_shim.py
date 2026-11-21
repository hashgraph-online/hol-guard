from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_harness_client import ask
from codex_plugin_scanner.guard.stable_guard_cli import prune_safe_cli_executable

from .native_bounded_runtime import durable_copy, use_bounded_runtime


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


def _grok_hook_argv(tmp_path: Path) -> tuple[str, ...]:
    """The bounded hook argv the native kind names for Grok in this process."""

    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    return tuple(str(part) for part in ask("hook_spec", context, harness="grok")["hook_argv"])


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
    runtime = tmp_path / "bundle" / "hol-guard-runtime"
    digest = use_bounded_runtime(monkeypatch, runtime)
    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr("sys.executable", str(versioned))
    command = _grok_hook_argv(tmp_path)
    assert command[:2] == (str(durable_copy(tmp_path / "guard-home", runtime, digest)), "bounded-hook-bridge")
    config = json.loads(command[2])
    assert config["python_executable"] == str(shim)
    assert config["frozen_launcher"] is True


def test_unfrozen_bounded_hook_command_names_the_native_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    use_bounded_runtime(monkeypatch, runtime)
    versioned, shim = _versioned_core(tmp_path)
    monkeypatch.setattr("sys.frozen", False, raising=False)
    monkeypatch.setattr("sys.executable", str(versioned))
    command = _grok_hook_argv(tmp_path)
    assert command[:2] == (str(runtime), "bounded-hook-bridge")
    assert len(command) == 3
    # Only a frozen Guard swaps its versioned path for the stable shim.
    assert json.loads(command[2])["python_executable"] == str(versioned)
    assert str(shim) not in command[2]


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
