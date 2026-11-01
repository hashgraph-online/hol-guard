from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.grok_executable import (
    grok_executable_names,
    resolve_trusted_grok_executable,
    sanitized_grok_launch_environment,
)

from .grok_native_fake import install_grok_native_fake


def _context(tmp_path: Path, *, workspace: bool = True, override: str | None = None) -> HarnessContext:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    workspace_dir = tmp_path / "workspace" if workspace else None
    home.mkdir(parents=True, exist_ok=True)
    guard_home.mkdir(parents=True, exist_ok=True)
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    overrides = {"grok": override} if override is not None else {}
    return HarnessContext(
        home_dir=home,
        workspace_dir=workspace_dir,
        guard_home=guard_home,
        executable_overrides=overrides,
    )


def _write_executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_workspace_path_collision_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    candidate = _write_executable(context.workspace_dir / "bin" / "grok")
    monkeypatch.setenv("PATH", str(candidate.parent))

    resolution = resolve_trusted_grok_executable(context)

    assert resolution.executable is None
    assert resolution.error is not None
    assert "workspace" in resolution.error.lower()


def test_relative_path_entry_is_never_promoted_to_absolute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path, workspace=False)
    _write_executable(tmp_path / "relative-bin" / "grok")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", "relative-bin")

    resolution = resolve_trusted_grok_executable(context)

    assert resolution.executable is None
    assert resolution.error is not None
    assert "absolute" in resolution.error.lower() or "cwd" in resolution.error.lower()


def test_symlink_target_inside_workspace_is_rejected(tmp_path: Path) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    target = _write_executable(context.workspace_dir / "tools" / "grok")
    candidate = tmp_path / "trusted-bin" / "grok"
    candidate.parent.mkdir(parents=True)
    candidate.symlink_to(target)
    context = replace(context, executable_overrides={"grok": str(candidate)})

    resolution = resolve_trusted_grok_executable(context)

    assert resolution.executable is None
    assert resolution.error is not None
    assert "workspace" in resolution.error.lower()


def test_missing_executable_has_actionable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path, workspace=False)
    monkeypatch.setenv("PATH", "")

    resolution = resolve_trusted_grok_executable(context)

    assert resolution.executable is None
    assert resolution.error is not None
    assert "not found" in resolution.error.lower()


def test_custom_path_root_requires_one_explicit_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path, workspace=False)
    candidate = _write_executable(tmp_path / "custom-tools" / "grok")
    monkeypatch.setenv("PATH", str(candidate.parent))

    resolution = resolve_trusted_grok_executable(context)

    assert resolution.executable is None
    assert resolution.error is not None
    assert "--grok-executable" in resolution.error


def test_group_writable_executable_is_rejected(tmp_path: Path) -> None:
    candidate = _write_executable(tmp_path / "custom-tools" / "grok")
    candidate.chmod(0o775)
    context = _context(tmp_path, workspace=False, override=str(candidate))

    resolution = resolve_trusted_grok_executable(context)

    assert resolution.executable is None
    assert resolution.error is not None
    assert "writable" in resolution.error.lower()


def test_windows_command_extensions_are_explicitly_supported() -> None:
    assert grok_executable_names(windows=True) == ("grok.exe", "grok.cmd", "grok.bat", "grok.com")
    assert grok_executable_names(windows=False) == ("grok",)


def test_launch_environment_removes_code_loader_variables_and_workspace_path(
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    workspace_bin = context.workspace_dir / "bin"
    workspace_bin.mkdir()
    inherited = {
        "PATH": os.pathsep.join((str(workspace_bin), "/usr/bin")),
        "HOME": str(context.home_dir),
        "GROK_HOME": str(context.workspace_dir / ".grok"),
        "NODE_OPTIONS": "--require=workspace-loader",
        "PYTHONPATH": str(context.workspace_dir),
        "SAFE_SETTING": "preserved",
    }

    environment = sanitized_grok_launch_environment(context, inherited)

    assert str(workspace_bin) not in environment["PATH"]
    assert "NODE_OPTIONS" not in environment
    assert "PYTHONPATH" not in environment
    assert "GROK_HOME" not in environment
    assert environment["SAFE_SETTING"] == "preserved"


def test_detect_reports_config_but_never_probes_untrusted_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    config = context.home_dir / ".grok" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[permission]\nallow = ["Read"]\n', encoding="utf-8")
    candidate = _write_executable(context.workspace_dir / "bin" / "grok")
    monkeypatch.setenv("PATH", str(candidate.parent))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.grok._run_command_probe",
        lambda *_args, **_kwargs: pytest.fail("untrusted executable must not be probed"),
    )

    detection = GrokHarnessAdapter().detect(context)

    assert detection.installed is True
    assert detection.command_available is False
    assert str(config) in detection.config_paths
    assert any("workspace" in warning.lower() for warning in detection.warnings)


def test_launch_uses_absolute_registered_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    custom = _write_executable(tmp_path / "custom-tools" / "grok")
    context = _context(tmp_path, workspace=False, override=str(custom))
    install_grok_native_fake(monkeypatch)

    command = GrokHarnessAdapter().launch_command(context, ["--help"])

    assert command == [str(custom.resolve()), "--help"]
    registration = context.guard_home / "managed" / "grok" / "trusted-executable.json"
    assert registration.is_file()
