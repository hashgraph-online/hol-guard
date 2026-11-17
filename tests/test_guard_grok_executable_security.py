from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext


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


def _refusal(context: HarnessContext) -> str:
    """The reason the native runtime gives for not launching Grok."""
    with pytest.raises(OSError) as refused:
        get_adapter("grok").launch_command(context, [])
    return str(refused.value)


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

    error = _refusal(context)

    assert "workspace" in error.lower()


def test_relative_path_entry_is_never_promoted_to_absolute(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path, workspace=False)
    _write_executable(tmp_path / "relative-bin" / "grok")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", "relative-bin")

    error = _refusal(context)

    assert "absolute" in error.lower() or "cwd" in error.lower()


def test_symlink_target_inside_workspace_is_rejected(tmp_path: Path) -> None:
    context = _context(tmp_path)
    assert context.workspace_dir is not None
    target = _write_executable(context.workspace_dir / "tools" / "grok")
    candidate = tmp_path / "trusted-bin" / "grok"
    candidate.parent.mkdir(parents=True)
    candidate.symlink_to(target)
    context = replace(context, executable_overrides={"grok": str(candidate)})

    error = _refusal(context)

    assert "workspace" in error.lower()


def test_missing_executable_has_actionable_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path, workspace=False)
    monkeypatch.setenv("PATH", "")

    error = _refusal(context)

    assert "not found" in error.lower()


def test_custom_path_root_requires_one_explicit_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path, workspace=False)
    candidate = _write_executable(tmp_path / "custom-tools" / "grok")
    monkeypatch.setenv("PATH", str(candidate.parent))

    error = _refusal(context)

    assert "--grok-executable" in error


def test_group_writable_executable_is_rejected(tmp_path: Path) -> None:
    candidate = _write_executable(tmp_path / "custom-tools" / "grok")
    candidate.chmod(0o775)
    context = _context(tmp_path, workspace=False, override=str(candidate))

    error = _refusal(context)

    assert "writable" in error.lower()


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

    environment = get_adapter("grok").prepare_launch_environment(context, inherited)

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

    detection = get_adapter("grok").detect(context)

    assert detection.installed is True
    assert detection.command_available is False
    assert str(config) in detection.config_paths
    assert any("workspace" in warning.lower() for warning in detection.warnings)
