"""Real-I/O race and compatibility controls for workspace config loading."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config


@pytest.mark.skipif(os.name != "posix", reason="Exercises POSIX directory-relative opens.")
@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
@pytest.mark.parametrize("boundary", ("file", "directory"))
def test_workspace_config_replacement_never_opens_outside_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str, boundary: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / filename).write_text('workspace_marker = "inside"\n', encoding="utf-8")
    outside_root = tmp_path / "outside-workspace"
    outside_root.mkdir()
    outside_target = outside_root / filename
    outside_target.write_text('workspace_marker = "outside"\n', encoding="utf-8")
    target = outside_target.stat()
    original_open = os.open
    replaced = False
    opened_target = False

    def replace_during_open(path: str | Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        nonlocal replaced, opened_target
        if boundary == "file" and not replaced and path == filename and dir_fd is not None:
            (workspace / filename).unlink()
            (workspace / filename).symlink_to(outside_target)
            replaced = True
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        actual = os.fstat(descriptor)
        if (actual.st_dev, actual.st_ino) == (target.st_dev, target.st_ino):
            opened_target = True
        if boundary == "directory" and not replaced and path == workspace and dir_fd is None:
            workspace.rename(tmp_path / "retired-workspace")
            workspace.symlink_to(outside_root, target_is_directory=True)
            replaced = True
        return descriptor

    with monkeypatch.context() as observation:
        observation.setattr(os, "open", replace_during_open)
        loaded = config._load_workspace_guard_config(workspace)

    assert replaced is True
    assert opened_target is False
    assert loaded == {}


@pytest.mark.skipif(os.name != "posix", reason="Verifies ordinary POSIX readable permissions.")
@pytest.mark.parametrize("filename", config.WORKSPACE_CONFIG_FILENAMES)
def test_workspace_config_accepts_readable_regular_file(tmp_path: Path, filename: str) -> None:
    candidate = tmp_path / filename
    candidate.write_text(
        'workspace_marker = "inside"\nmode = "observe"\nprotection_posture = "off"\n',
        encoding="utf-8",
    )
    candidate.chmod(0o644)

    assert config._load_workspace_guard_config(tmp_path) == {"workspace_marker": "inside"}


def test_explicit_home_config_keeps_existing_symlink_behavior(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    target = tmp_path / "selected-config.toml"
    target.write_text('default_action = "warn"\n', encoding="utf-8")
    (guard_home / "config.toml").symlink_to(target)

    assert config.load_guard_config(guard_home).default_action == "warn"


def test_workspace_config_keeps_existing_malformed_toml_error(tmp_path: Path) -> None:
    (tmp_path / config.WORKSPACE_CONFIG_FILENAMES[0]).write_text("broken = [\n", encoding="utf-8")

    with pytest.raises(config.tomllib.TOMLDecodeError):
        config._load_workspace_guard_config(tmp_path)
