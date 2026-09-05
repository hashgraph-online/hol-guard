"""Focused permission and identity checks for installed Cursor hooks."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters import cursor_hook_config


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission semantics are required")
def test_make_executable_adds_only_owner_execute_permission(tmp_path: Path) -> None:
    script = tmp_path / "hol-guard-cursor-hook.py"
    script.write_text("pass\n", encoding="utf-8")
    script.chmod(0o600)

    cursor_hook_config._make_executable(script)

    assert stat.S_IMODE(script.stat().st_mode) == 0o700


def test_make_executable_skips_permission_update_on_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "hol-guard-cursor-hook.py"
    script.write_text("pass\n", encoding="utf-8")
    script.chmod(0o600)
    monkeypatch.setattr(cursor_hook_config.os, "name", "nt")

    cursor_hook_config._make_executable(script)

    assert stat.S_IMODE(script.stat().st_mode) == 0o600


def test_make_executable_rejects_non_regular_paths(tmp_path: Path) -> None:
    directory = tmp_path / "hooks"
    directory.mkdir()

    with pytest.raises(OSError, match="non-regular"):
        cursor_hook_config._make_executable(directory)


@pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor identity semantics are required")
def test_make_executable_rejects_replaced_path_before_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "hol-guard-cursor-hook.py"
    script.write_text("pass\n", encoding="utf-8")
    script.chmod(0o600)
    before = script.lstat()
    monkeypatch.setattr(
        cursor_hook_config.os,
        "fstat",
        lambda _descriptor: SimpleNamespace(st_dev=before.st_dev + 1, st_ino=before.st_ino),
    )

    with pytest.raises(OSError, match="changed before"):
        cursor_hook_config._make_executable(script)

    assert stat.S_IMODE(script.stat().st_mode) == 0o600
