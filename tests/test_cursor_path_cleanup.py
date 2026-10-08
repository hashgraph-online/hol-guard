"""Focused coverage for deprecated project-local Cursor hook cleanup."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import cursor_path_cleanup


def test_prune_empty_project_cursor_dir_removes_empty_hook_and_cursor_dirs(tmp_path: Path) -> None:
    hooks_dir = tmp_path / ".cursor" / "hooks"
    hooks_dir.mkdir(parents=True)

    cursor_path_cleanup.prune_empty_project_cursor_dir(tmp_path)

    assert not hooks_dir.exists()
    assert not (tmp_path / ".cursor").exists()


def test_prune_empty_project_cursor_dir_preserves_nonempty_hook_dir(tmp_path: Path) -> None:
    hooks_dir = tmp_path / ".cursor" / "hooks"
    hooks_dir.mkdir(parents=True)
    marker = hooks_dir / "third-party-hook.py"
    marker.write_text("# owned by the project\n", encoding="utf-8")

    cursor_path_cleanup.prune_empty_project_cursor_dir(tmp_path)

    assert marker.is_file()
    assert hooks_dir.is_dir()


def test_prune_empty_project_cursor_dir_keeps_cursor_dir_with_other_entries(tmp_path: Path) -> None:
    hooks_dir = tmp_path / ".cursor" / "hooks"
    hooks_dir.mkdir(parents=True)
    settings = tmp_path / ".cursor" / "settings.json"
    settings.write_text("{}\n", encoding="utf-8")

    cursor_path_cleanup.prune_empty_project_cursor_dir(tmp_path)

    assert not hooks_dir.exists()
    assert settings.is_file()
    assert (tmp_path / ".cursor").is_dir()


def test_prune_empty_project_cursor_dir_returns_when_cursor_dir_is_missing(tmp_path: Path) -> None:
    cursor_path_cleanup.prune_empty_project_cursor_dir(tmp_path)

    assert not (tmp_path / ".cursor").exists()


def test_prune_empty_project_cursor_dir_handles_hook_listing_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hooks_dir = tmp_path / ".cursor" / "hooks"
    hooks_dir.mkdir(parents=True)
    path_type = type(hooks_dir)
    original_iterdir = path_type.iterdir

    def fail_hooks_listing(path: Path):
        if path == hooks_dir:
            raise OSError("hook directory unavailable")
        return original_iterdir(path)

    monkeypatch.setattr(path_type, "iterdir", fail_hooks_listing)

    cursor_path_cleanup.prune_empty_project_cursor_dir(tmp_path)

    assert hooks_dir.is_dir()


def test_prune_empty_project_cursor_dir_handles_cursor_listing_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hooks_dir = tmp_path / ".cursor" / "hooks"
    hooks_dir.mkdir(parents=True)
    cursor_dir = tmp_path / ".cursor"
    path_type = type(cursor_dir)
    original_iterdir = path_type.iterdir

    def fail_cursor_listing(path: Path):
        if path == cursor_dir:
            raise OSError("cursor directory unavailable")
        return original_iterdir(path)

    monkeypatch.setattr(path_type, "iterdir", fail_cursor_listing)

    cursor_path_cleanup.prune_empty_project_cursor_dir(tmp_path)

    assert not hooks_dir.exists()
    assert cursor_dir.is_dir()


def test_prune_empty_project_cursor_dir_handles_cursor_removal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hooks_dir = tmp_path / ".cursor" / "hooks"
    hooks_dir.mkdir(parents=True)
    cursor_dir = tmp_path / ".cursor"
    path_type = type(cursor_dir)
    original_rmdir = path_type.rmdir

    def fail_cursor_removal(path: Path) -> None:
        if path == cursor_dir:
            raise OSError("cursor directory changed")
        original_rmdir(path)

    monkeypatch.setattr(path_type, "rmdir", fail_cursor_removal)

    cursor_path_cleanup.prune_empty_project_cursor_dir(tmp_path)

    assert not hooks_dir.exists()
    assert cursor_dir.is_dir()
