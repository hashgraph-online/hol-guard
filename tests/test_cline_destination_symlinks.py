"""Cline destinations must reject links even when their targets do not exist."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_paths import ensure_safe_cline_destination


def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HarnessContext:
    monkeypatch.delenv("CLINE_DIR", raising=False)
    monkeypatch.delenv("CLINE_DATA_DIR", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home, None, home / ".hol-guard")


@pytest.mark.parametrize("existing_target", [False, True])
def test_rejects_leaf_symlink_without_following_target(tmp_path, monkeypatch, existing_target) -> None:
    context = _context(tmp_path, monkeypatch)
    target = tmp_path / "outside.txt"
    if existing_target:
        target.write_text("unchanged", encoding="utf-8")
    link = context.home_dir / "hook"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available")

    with pytest.raises(RuntimeError, match="symlink"):
        ensure_safe_cline_destination(context, link)

    assert link.is_symlink()
    if existing_target:
        assert target.read_text(encoding="utf-8") == "unchanged"
    else:
        assert not target.exists()


@pytest.mark.parametrize("existing_target", [False, True])
def test_rejects_symlink_ancestor_inside_home(tmp_path, monkeypatch, existing_target) -> None:
    context = _context(tmp_path, monkeypatch)
    target = context.home_dir / "alternate"
    if existing_target:
        target.mkdir()
    link = context.home_dir / "hooks"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not available")

    with pytest.raises(RuntimeError, match="symlink"):
        ensure_safe_cline_destination(context, link / "PreToolUse")

    assert not (target / "PreToolUse").exists()


def test_missing_regular_destination_is_allowed(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path, monkeypatch)
    destination = context.home_dir / ".cline" / "hooks" / "PreToolUse"

    ensure_safe_cline_destination(context, destination)

    assert not destination.exists()


def test_external_destination_is_rejected(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path, monkeypatch)

    with pytest.raises(RuntimeError, match="escapes"):
        ensure_safe_cline_destination(context, tmp_path / "outside" / "PreToolUse")
