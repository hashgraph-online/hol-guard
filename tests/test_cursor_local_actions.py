"""Cursor local setup, status, repair, and remove action tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.install_commands import (
    apply_managed_install,
    build_harness_setup_plan,
    build_harness_verification,
    cursor_local_action_payload,
)
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home.mkdir()
    workspace.mkdir()
    guard_home.mkdir()
    cursor_dir = workspace / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text('{"mcpServers":{}}', encoding="utf-8")
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_cursor_local_actions_preserve_editor_and_cli_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-05-29T12:00:00Z"

    connect = apply_managed_install("install", "cursor", False, context, store, str(context.workspace_dir), now)
    repair = build_harness_setup_plan("repair", "cursor", context, dry_run=True, surface="editor")
    status = build_harness_verification("cursor", context, store, surface="cli")
    remove = build_harness_setup_plan("uninstall", "cursor", context, dry_run=True, surface="editor")

    assert connect["cursor_action"]["surface_statuses"] == [
        {"surface": "editor", "status": "protected"},
        {"surface": "cli", "status": "not_detected"},
    ]
    assert repair["cursor_action"] == cursor_local_action_payload(
        action="repair",
        surface="editor",
        context=context,
        protected=False,
    )
    assert status["cursor_action"]["surface"] == "cli"
    assert status["cursor_action"]["sync"]["surface"] == "cli"
    assert status["cursor_action"]["evidence"]["surface"] == "cli"
    assert remove["cursor_action"]["action"] == "uninstall"
    assert remove["cursor_action"]["surface"] == "editor"


def test_cursor_local_actions_reject_unknown_surfaces(tmp_path: Path) -> None:
    context = _context(tmp_path)

    try:
        build_harness_setup_plan("repair", "cursor", context, dry_run=True, surface="browser")
    except ValueError as error:
        assert "Unsupported Cursor surface" in str(error)
    else:
        raise AssertionError("Expected unsupported Cursor surface to fail")
