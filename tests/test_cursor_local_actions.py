"""Cursor local setup, status, repair, and remove action tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.install_commands import (
    apply_managed_install,
    build_harness_setup_plan,
    build_harness_verification,
    cursor_local_action_payload,
)
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path, *, workspace_cursor: bool = True) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    home.mkdir()
    workspace.mkdir()
    guard_home.mkdir()
    if workspace_cursor:
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
        {"surface": "cli", "status": "protected"},
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


def test_cursor_install_all_reports_auto_detected_cursor_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.install_commands.detect_all",
        lambda _: [
            HarnessDetection(
                harness="cursor",
                installed=False,
                command_available=False,
                config_paths=(str(context.workspace_dir / ".cursor" / "mcp.json"),),
                artifacts=(),
            )
        ],
    )

    payload = apply_managed_install(
        "install",
        None,
        True,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-29T12:00:00Z",
    )

    assert payload["managed_install"]["harness"] == "cursor"
    assert payload["cursor_action"]["app_id"] == "cursor"
    assert payload["cursor_action"]["status"] == "protected"


def test_cursor_editor_detection_uses_global_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path, workspace_cursor=False)
    cursor_dir = context.home_dir / ".cursor"
    cursor_dir.mkdir()
    (cursor_dir / "mcp.json").write_text('{"mcpServers":{}}', encoding="utf-8")

    payload = cursor_local_action_payload(
        action="test",
        surface="editor",
        context=context,
        protected=False,
    )

    assert payload["surface_statuses"] == [
        {"surface": "editor", "status": "detected_unprotected"},
        {"surface": "cli", "status": "not_detected"},
    ]
    assert payload["evidence"]["redactedPath"] == "$HOME/.cursor/mcp.json"


def test_cursor_editor_install_wraps_workspace_config_and_remove_restores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config_path = context.workspace_dir / ".cursor" / "mcp.json"
    original_payload = {
        "mcpServers": {
            "filesystem": {
                "command": "node",
                "args": ["server.js"],
                "env": {"SAFE_FLAG": "1"},
            }
        }
    }
    config_path.write_text(json.dumps(original_payload, indent=2) + "\n", encoding="utf-8")

    install_payload = apply_managed_install(
        "install",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-29T12:00:00Z",
        surface="editor",
    )
    managed_install = install_payload["managed_install"]
    assert managed_install["surface"] == "editor"
    assert install_payload["cursor_action"]["surface"] == "editor"
    assert install_payload["cursor_action"]["status"] == "protected"

    protected_payload = json.loads(config_path.read_text(encoding="utf-8"))
    server = protected_payload["mcpServers"]["filesystem"]
    assert server["command"] == sys.executable
    assert "cursor-mcp-proxy" in server["args"]
    assert "--command" in server["args"]
    assert "node" in server["args"]
    assert "--arg=server.js" in server["args"]
    assert server["env"]["SAFE_FLAG"] == "1"

    remove_payload = apply_managed_install(
        "uninstall",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-29T12:01:00Z",
        surface="editor",
    )

    assert remove_payload["cursor_action"]["surface"] == "editor"
    assert json.loads(config_path.read_text(encoding="utf-8")) == original_payload


def test_cursor_cli_install_uses_cursor_agent_shim_without_editor_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path, workspace_cursor=False)
    store = GuardStore(context.guard_home)

    install_payload = apply_managed_install(
        "install",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-29T12:00:00Z",
        surface="cli",
    )

    managed_install = install_payload["managed_install"]
    assert managed_install["surface"] == "cli"
    assert managed_install["shim_command"] == "guard-cursor-agent"
    assert Path(managed_install["shim_path"]).exists()
    assert install_payload["cursor_action"]["surface"] == "cli"
    assert not (context.workspace_dir / ".cursor" / "mcp.json").exists()

    remove_payload = apply_managed_install(
        "uninstall",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-29T12:01:00Z",
        surface="cli",
    )

    assert remove_payload["managed_install"]["surface"] == "cli"
    assert not Path(managed_install["shim_path"]).exists()
