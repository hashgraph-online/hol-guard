"""Cursor completion gates for local setup, proof, and public guidance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.cli.install_commands import (
    apply_managed_install,
    build_harness_verification,
)
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.store import GuardStore

REPO_ROOT = Path(__file__).resolve().parent.parent


def _context(tmp_path: Path, *, workspace_cursor: bool = False) -> HarnessContext:
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


def test_cursor_completion_gate_reports_missing_cursor_without_fake_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path)
    payload = build_harness_verification("cursor", context, GuardStore(context.guard_home), surface="editor")

    assert payload["verification"]["installed"] is False
    assert payload["cursor_action"]["status"] == "not_detected"
    assert payload["cursor_action"]["surface_statuses"] == [
        {"surface": "editor", "status": "not_detected"},
        {"surface": "cli", "status": "not_detected"},
    ]


def test_cursor_completion_gate_detects_broken_editor_hook_as_unprotected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path, workspace_cursor=True)
    config_path = context.workspace_dir / ".cursor" / "mcp.json"
    config_path.write_text(
        json.dumps({"mcpServers": {"filesystem": {"command": "node", "args": ["server.js"]}}}),
        encoding="utf-8",
    )

    payload = build_harness_verification("cursor", context, GuardStore(context.guard_home), surface="editor")

    assert payload["verification"]["installed"] is False
    assert payload["cursor_action"]["status"] == "detected_unprotected"
    assert payload["cursor_action"]["evidence"]["redactedPath"] == "$WORKSPACE/.cursor/mcp.json"


def test_cursor_completion_gate_receipts_preserve_stale_sync_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    context = _context(tmp_path, workspace_cursor=True)
    store = GuardStore(context.guard_home)
    install_payload = apply_managed_install(
        "install",
        "cursor",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-30T10:00:00Z",
        surface="editor",
    )
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = type("Server", (), {"store": store})()

    summary = _GuardDaemonHandler._record_headless_receipt(
        handler,
        harness="cursor",
        operation="status",
        payload={"surface": "editor", "workspace_id": "workspace-1"},
        result={"cursor_action": install_payload["cursor_action"]},
        workspace_id="workspace-1",
        cloud_sync={"status": "stale", "last_synced_at": "2026-05-29T10:00:00Z"},
    )

    receipt = store.get_receipt(str(summary["id"]))
    assert receipt is not None
    assert summary["cloud_sync"]["status"] == "stale"
    assert receipt["scanner_evidence"][0]["cloud_sync_status"] == "stale"
    assert receipt["scanner_evidence"][0]["workspace_id"] == "workspace-1"


def test_cursor_completion_gate_rejects_unsupported_surface_without_noop_repair(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = type("Server", (), {"store": store})()

    status, payload = _GuardDaemonHandler._headless_app_action_payload(
        handler,
        action_path="repair",
        payload={"harness": "cursor", "surface": "android"},
    )

    assert status == 400
    assert payload["error"]["code"] == "invalid_cursor_surface"
    assert payload["error"]["surface"] == "android"
    assert payload["error"]["app_id"] == "cursor"


def test_cursor_public_skill_guidance_names_editor_and_cli_without_fake_commands() -> None:
    text = (REPO_ROOT / "docs/guard/SKILL.md").read_text(encoding="utf-8")

    assert "Cursor editor" in text
    assert "Cursor CLI" in text
    assert "hol-guard apps connect cursor --surface editor" in text
    assert "hol-guard apps connect cursor --surface cli" in text
    assert "hol-guard apps test cursor --surface editor" in text
    assert "hol-guard apps test cursor --surface cli" in text
    assert "get.holguard.dev" not in text
    assert "curl -fsSL" not in text


def test_cursor_contract_documents_unsupported_state() -> None:
    text = (REPO_ROOT / "docs/guard/cursor-local-cloud-contract.md").read_text(encoding="utf-8")

    assert "unavailable" in text
    assert "unsupported" in text
    assert "must not offer a no-op repair" in text
    assert CursorHarnessAdapter.harness == "cursor"
