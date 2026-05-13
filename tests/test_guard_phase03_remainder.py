"""Remaining Phase 03 Guard local install, update, and connect contracts."""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.connect_flow import build_guard_connect_browser_url, run_guard_connect_command
from codex_plugin_scanner.guard.cli.install_commands import apply_managed_install, list_harness_setup_items
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir(parents=True, exist_ok=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_update_detects_uv_tool_install_and_plans_uv_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/Users/test/.local/share/uv/tools/hol-guard")
    monkeypatch.setattr(update_commands.shutil, "which", lambda name: f"/Users/test/.local/bin/{name}")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["installer"] == "uv"
    assert payload["command"] == ["uv", "tool", "upgrade", "hol-guard"]
    assert payload["retry_command"] == "uv tool upgrade hol-guard"
    assert payload["binary_diagnostics"]["path_status"] == "uv_tool_shim_detected"


def test_update_version_check_marks_stale_local_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/opt/guard-venv")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard-venv/bin/python")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.10")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["version_check"] == {
        "source": "pypi",
        "status": "stale",
        "current_version": "2.0.0",
        "latest_version": "2.0.10",
        "update_available": True,
    }


def test_update_version_check_treats_stable_release_newer_than_prerelease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/opt/guard-venv")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard-venv/bin/python")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0rc1")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.0.0")

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["version_check"] == {
        "source": "pypi",
        "status": "stale",
        "current_version": "2.0.0rc1",
        "latest_version": "2.0.0",
        "update_available": True,
    }


def test_update_version_check_handles_latest_lookup_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_commands.sys, "prefix", "/opt/guard-venv")
    monkeypatch.setattr(update_commands.sys, "executable", "/opt/guard-venv/bin/python")
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.0.0")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: None)

    payload, exit_code = update_commands.run_guard_update(dry_run=True)

    assert exit_code == 0
    assert payload["version_check"] == {
        "source": "pypi",
        "status": "unavailable",
        "current_version": "2.0.0",
        "latest_version": None,
        "update_available": None,
    }


def test_install_setup_listing_detects_safe_config_without_mutating_it(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_text = json.dumps({"mcpServers": {"local": {"command": "node"}}})
    config_path.write_text(config_text, encoding="utf-8")
    before_mtime = config_path.stat().st_mtime_ns

    items = list_harness_setup_items(context, store)

    cursor_item = next(item for item in items if item["harness"] == "cursor")
    assert cursor_item["status"] == "found"
    assert cursor_item["installed"] is False
    assert cursor_item["config_paths"] == [str(config_path)]
    assert config_path.read_text(encoding="utf-8") == config_text
    assert config_path.stat().st_mtime_ns == before_mtime


def test_doctor_reports_partial_setup_for_found_unprotected_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"mcpServers": {"local": {"command": "node"}}}), encoding="utf-8")
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: False)

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "partial"
    assert payload["command_available"] is False
    assert payload["config_paths"] == [str(config_path)]
    assert any("config was found" in warning for warning in payload["warnings"])


def test_doctor_does_not_mark_harness_command_presence_as_guard_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".cursor" / "mcp.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps({"mcpServers": {"local": {"command": "node"}}}), encoding="utf-8")
    monkeypatch.setattr("codex_plugin_scanner.guard.adapters.cursor._command_available", lambda command: True)

    from codex_plugin_scanner.guard.adapters import get_adapter

    payload = get_adapter("cursor").diagnostics(context)

    assert payload["setup_status"] == "partial"
    assert payload["installed"] is True
    assert payload["command_available"] is True
    assert any("Guard is not installed" in warning for warning in payload["warnings"])


def test_install_native_contract_output_prefers_native_hooks_for_supported_harnesses(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)

    payload = apply_managed_install(
        "install",
        "codex",
        False,
        context,
        store,
        str(context.workspace_dir),
        "2026-05-13T00:00:00Z",
    )

    managed_install = payload["managed_install"]
    assert managed_install["harness"] == "codex"
    assert managed_install["active"] is True
    assert managed_install["mode"] == "codex-mcp-proxy"
    assert managed_install["native_hooks"] is True
    assert managed_install["primary_integration"] == "native_hooks"
    assert managed_install["manifest"]["mode"] == "codex-mcp-proxy"


def test_connect_rejects_invalid_url_before_daemon_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon_calls: list[Path] = []

    def ensure_daemon(guard_home: Path) -> str:
        daemon_calls.append(guard_home)
        raise AssertionError("daemon must not start for invalid connect URL")

    monkeypatch.setattr("codex_plugin_scanner.guard.cli.connect_flow.ensure_guard_daemon", ensure_daemon)

    with pytest.raises(ValueError, match="absolute http"):
        run_guard_connect_command(
            guard_home=tmp_path / "guard-home",
            store=store,
            sync_url="https://hol.org/api/guard/receipts/sync",
            connect_url="not-a-url",
            opener=lambda url: True,
            wait_timeout_seconds=1,
        )

    assert daemon_calls == []


def test_connect_browser_url_keeps_pairing_secret_in_fragment_only() -> None:
    browser_url = build_guard_connect_browser_url(
        connect_url="https://hol.org/guard/connect?source=cli",
        daemon_url="http://127.0.0.1:4781",
        request_id="connect-123",
        pairing_secret="pairing-secret",
    )

    parsed = urllib.parse.urlparse(browser_url)
    query = urllib.parse.parse_qs(parsed.query)
    fragment = urllib.parse.parse_qs(parsed.fragment)

    assert query["source"] == ["cli"]
    assert query["guardPairRequest"] == ["connect-123"]
    assert query["guardDaemon"] == ["http://127.0.0.1:4781"]
    assert "pairing-secret" not in parsed.query
    assert fragment["guardPairSecret"] == ["pairing-secret"]
