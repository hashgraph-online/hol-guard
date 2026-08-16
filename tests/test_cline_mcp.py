from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cline_mcp import (
    detect_cline_mcp,
    install_cline_mcp_proxies,
    restore_cline_mcp_proxies,
)


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    workspace = home / "workspace"
    guard_home = home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_cline_mcp_proxy_install_preserves_remote_and_restores_exact_text(tmp_path: Path) -> None:
    context = _context(tmp_path)
    settings = context.home_dir / ".cline" / "data" / "settings" / "cline_mcp_settings.json"
    settings.parent.mkdir(parents=True)
    original = {
        "mcpServers": {
            "local": {"command": "node", "args": ["server.js"], "env": {"TOKEN": "secret"}},
            "remote": {"url": "https://example.invalid/mcp"},
        }
    }
    original_text = json.dumps(original, indent=2) + "\n"
    settings.write_text(original_text, encoding="utf-8")

    detection = detect_cline_mcp(context)
    assert {artifact.name for artifact in detection.artifacts} == {"local", "remote"}
    evidence_text = json.dumps(
        [
            {
                "name": artifact.name,
                "args": artifact.args,
                "metadata": artifact.metadata,
            }
            for artifact in detection.artifacts
        ],
        sort_keys=True,
    )
    assert "secret" not in evidence_text
    assert "TOKEN" in evidence_text

    result = install_cline_mcp_proxies(context)
    assert result["managed_servers"] == ["local"]
    assert result["skipped_remote_servers"] == ["remote"]
    managed = json.loads(settings.read_text(encoding="utf-8"))
    assert managed["mcpServers"]["local"]["command"] == sys.executable
    assert "mcp-proxy" in managed["mcpServers"]["local"]["args"]
    assert managed["mcpServers"]["remote"] == original["mcpServers"]["remote"]

    restored = restore_cline_mcp_proxies(context)
    assert restored["complete"] is True
    assert settings.read_text(encoding="utf-8") == original_text


def test_cline_mcp_restore_never_clobbers_user_edits(tmp_path: Path) -> None:
    context = _context(tmp_path)
    settings = context.home_dir / ".cline" / "data" / "settings" / "cline_mcp_settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps({"mcpServers": {"local": {"command": "node", "args": ["server.js"]}}}),
        encoding="utf-8",
    )
    install_cline_mcp_proxies(context)
    managed = json.loads(settings.read_text(encoding="utf-8"))
    managed["userChange"] = True
    settings.write_text(json.dumps(managed), encoding="utf-8")

    restored = restore_cline_mcp_proxies(context)
    assert restored["complete"] is False
    assert str(settings) in restored["retained_modified"]
    assert json.loads(settings.read_text(encoding="utf-8"))["userChange"] is True
