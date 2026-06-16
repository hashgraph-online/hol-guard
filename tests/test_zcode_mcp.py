"""Regression tests for ZCode MCP tool PreToolUse hook coverage.

ZCode invokes MCP tools as ``mcp__<server>__<tool>``. The managed PreToolUse
hook must include an ``mcp__.*`` matcher so MCP tool calls are intercepted by
Guard; without it a project or plugin that registers an MCP server could have
the model invoke its tools without the approval center or runtime policy being
consulted.
"""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import (
    ZCODE_PRETOOL_MATCHERS,
    is_guard_managed_hook_command,
)
from codex_plugin_scanner.guard.runtime.actions import normalize_zcode_hook_payload


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "zcode" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


class TestZCodeMcpToolCoverage:
    """MCP tools must be covered by a managed PreToolUse hook."""

    def test_mcp_matcher_is_in_pretool_matchers(self) -> None:
        assert "mcp__.*" in ZCODE_PRETOOL_MATCHERS

    def test_install_installs_mcp_pretooluse_hook(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.zcode.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-zcode"), "notes": []},
        )
        ZCodeHarnessAdapter().install(ctx)
        payload = json.loads((ctx.home_dir / ".zcode" / "cli" / "config.json").read_text(encoding="utf-8"))
        matchers = {
            entry.get("matcher")
            for entry in payload["hooks"]["PreToolUse"]
            if isinstance(entry, dict) and isinstance(entry.get("matcher"), str)
        }
        assert "mcp__.*" in matchers, "Guard must install an mcp__.* PreToolUse matcher so MCP tools are intercepted"
        mcp_entry = next(entry for entry in payload["hooks"]["PreToolUse"] if entry.get("matcher") == "mcp__.*")
        assert any(
            is_guard_managed_hook_command(handler.get("command"))
            for handler in mcp_entry.get("hooks", [])
            if isinstance(handler, dict)
        )

    def test_mcp_tool_payload_is_intercepted_as_pretooluse(self, tmp_path: Path) -> None:
        envelope = normalize_zcode_hook_payload(
            _fixture("pretooluse_mcp.json"),
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"
        assert envelope.event_name == "PreToolUse"
        assert str(envelope.tool_name).startswith("mcp__")
