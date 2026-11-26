"""The Puppeteer MCP profile maps exactly the tools of its recorded reference servers."""

from __future__ import annotations

import json
from pathlib import Path

from ci.gauntlet.browser_fixtures import recorded_tools

_ROOT = Path(__file__).resolve().parents[1]
_PROFILE = _ROOT / "contributions" / "browser-drivers" / "browser.puppeteer-mcp.json"
_BUNDLE = _ROOT / "rust" / "crates" / "guard-command" / "src" / "browser_first_party_drivers.rs"


def _profile() -> dict:
    return json.loads(_PROFILE.read_text(encoding="utf-8"))


def test_profile_lists_every_recorded_tool_and_no_other() -> None:
    profiled = sorted(tool["name"] for tool in _profile()["tools"])
    recorded = sorted(tool["name"] for tool in recorded_tools("puppeteer"))
    assert profiled == recorded


def test_every_pointer_names_an_argument_the_tool_takes() -> None:
    schemas = {tool["name"]: tool["inputSchema"]["properties"] for tool in recorded_tools("puppeteer")}
    checked = 0
    for tool in _profile()["tools"]:
        for field, pointers in tool.items():
            if field in {"name", "verb"}:
                continue
            names = pointers["name"] if isinstance(pointers, dict) else pointers
            for name in names:
                assert name in schemas[tool["name"]], (tool["name"], field, name)
                checked += 1
    assert checked >= len(schemas)


def test_the_profile_is_bundled_and_tracked_upstream() -> None:
    profile = _profile()
    assert "browser.puppeteer-mcp.json" in _BUNDLE.read_text(encoding="utf-8")
    assert profile["referenceVersion"]
    assert profile["publisher"]["verified"] is True
    assert profile["profileMode"] == {"default": "unknown"}
