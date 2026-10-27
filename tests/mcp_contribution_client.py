"""Per-tool contribution defaults, read by tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from codex_plugin_scanner.guard.runtime.mcp_server_contribution import _TOOL_STATES, _normalized_tool_name


def mcp_tool_state(payload: Mapping[str, object], tool_name: str) -> str:
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return "inherit"
    wanted = _normalized_tool_name(tool_name)
    fallback = "inherit"
    for item in tools:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        state = item.get("state")
        normalized = _normalized_tool_name(name) if isinstance(name, str) else ""
        if normalized == "other" and state in _TOOL_STATES:
            fallback = cast(str, state)
        if normalized == wanted and state in _TOOL_STATES:
            return cast(str, state)
    return fallback
