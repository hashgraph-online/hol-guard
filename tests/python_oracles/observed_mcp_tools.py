"""Parse a qualified MCP tool name into the observed connector it belongs to.

The native runtime owns this parser (``guard_store_observed_mcp.rs``) and
hands each discovered tool back with its command id. Tests build the same
``ObservedMcpTool`` records to seed stores and name the commands they expect.
"""

from __future__ import annotations

import re
from hashlib import sha256

from codex_plugin_scanner.guard.native_policy_snapshot_codec import _normalized_harness_selector_v3
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import ObservedMcpTool

_TOKEN = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")


def observed_command_id(tool: ObservedMcpTool) -> str:
    """The local CLI command id the native discovery gives this tool."""

    return "tool-" + sha256(tool.qualified_name.encode()).hexdigest()[:24]


def observed_mcp_tool(harness: object, tool_name: object) -> ObservedMcpTool | None:
    if not isinstance(harness, str) or not isinstance(tool_name, str):
        return None
    harness = harness.strip().lower()
    if not _TOKEN.fullmatch(harness) or not tool_name.startswith("mcp__") or len(tool_name) > 160:
        return None
    canonical_harness = _normalized_harness_selector_v3(harness)
    if canonical_harness is None:
        return None
    parts = tool_name[5:].split("__")
    if len(parts) < 2 or any(not _TOKEN.fullmatch(part) for part in parts):
        return None
    server = parts[0]
    split = 1
    if server == "codex_apps" and len(parts) >= 3:
        server = parts[1]
        split = 2
    name = "__".join(parts[split:])
    namespace = "mcp__" + "__".join(parts[:split]) + "__"
    if len(name) > 120 or len(namespace) > 155:
        return None
    return ObservedMcpTool(
        harness=canonical_harness,
        namespace=namespace,
        name=name,
        qualified_name=tool_name,
        server_name="Codex Apps" if server == "codex_apps" else server,
    )
