"""Normalize MCP tool calls from each harness's JSON stream to Claude Code's ``mcp__<server>__<tool>``.

Claude Code already reports that spelling. Codex emits an ``mcp_tool_call`` item that names
the server and tool separately, and Cursor wraps every MCP call as ``mcpToolCall`` with the
server in ``providerIdentifier``. One name lets the connector judges match a call the same
way on every lane.
"""

from __future__ import annotations

from typing import Any


def mcp_name(server: Any, tool: Any) -> str | None:
    """The normalized tool name, or ``None`` when the event does not name both parts."""
    if isinstance(server, str) and server and isinstance(tool, str) and tool:
        return f"mcp__{server}__{tool}"
    return None


def codex_call(item: dict[str, Any]) -> tuple[str, Any] | None:
    """Name and arguments of a Codex ``mcp_tool_call`` item."""
    name = mcp_name(item.get("server"), item.get("tool"))
    return (name, item.get("arguments")) if name else None


def codex_result(item: dict[str, Any]) -> tuple[bool, Any]:
    """Whether a completed Codex MCP item failed, and the error or result it carried."""
    error = item.get("error")
    return item.get("status") != "completed" or bool(error), error or item.get("result")


def cursor_call(name: str, body: dict[str, Any]) -> tuple[str, Any]:
    """Name and arguments of a Cursor tool-call wrapper; an unnamed MCP call keeps its wrapper name."""
    args = body.get("args")
    if name != "mcpToolCall" or not isinstance(args, dict):
        return name, args
    return mcp_name(args.get("providerIdentifier"), args.get("toolName")) or name, args.get("args")
