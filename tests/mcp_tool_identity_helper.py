"""Test-only projection of the native MCP tool identity (no production caller remains)."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.native_context import context_mcp_identity


@dataclass(frozen=True, slots=True)
class McpToolIdentity:
    server_hash: str
    tool_name: str
    schema_hash: str
    description_hash: str
    identity_hash: str


def build_mcp_tool_identity(
    *,
    server_hash: str,
    tool_name: str,
    schema: object | None = None,
    description: str | None = None,
) -> McpToolIdentity:
    identity = context_mcp_identity(
        "mcp_tool_identity",
        {"server_hash": server_hash, "tool_name": tool_name, "schema": schema, "description": description},
    )
    if identity is None:
        raise ValueError("native_mcp_tool_identity_unavailable")
    return McpToolIdentity(**identity)
