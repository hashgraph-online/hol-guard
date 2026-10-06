"""Regression coverage for FastMCP tool registration."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from codex_plugin_scanner.guard.mcp.registry import build_tool_registry
from codex_plugin_scanner.guard.mcp.server import (
    _ORIGINAL_TOOL_DESCRIPTIONS,
    GuardMCPServer,
    _create_annotations,
)


def test_fastmcp_registration_resolves_tool_annotations(tmp_path: Path) -> None:
    """FastMCP must resolve annotations for every Guard MCP tool."""
    server = GuardMCPServer(guard_home=tmp_path)
    mcp = FastMCP("hol-guard-test")

    for tool_definition in build_tool_registry():
        server._register_fastmcp_tool(
            mcp,
            tool_definition,
            _ORIGINAL_TOOL_DESCRIPTIONS.get(tool_definition.name, tool_definition.description),
            _create_annotations(
                read_only=tool_definition.annotations.read_only,
                destructive=tool_definition.annotations.destructive,
            ),
        )
