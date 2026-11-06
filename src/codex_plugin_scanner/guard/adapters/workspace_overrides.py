"""Shared precedence checks for workspace-scoped MCP configuration."""

from __future__ import annotations

from .base import HarnessContext
from .mcp_servers import ManagedMcpServer


def should_skip_workspace_override(
    *,
    context: HarnessContext,
    server: ManagedMcpServer,
    existing_workspace_server_names: set[str],
    for_companion: bool = False,
) -> bool:
    """Return whether a workspace entry shadows the managed non-project server."""

    if context.workspace_dir is None:
        return False
    if server.source_scope == "project":
        return False
    if for_companion and server.source_scope == "global":
        return False
    return server.name in existing_workspace_server_names
