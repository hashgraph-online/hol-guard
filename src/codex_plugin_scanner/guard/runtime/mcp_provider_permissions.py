"""Conservative permissions for provider actions inside an MCP router.

The currently supported identity is the observed host namespace, across all its
accounts. It supports Ask and Deny. Allow needs a verified account binding and
is intentionally absent from this contract.
"""

from __future__ import annotations

import re

from .observed_mcp_tools import ObservedMcpTool, observed_mcp_tool

_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def provider_action_selector(source: ObservedMcpTool, slug: str) -> str:
    if not _SLUG.fullmatch(slug) or observed_mcp_tool(source.harness, source.qualified_name) != source:
        raise ValueError("invalid provider action identity")
    return f"{source.harness}:{source.namespace}:composio:all-accounts:{slug}"


def valid_provider_action_selector(selector: str) -> bool:
    parts = selector.split(":")
    if len(parts) != 5 or parts[2:4] != ["composio", "all-accounts"] or not _SLUG.fullmatch(parts[4]):
        return False
    source = observed_mcp_tool(parts[0], parts[1] + "probe")
    return source is not None and source.harness == parts[0] and source.namespace == parts[1]
