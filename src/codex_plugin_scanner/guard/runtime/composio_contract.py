"""Recognize the inspected Composio meta-tool execution boundaries.

Tool roles describe routing, never authority. Hosted execution takes an array
of exact tool slugs, arguments and optional account selectors. Missing account
selectors cannot be interpreted as an account identity by Guard.
"""

from __future__ import annotations

from typing import Literal

ComposioToolRole = Literal["discovery", "batch", "workbench", "connections", "unknown"]
_ROLES: dict[str, ComposioToolRole] = {
    "composio_search_tools": "discovery",
    "composio_get_tool_schemas": "discovery",
    "composio_multi_execute_tool": "batch",
    "composio_remote_workbench": "workbench",
    "composio_remote_bash_tool": "workbench",
    "composio_manage_connections": "connections",
}


def composio_tool_role(tool_name: str) -> ComposioToolRole | None:
    name = tool_name.rsplit("__", 1)[-1].casefold()
    role = _ROLES.get(name)
    if role is not None:
        return role
    if name.startswith("composio_"):
        return "unknown"
    return None


def composio_requires_action_review(tool_name: str) -> bool:
    return composio_tool_role(tool_name) in {"batch", "workbench", "connections", "unknown"}
