"""Recognize the inspected Composio meta-tool execution boundaries.

Tool roles describe routing, never authority. Hosted execution takes an array
of exact tool slugs, arguments and optional account selectors. Missing account
selectors cannot be interpreted as an account identity by Guard.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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


@dataclass(frozen=True, slots=True)
class ComposioRequestedAction:
    tool_slug: str
    account: str | None
    arguments: Mapping[str, object]


def composio_batch_actions(arguments: object) -> tuple[ComposioRequestedAction, ...] | None:
    """Parse a complete supported batch without guessing malformed members.

    A parsed account is an untrusted selector, not a verified connection. The
    caller must resolve it against authenticated provider/host evidence before
    any grant can be applied. This parser never executes or authorizes a batch.
    """

    if not isinstance(arguments, Mapping):
        return None
    tools = arguments.get("tools")
    if not isinstance(tools, list) or not 1 <= len(tools) <= 50:
        return None
    actions: list[ComposioRequestedAction] = []
    for tool in tools:
        if not isinstance(tool, Mapping) or set(tool) - {"tool_slug", "account", "arguments"}:
            return None
        slug, account, params = tool.get("tool_slug"), tool.get("account"), tool.get("arguments")
        if not isinstance(slug, str) or not slug or slug != slug.strip() or len(slug) > 256:
            return None
        if account is not None and (
            not isinstance(account, str) or not account or account != account.strip() or len(account) > 256
        ):
            return None
        if not isinstance(params, Mapping) or any(not isinstance(key, str) for key in params):
            return None
        actions.append(ComposioRequestedAction(slug, account, dict(params)))
    return tuple(actions)
