"""Conservative permissions for provider actions inside an MCP router.

The currently supported identity is the observed host namespace, across all its
accounts. It supports Ask and Deny. Allow needs a verified account binding and
is intentionally absent from this contract.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from .composio_contract import composio_batch_actions, composio_tool_role
from .observed_mcp_tools import ObservedMcpTool, observed_mcp_tool

ProviderActionState = Literal["review", "block"]
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


@dataclass(frozen=True, slots=True)
class ProviderActionFloor:
    action: ProviderActionState
    reason: Literal["denied-batch-member", "opaque-execution-with-deny", "unresolved-actions"]


def composio_provider_action_floor(
    choices: Mapping[str, str],
    *,
    harness: str,
    tool_name: str,
    arguments: object,
) -> ProviderActionFloor | None:
    source = observed_mcp_tool(harness, tool_name)
    role = composio_tool_role(tool_name)
    if source is None or role not in {"batch", "workbench", "unknown"}:
        return None
    prefix = f"{source.harness}:{source.namespace}:composio:all-accounts:"
    scoped = {
        key[len(prefix) :]: value
        for key, value in choices.items()
        if key.startswith(prefix) and valid_provider_action_selector(key) and value in {"review", "block"}
    }
    if role != "batch":
        return (
            ProviderActionFloor("block", "opaque-execution-with-deny")
            if "block" in scoped.values()
            else (ProviderActionFloor("review", "unresolved-actions"))
        )
    parsed = composio_batch_actions(arguments)
    # A malformed batch cannot hide a definite denied member. This scan does
    # not resolve or authorize other members, and never executes a subset.
    raw = arguments.get("tools") if isinstance(arguments, Mapping) else None
    denied = {slug.casefold() for slug, state in scoped.items() if state == "block"}
    if (
        isinstance(raw, list)
        and len(raw) <= 50
        and any(
            isinstance(member, Mapping)
            and isinstance(slug := member.get("tool_slug"), str)
            and slug.casefold() in denied
            for member in raw
        )
    ):
        return ProviderActionFloor("block", "denied-batch-member")
    if (parsed is None or any(not _SLUG.fullmatch(action.tool_slug) for action in parsed)) and denied:
        return ProviderActionFloor("block", "opaque-execution-with-deny")
    return ProviderActionFloor("review", "unresolved-actions")
