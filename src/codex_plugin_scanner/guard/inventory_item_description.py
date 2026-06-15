from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

InventoryItemKind = Literal[
    "agent",
    "daemon_plugin",
    "harness",
    "model_provider",
    "package",
    "prompt_pack",
    "skill",
    "mcp_server",
    "mcp_tool",
    "plugin",
    "channel",
    "hook",
    "overlay",
    "repository",
    "container_image",
    "policy",
    "secret_reference",
    "network_endpoint",
]

_MAX_DESCRIPTION_LENGTH = 500
_WHITESPACE_RE = re.compile(r"\s+")

_DESCRIPTION_METADATA_KEYS = (
    "description",
    "summary",
    "pluginDescription",
    "displayDescription",
)


def _clean_description_text(value: str) -> str:
    collapsed = _WHITESPACE_RE.sub(" ", value.strip())
    if not collapsed:
        return ""
    if len(collapsed) <= _MAX_DESCRIPTION_LENGTH:
        return collapsed
    trimmed = collapsed[: _MAX_DESCRIPTION_LENGTH - 1].rstrip()
    return f"{trimmed}…"


def _metadata_description(metadata: dict[str, object]) -> str | None:
    for key in _DESCRIPTION_METADATA_KEYS:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _publisher_clause(publisher: str | None) -> str:
    if not publisher or not publisher.strip():
        return ""
    return f" published by {publisher.strip()}"


def _kind_fallback_description(
    *,
    harness: str,
    item_kind: InventoryItemKind,
    display_name: str,
    publisher: str | None,
) -> str:
    name = display_name.strip() or "This item"
    harness_label = harness.replace("_", " ")
    publisher_text = _publisher_clause(publisher)
    templates: dict[InventoryItemKind, str] = {
        "agent": f"{name} configures agent behavior for {harness_label}.",
        "daemon_plugin": f"{name} is a Guard daemon plugin on this machine.",
        "harness": f"{name} is the protected harness runtime Guard monitors.",
        "model_provider": f"{name} is a model provider configured for {harness_label}.",
        "package": f"{name} is an installed package used by {harness_label}.",
        "prompt_pack": f"{name} is a prompt or command pack available to {harness_label}.",
        "skill": f"{name} is an agent skill with instructions {harness_label} can load.",
        "mcp_server": f"{name} is an MCP server connected to {harness_label}.",
        "mcp_tool": f"{name} is an MCP tool exposed by a connected server.",
        "plugin": f"{name} is an extension{publisher_text} installed for {harness_label}.",
        "channel": f"{name} is a messaging channel configured for {harness_label}.",
        "hook": f"{name} is a lifecycle hook invoked by {harness_label}.",
        "overlay": f"{name} is workspace guidance or rules consumed by {harness_label}.",
        "repository": f"{name} is a repository context linked to {harness_label}.",
        "container_image": f"{name} is a container image referenced by {harness_label}.",
        "policy": f"{name} is a policy artifact governing {harness_label} behavior.",
        "secret_reference": f"{name} references credentials used by {harness_label}.",
        "network_endpoint": f"{name} is a network endpoint reachable from {harness_label}.",
    }
    return templates.get(item_kind, f"{name} is an inventory item detected for {harness_label}.")


def resolve_inventory_item_description(
    *,
    harness: str,
    item_kind: InventoryItemKind,
    display_name: str,
    metadata: dict[str, object],
    publisher: str | None = None,
    explicit_description: str | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
) -> str:
    from .inventory_contract import (
        _SAFE_SERIALIZED_MARKERS,
        _safe_finding_text,
        _sanitize_serializer_string,
    )

    candidate = explicit_description or _metadata_description(metadata)
    if candidate:
        sanitized = _sanitize_serializer_string(candidate, parent_key="description")
        if home_dir is not None:
            sanitized = _safe_finding_text(
                sanitized,
                home_dir=home_dir,
                workspace_dir=workspace_dir,
            )
        cleaned = _clean_description_text(sanitized)
        if cleaned and cleaned not in _SAFE_SERIALIZED_MARKERS:
            return cleaned

    return _clean_description_text(
        _kind_fallback_description(
            harness=harness,
            item_kind=item_kind,
            display_name=display_name,
            publisher=publisher,
        )
    )
