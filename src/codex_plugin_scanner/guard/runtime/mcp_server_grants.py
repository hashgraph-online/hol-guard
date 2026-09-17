"""Apply contributed MCP server defaults after this-device custom grants."""

from __future__ import annotations

from collections.abc import Mapping

from ..models import GuardAction, GuardArtifact
from .extension_control_contract import ExtensionControlLayer
from .extension_trust import extension_is_active
from .mcp_server_contribution import (
    catalog_id_for_mcp_id,
    load_mcp_contribution_payloads,
    mcp_tool_state,
)

_REVIEW_ACTIONS = frozenset({"review", "require-reapproval", "warn"})


def apply_contributed_mcp_decision(
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
    if current_action not in _REVIEW_ACTIONS:
        return None
    payload = matching_mcp_contribution(artifact)
    if payload is None:
        return None
    mcp_id = payload.get("id")
    if not isinstance(mcp_id, str):
        return None
    catalog_id = catalog_id_for_mcp_id(mcp_id)
    layers = _authority_layers(store)
    if not extension_is_active(catalog_id, layers):
        return None
    tool_name = _mcp_identity_tool_name(artifact)
    if tool_name is None:
        return None
    state = mcp_tool_state(payload, tool_name)
    lockdown = any(layer.global_lockdown for layer in layers or ())
    if state == "block":
        return (
            "block",
            "catalog-mcp-extension",
            "This MCP tool is blocked by a catalog MCP server on this device.",
        )
    if state == "allow" and not lockdown:
        return (
            "allow",
            "catalog-mcp-extension",
            "This MCP tool is allowed by a catalog MCP server on this device.",
        )
    return None


def matching_mcp_contribution(artifact: GuardArtifact) -> dict[str, object] | None:
    package = _package_name(artifact)
    if package is None:
        return None
    for payload in load_mcp_contribution_payloads():
        launch = payload.get("launch")
        if not isinstance(launch, dict):
            continue
        declared = launch.get("package")
        if isinstance(declared, str) and declared.strip().lower() == package:
            return payload
    return None


def _authority_layers(store: object) -> tuple[ExtensionControlLayer, ...] | None:
    lookup = getattr(store, "read_extension_control_authority_for_registry", None)
    if not callable(lookup):
        return None
    from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    view = lookup(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    layers = getattr(view, "layers", None)
    if layers is None:
        return None
    return tuple(layers)


def _package_name(artifact: GuardArtifact) -> str | None:
    metadata = artifact.metadata
    if not isinstance(metadata, Mapping):
        return None
    identity = metadata.get("mcp_server_identity")
    if not isinstance(identity, Mapping):
        return None
    package = identity.get("package_name")
    if not isinstance(package, str) or not package.strip():
        return None
    return package.strip().lower()


def _mcp_identity_tool_name(artifact: GuardArtifact) -> str | None:
    metadata = artifact.metadata
    if not isinstance(metadata, Mapping):
        return None
    tool_identity = metadata.get("mcp_tool_identity")
    if not isinstance(tool_identity, Mapping):
        return None
    name = tool_identity.get("tool_name")
    if not isinstance(name, str) or not name.strip():
        return None
    return name.strip()
