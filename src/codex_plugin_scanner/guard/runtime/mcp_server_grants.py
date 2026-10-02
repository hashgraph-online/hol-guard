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
    normalized_remote_server_name,
    remote_mcp_endpoint_identity,
)

_REVIEW_ACTIONS = frozenset({"review", "require-reapproval", "warn"})
_REMOTE_TRANSPORTS = frozenset({"http", "https", "remote", "sse", "streamable-http", "streamable_http"})


def apply_contributed_mcp_decision(
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
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
        if current_action == "block":
            return None
        return (
            "block",
            "catalog-mcp-extension",
            "This MCP tool is blocked by a catalog MCP server on this device.",
        )
    if state == "review":
        if current_action not in {"allow", "warn"}:
            return None
        return (
            "review",
            "catalog-mcp-extension",
            "This MCP tool requires review under a catalog MCP server enabled on this device.",
        )
    if current_action not in _REVIEW_ACTIONS:
        return None
    if state == "allow" and not lockdown:
        return (
            "allow",
            "catalog-mcp-extension",
            "This MCP tool is allowed by a catalog MCP server on this device.",
        )
    return None


def matching_mcp_contribution(artifact: GuardArtifact) -> dict[str, object] | None:
    package = _package_name(artifact)
    if package is not None:
        for payload in load_mcp_contribution_payloads():
            launch = payload.get("launch")
            if not isinstance(launch, dict) or launch.get("kind") != "package-launcher":
                continue
            declared = launch.get("package")
            if isinstance(declared, str) and declared.strip().lower() == package:
                return payload
    for payload in load_mcp_contribution_payloads():
        launch = payload.get("launch")
        if not isinstance(launch, dict) or launch.get("kind") != "remote-http":
            continue
        if _matches_remote_http_contribution(artifact, launch):
            return payload
    return None


def _matches_remote_http_contribution(artifact: GuardArtifact, launch: Mapping[str, object]) -> bool:
    if _mcp_transport(artifact) != "http":
        return False
    remote_endpoint = remote_mcp_endpoint_identity(launch.get("url"))
    if remote_endpoint is None:
        return False
    identity_command_value = _mcp_identity_command(artifact)
    if identity_command_value is not None:
        identity_endpoint = remote_mcp_endpoint_identity(identity_command_value)
        if identity_endpoint is None:
            return False
        return identity_endpoint == remote_endpoint
    server_name = normalized_remote_server_name(_mcp_server_name(artifact))
    server_names = launch.get("serverNames")
    if server_name is None or not isinstance(server_names, list):
        return False
    declared_names = {
        normalized for item in server_names if (normalized := normalized_remote_server_name(item)) is not None
    }
    return server_name in declared_names


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


def _mcp_identity_command(artifact: GuardArtifact) -> object:
    metadata = artifact.metadata
    if not isinstance(metadata, Mapping):
        return None
    identity = metadata.get("mcp_server_identity")
    if not isinstance(identity, Mapping):
        return None
    return identity.get("command")


def _mcp_transport(artifact: GuardArtifact) -> str | None:
    metadata = artifact.metadata
    if isinstance(metadata, Mapping):
        identity = metadata.get("mcp_server_identity")
        if isinstance(identity, Mapping):
            transport = identity.get("transport")
            if isinstance(transport, str) and transport.strip():
                normalized = transport.strip().lower()
                return "http" if normalized in _REMOTE_TRANSPORTS else normalized
    if isinstance(artifact.transport, str) and artifact.transport.strip():
        normalized = artifact.transport.strip().lower()
        return "http" if normalized in _REMOTE_TRANSPORTS else normalized
    return None


def _mcp_server_name(artifact: GuardArtifact) -> object:
    metadata = artifact.metadata
    if not isinstance(metadata, Mapping):
        return None
    return metadata.get("server_name")


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
