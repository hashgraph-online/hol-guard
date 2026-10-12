"""Non-authoritative inputs for the resident's this-device MCP extension decision.

The resident reads the grant rows and the bundled catalog contributions itself
and decides in the tool-policy pass. This module supplies only what is recorded
on the artifact (server identity material, tool name, authority digests, the
caller's launcher ``PATH``/home) and the extension-control layers the store
verified. It never decides, and it never reads grant rows.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from .models import GuardArtifact
from .runtime.extension_control_contract import ControlTargetKind, ExtensionControlLayer

_CONTRIBUTED_KEYS = ("package_name", "command", "transport", "package_source", "package_version", "env_keys")
_HEX = frozenset("0123456789abcdef")


def build_extension_input(store: object, artifact: GuardArtifact) -> dict[str, object]:
    metadata = artifact.metadata if isinstance(artifact.metadata, Mapping) else {}
    identity = metadata.get("mcp_server_identity")
    identity = identity if isinstance(identity, Mapping) else {}
    store_path, guard_home = getattr(store, "path", None), getattr(store, "guard_home", None)
    launcher_path, local_unavailable = None, False
    try:
        launcher_path = _caller_launcher_path(os.environ.get("PATH"))
    except OSError:
        # A deleted working directory cannot anchor relative entries; hold for review.
        local_unavailable = True
    layers_unavailable = False
    try:
        layers = _layer_inputs(_authority_layers(store))
    except Exception:
        # An unreadable control layer must not abort the call before the
        # resident applies its own denials; it holds the call for review.
        layers, layers_unavailable = [], True
    server_hash = _server_identity_hash(identity)
    tool_identity = metadata.get("mcp_tool_identity")
    return {
        "store_path": str(store_path) if isinstance(store_path, Path) else "",
        "guard_home": str(guard_home) if isinstance(guard_home, Path) else "",
        "harness": artifact.harness,
        "tool_name": _tool_name(artifact, metadata),
        "server": {
            "identity_hash": _raw_text(identity.get("identity_hash")),
            "transport": _raw_text(identity.get("transport")),
            "command": _stripped(identity.get("command")),
            "args_hash": _stripped(identity.get("args_hash")),
            "package_name": _stripped(identity.get("package_name")),
            "package_version": _stripped(identity.get("package_version")),
            "package_source": _stripped(identity.get("package_source")),
            "env_values_hash": _stripped(identity.get("env_values_hash")),
        },
        "connection_identity_hash": None if server_hash is None else _connection_hash(artifact, server_hash),
        "tool_authority_hash": _tool_authority_hash(artifact),
        "launcher_path": launcher_path,
        "launcher_home": os.path.expanduser("~"),
        "local_unavailable": local_unavailable,
        "server_identity": ({key: identity[key] for key in _CONTRIBUTED_KEYS if key in identity} if identity else None),
        "artifact_transport": artifact.transport,
        "server_name": metadata.get("server_name"),
        "contributed_tool_name": tool_identity.get("tool_name") if isinstance(tool_identity, Mapping) else None,
        "layers": layers,
        "layers_unavailable": layers_unavailable,
    }


def _raw_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _stripped(value: object) -> str | None:
    return (value.strip() or None) if isinstance(value, str) else None


def _caller_launcher_path(path_value: str | None) -> str | None:
    """Anchor relative ``PATH`` entries to this process's working directory.

    The resident runs elsewhere, so a relative entry such as
    ``node_modules/.bin`` would otherwise resolve against its own directory.
    """

    if path_value is None:
        return None
    parts = path_value.split(os.pathsep)
    if all(not part or os.path.isabs(part) for part in parts):
        return path_value
    cwd = os.getcwd()
    return os.pathsep.join(part if not part or os.path.isabs(part) else os.path.join(cwd, part) for part in parts)


def _tool_authority_hash(artifact: GuardArtifact) -> str | None:
    public_hash = artifact.metadata.get("mcp_tool_authority_hash")
    # An explicitly empty or invalid public hash must fail closed.
    value = public_hash if public_hash is not None else artifact.runtime_private_metadata.get("mcp_tool_authority_hash")
    return value if isinstance(value, str) else None


def _server_identity_hash(identity: Mapping[str, object]) -> str | None:
    value = identity.get("identity_hash")
    if not isinstance(value, str) or len(value) != 64:
        return None
    lowered = value.lower()
    return lowered if set(lowered) <= _HEX else None


def _connection_hash(artifact: GuardArtifact, server_hash: str) -> str:
    from .runtime.mcp_connection_identity import build_mcp_connection_identity

    server_name = artifact.metadata.get("server_name")
    return build_mcp_connection_identity(
        host=artifact.harness,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        server_name=server_name if isinstance(server_name, str) else "",
        server_identity_hash=server_hash,
    ).identity_hash


def _tool_name(artifact: GuardArtifact, metadata: Mapping[str, object]) -> str:
    tool_identity = metadata.get("mcp_tool_identity")
    if isinstance(tool_identity, Mapping):
        name = tool_identity.get("tool_name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    command = artifact.command
    if isinstance(command, str) and command.strip():
        return command.strip()
    name = artifact.name
    if isinstance(name, str) and ":" in name:
        return name.rsplit(":", 1)[-1].strip()
    return name.strip() if isinstance(name, str) else ""


def _layer_inputs(layers: tuple[ExtensionControlLayer, ...]) -> list[dict[str, object]]:
    """Verified layer facts the resident composes; extension-kind controls only."""

    return [
        {
            "kind": layer.kind.value,
            "global_lockdown": layer.global_lockdown,
            "controls": [
                {"target_id": control.target.target_id, "state": control.state.value}
                for control in layer.controls
                if control.target.kind is ControlTargetKind.EXTENSION
            ],
        }
        for layer in layers
    ]


def _authority_layers(store: object) -> tuple[ExtensionControlLayer, ...]:
    lookup = getattr(store, "read_extension_control_authority_for_registry", None)
    if not callable(lookup):
        return ()
    from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

    return tuple(getattr(lookup(BUILT_IN_COMMAND_EXTENSION_REGISTRY), "layers", None) or ())
