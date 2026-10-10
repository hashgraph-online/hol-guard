"""Present the native contributed MCP server decision.

The resident owns the decision: it loads the bundled MCP contributions, picks
the contribution that matches the server, resolves the per-tool state, and
binds any automatic allow to the reviewed launcher, package source, and
transport. Python sends only non-authoritative inputs recorded on the artifact
plus the extension-control layers it verified, and maps the answer back.

When the resident gives no answer Python does not guess: it raises
``LocalCliIdentityUnavailableError`` so callers hold an otherwise allowed call
for review. There is no Python verdict and no silent allow.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from ..models import GuardAction, GuardArtifact
from ..native_contributed_mcp_decision import NativeContributedMcpFailure, native_contributed_mcp_decision
from ..native_local_cli_identity import LocalCliIdentityUnavailableError
from .extension_control_contract import ControlTargetKind, ExtensionControlLayer

_IDENTITY_KEYS = ("package_name", "command", "transport", "package_source", "package_version", "env_keys")
_UNAVAILABLE = "native_contributed_mcp_unavailable"
_LOGGER = logging.getLogger(__name__)


def apply_contributed_mcp_decision(
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
    """Return the contributed ``(action, source, reason)``, or ``None`` if none applies.

    Raises ``LocalCliIdentityUnavailableError`` when the resident gives no answer.
    """

    store_path = getattr(store, "path", None)
    guard_home = getattr(store, "guard_home", None)
    if not isinstance(store_path, Path) or not isinstance(guard_home, Path):
        raise LocalCliIdentityUnavailableError(_UNAVAILABLE)
    metadata = artifact.metadata if isinstance(artifact.metadata, Mapping) else {}
    tool_identity = metadata.get("mcp_tool_identity")
    native = native_contributed_mcp_decision(
        store_path=store_path,
        guard_home=guard_home,
        current_action=current_action,
        server_identity=_server_identity(metadata.get("mcp_server_identity")),
        artifact_transport=artifact.transport,
        server_name=metadata.get("server_name"),
        tool_name=tool_identity.get("tool_name") if isinstance(tool_identity, Mapping) else None,
        layers=_layer_inputs(_authority_layers(store)),
    )
    if isinstance(native, NativeContributedMcpFailure):
        # Callers hold the call for review without an answer; record why so a
        # held call can be traced to its cause.
        _LOGGER.warning("contributed MCP decision unavailable: %s", native.code)
        raise LocalCliIdentityUnavailableError(native.code)
    if native.state == "decided" and native.action is not None:
        return cast(GuardAction, native.action), native.source or "", native.reason or ""
    return None


def _server_identity(identity: object) -> dict[str, object] | None:
    if not isinstance(identity, Mapping):
        return None
    return {key: identity[key] for key in _IDENTITY_KEYS if key in identity}


def _layer_inputs(layers: tuple[ExtensionControlLayer, ...] | None) -> list[dict[str, object]]:
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
        for layer in layers or ()
    ]


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
