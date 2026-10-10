"""Present the native this-device MCP grant decision.

The resident owns the decision. This module supplies only non-authoritative
inputs recorded on the artifact (server identity material, tool name, live
authority digest, connection identity digest, and the caller's launcher
``PATH``/home) and maps the answer back to callers.

When the resident gives no answer, an existing block must not silently
vanish, and Python must not guess. The answer is the same
``LocalCliIdentityUnavailableError`` an identity failure raises: callers hold
an otherwise allowed tool call for review while block rules exist. Python
never reads grant rows to substitute.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from .models import GuardAction, GuardArtifact
from .native_local_cli_identity import LocalCliIdentityUnavailableError
from .native_local_mcp_grant import NativeLocalMcpGrantFailure, native_local_mcp_grant

_LOGGER = logging.getLogger(__name__)

McpGrantOutcome = Literal["allowed", "blocked", "review"]


def decide_local_mcp_grant(
    *,
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> McpGrantOutcome | None:
    """Return the grant outcome for a live tools/call, or ``None`` if none applies."""

    store_path = getattr(store, "path", None)
    guard_home = getattr(store, "guard_home", None)
    if not isinstance(store_path, Path) or not isinstance(guard_home, Path):
        raise LocalCliIdentityUnavailableError("native_local_mcp_grant_unavailable")
    server_hash = _mcp_server_identity_hash(artifact)
    command, args_hash = _mcp_server_launch(artifact)
    native = native_local_mcp_grant(
        store_path=store_path,
        guard_home=guard_home,
        current_action=current_action,
        harness=artifact.harness,
        tool_name=_mcp_tool_name(artifact),
        server={
            "identity_hash": _mcp_server_field(artifact, "identity_hash"),
            "transport": _mcp_server_field(artifact, "transport"),
            "command": command,
            "args_hash": args_hash,
            "package_name": _mcp_server_package_field(artifact, "package_name"),
            "package_version": _mcp_server_package_field(artifact, "package_version"),
            "package_source": _mcp_server_package_field(artifact, "package_source"),
            "env_values_hash": _mcp_server_package_field(artifact, "env_values_hash"),
        },
        connection_identity_hash=(
            None if server_hash is None else _configured_mcp_connection_hash(artifact, server_hash)
        ),
        tool_authority_hash=_tool_authority_hash(artifact),
        launcher_path=_caller_launcher_path(os.environ.get("PATH")),
        launcher_home=os.path.expanduser("~"),
    )
    if isinstance(native, NativeLocalMcpGrantFailure):
        # Callers hold the call for review without an answer; record why so a
        # grant that stopped applying can be traced to its cause.
        _LOGGER.warning("local MCP grant decision unavailable: %s", native.code)
        raise LocalCliIdentityUnavailableError(native.code)
    state = native.state
    if state == "allowed" or state == "blocked" or state == "review":
        return state
    return None


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
    try:
        cwd = os.getcwd()
    except OSError as error:
        # A deleted working directory cannot anchor relative entries; hold for review.
        raise LocalCliIdentityUnavailableError("native_local_mcp_grant_unavailable") from error
    return os.pathsep.join(part if not part or os.path.isabs(part) else os.path.join(cwd, part) for part in parts)


def _tool_authority_hash(artifact: GuardArtifact) -> str | None:
    public_hash = artifact.metadata.get("mcp_tool_authority_hash")
    # An explicitly empty or invalid public hash must fail closed.
    value = public_hash if public_hash is not None else artifact.runtime_private_metadata.get("mcp_tool_authority_hash")
    return value if isinstance(value, str) else None


def _mcp_server_field(artifact: GuardArtifact, field: str) -> str | None:
    metadata = artifact.metadata
    identity = metadata.get("mcp_server_identity") if isinstance(metadata, Mapping) else None
    value = identity.get(field) if isinstance(identity, Mapping) else None
    return value if isinstance(value, str) else None


def _configured_mcp_connection_hash(artifact: GuardArtifact, server_hash: str) -> str:
    from .runtime.mcp_connection_identity import build_mcp_connection_identity

    server_name = artifact.metadata.get("server_name")
    return build_mcp_connection_identity(
        host=artifact.harness,
        source_scope=artifact.source_scope,
        config_path=artifact.config_path,
        server_name=server_name if isinstance(server_name, str) else "",
        server_identity_hash=server_hash,
    ).identity_hash


def _mcp_server_launch(artifact: GuardArtifact) -> tuple[str | None, str | None]:
    metadata = artifact.metadata
    if not isinstance(metadata, Mapping):
        return None, None
    identity = metadata.get("mcp_server_identity")
    if not isinstance(identity, Mapping):
        return None, None
    command = identity.get("command")
    args_hash = identity.get("args_hash")
    command_text = command.strip() if isinstance(command, str) and command.strip() else None
    args_text = args_hash.strip() if isinstance(args_hash, str) and args_hash.strip() else None
    return command_text, args_text


def _mcp_server_package_field(artifact: GuardArtifact, field: str) -> str | None:
    metadata = artifact.metadata
    if not isinstance(metadata, Mapping):
        return None
    identity = metadata.get("mcp_server_identity")
    if not isinstance(identity, Mapping):
        return None
    value = identity.get(field)
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _mcp_server_identity_hash(artifact: GuardArtifact) -> str | None:
    metadata = artifact.metadata
    if not isinstance(metadata, Mapping):
        return None
    identity = metadata.get("mcp_server_identity")
    if not isinstance(identity, Mapping):
        return None
    value = identity.get("identity_hash")
    if not isinstance(value, str) or len(value) != 64:
        return None
    lowered = value.lower()
    if any(character not in "0123456789abcdef" for character in lowered):
        return None
    return lowered


def _mcp_tool_name(artifact: GuardArtifact) -> str:
    metadata = artifact.metadata
    if isinstance(metadata, Mapping):
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
