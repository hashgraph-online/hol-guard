"""This-device allow and block grants for unlisted CLIs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .models import GuardAction, GuardArtifact
from .runtime.local_cli_commands import (
    OTHER_COMMAND_ID,
    LocalCliCommand,
    resolve_command_id_for_text,
    slug_local_cli_command_id,
)
from .runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli

LocalCliGrantState = Literal["allowed", "blocked"]


@dataclass(frozen=True, slots=True)
class LocalCliGrant:
    cli_id: str
    identity_hash: str
    state: LocalCliGrantState
    revision: int
    updated_at: str


def matching_local_cli_grant(
    *,
    store: object,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
) -> tuple[UnlistedCliIdentity, LocalCliGrantState] | None:
    """Return an enrolled grant when the command matches an unlisted CLI identity."""

    if current_action not in {"review", "require-reapproval", "warn"}:
        return None
    identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return None
    lookup = getattr(store, "read_local_cli_grant", None)
    if not callable(lookup):
        return None
    grant = lookup(identity.cli_id)
    if not isinstance(grant, Mapping):
        return None
    raw_state = grant.get("state")
    identity_hash = grant.get("identity_hash")
    if raw_state != "allowed" and raw_state != "blocked":
        return None
    state: LocalCliGrantState = "allowed" if raw_state == "allowed" else "blocked"
    if identity_hash != identity.identity_hash:
        return None
    if state == "blocked":
        return identity, "blocked"
    command_state = _command_state_for_grant(
        store,
        identity=identity,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
    )
    if command_state == "allow":
        return identity, "allowed"
    if command_state == "block":
        return identity, "blocked"
    return None


def apply_local_mcp_extension_decision(
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
    matched = matching_local_mcp_grant(
        store=store,
        artifact=artifact,
        current_action=current_action,
    )
    if matched == "blocked":
        return (
            "block",
            "local-mcp-extension",
            "This MCP tool is blocked by a custom extension on this device.",
        )
    if matched == "allowed":
        return (
            "allow",
            "local-mcp-extension",
            "This MCP tool is allowed by a custom extension on this device.",
        )
    return None


def matching_local_mcp_grant(
    *,
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> LocalCliGrantState | None:
    """Return a this-device MCP extension grant for a live tools/call."""

    if current_action not in {"review", "require-reapproval", "warn"}:
        return None
    lookup = getattr(store, "read_local_mcp_grant", None)
    if not callable(lookup):
        return None
    identity_hash = _mcp_server_identity_hash(artifact)
    if identity_hash is None:
        return None
    command, args_hash = _mcp_server_launch(artifact)
    grant = lookup(identity_hash, command=command, args_hash=args_hash)
    if not isinstance(grant, Mapping):
        return None
    raw_state = grant.get("state")
    if raw_state != "allowed" and raw_state != "blocked":
        return None
    if raw_state == "blocked":
        return "blocked"
    commands = grant.get("commands")
    if not isinstance(commands, list) or not commands:
        return "allowed"
    command_id = slug_local_cli_command_id(_mcp_tool_name(artifact))
    known = {item.command_id for item in commands if isinstance(item, LocalCliCommand)}
    if command_id not in known:
        command_id = OTHER_COMMAND_ID
    states = grant.get("command_states")
    if not isinstance(states, dict):
        return None
    tool_state = states.get(command_id, "inherit")
    if tool_state == "allow":
        return "allowed"
    if tool_state == "block":
        return "blocked"
    return None


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


def _command_state_for_grant(
    store: object,
    *,
    identity: UnlistedCliIdentity,
    command: str,
    cwd: Path,
    home_dir: Path | None,
) -> str:
    catalog_lookup = getattr(store, "read_local_cli_command_catalog", None)
    states_lookup = getattr(store, "read_local_cli_command_states", None)
    commands: list[LocalCliCommand] = []
    if callable(catalog_lookup):
        loaded = catalog_lookup(identity.cli_id)
        if isinstance(loaded, list):
            commands = [item for item in loaded if isinstance(item, LocalCliCommand)]
    if not commands:
        return "allow"
    command_id = resolve_command_id_for_text(
        command,
        cwd=cwd,
        home_dir=home_dir,
        identity=identity,
        commands=commands,
    )
    states = states_lookup(identity.cli_id) if callable(states_lookup) else {}
    if not isinstance(states, dict):
        return "inherit"
    raw_state = states.get(command_id, "inherit")
    return raw_state if raw_state in {"inherit", "allow", "block"} else "inherit"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
