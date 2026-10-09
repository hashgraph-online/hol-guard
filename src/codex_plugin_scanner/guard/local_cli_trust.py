"""This-device allow and block grants for unlisted CLIs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .local_cli_grant_decision import GRANT_REFINABLE_ACTIONS, decide_local_cli_grant
from .models import GuardAction, GuardArtifact
from .native_local_cli_identity import LocalCliIdentityUnavailableError, track_local_cli_identity_failures
from .runtime.local_cli_commands import (
    OTHER_COMMAND_ID,
    LocalCliCommand,
    slug_local_cli_command_id,
)
from .runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli
from .runtime.package_json_scripts import identify_package_json_scripts

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
    """Return an enrolled grant when the command matches an unlisted CLI identity.

    Raises ``LocalCliIdentityUnavailableError`` when the identity could not be
    derived, so callers can fail closed instead of treating it as no grant.
    """

    if current_action not in GRANT_REFINABLE_ACTIONS:
        return None
    with track_local_cli_identity_failures() as failures:
        identity = identify_package_json_scripts(command, cwd=cwd, home_dir=home_dir)
        if identity is None:
            identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    # A failed script derivation can fall through to the binary's identity.
    if failures:
        raise LocalCliIdentityUnavailableError(failures[0])
    if identity is None:
        return None
    # The resident reads the grant rows and decides; this raises
    # ``LocalCliIdentityUnavailableError`` when it gives no answer.
    outcome = decide_local_cli_grant(
        store=store,
        identity=identity,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
    )
    return None if outcome is None else (identity, outcome)


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
    if matched == "review":
        return (
            "review",
            "local-mcp-extension",
            "This tool is not in the reviewed catalog. Review its authority before execution.",
        )
    from .runtime.mcp_server_grants import apply_contributed_mcp_decision

    contributed = apply_contributed_mcp_decision(store, artifact, current_action)
    if contributed is not None:
        return contributed
    if current_action == "review":
        reasserted = apply_contributed_mcp_decision(store, artifact, "allow")
        if reasserted is not None and reasserted[0] == "review":
            return reasserted
    return None


def matching_local_mcp_grant(
    *,
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> LocalCliGrantState | Literal["review"] | None:
    """Return a this-device MCP extension grant for a live tools/call."""

    if current_action not in {"allow", "review", "require-reapproval", "warn"}:
        return None
    lookup = getattr(store, "read_local_mcp_grant", None)
    if not callable(lookup):
        return None
    identity_hash = _mcp_server_identity_hash(artifact)
    observed = None
    metadata = artifact.metadata
    server_identity = metadata.get("mcp_server_identity") if isinstance(metadata, Mapping) else None
    observed_transport = isinstance(server_identity, Mapping) and server_identity.get("transport") == "observed"
    if identity_hash is None or observed_transport:
        from .runtime.observed_mcp_tools import observed_mcp_tool

        observed = observed_mcp_tool(artifact.harness, _mcp_tool_name(artifact))
        if observed is None:
            return None
        identity_hash = observed.server_identity.identity_hash
        command, args_hash = observed.server_identity.command, observed.server_identity.args_hash
    else:
        command, args_hash = _mcp_server_launch(artifact)
    connection_identity_hash = _configured_mcp_connection_hash(artifact, identity_hash) if observed is None else None
    grant = lookup(
        identity_hash,
        command=command,
        args_hash=args_hash,
        package_name=_mcp_server_package_field(artifact, "package_name"),
        package_version=_mcp_server_package_field(artifact, "package_version"),
        package_source=_mcp_server_package_field(artifact, "package_source"),
        env_values_hash=_mcp_server_package_field(artifact, "env_values_hash"),
        connection_identity_hash=connection_identity_hash,
        tool_name=_mcp_tool_name(artifact),
    )
    if not isinstance(grant, Mapping):
        return None
    raw_state = grant.get("state")
    if raw_state != "allowed" and raw_state != "blocked":
        return None
    if raw_state == "blocked":
        return "blocked"
    commands = grant.get("commands")
    command_id = observed.command_id if observed is not None else slug_local_cli_command_id(_mcp_tool_name(artifact))
    known = (
        {item.command_id for item in commands if isinstance(item, LocalCliCommand)}
        if isinstance(commands, list)
        else set()
    )
    states = grant.get("command_states")
    if command_id not in known:
        # Enrollment cannot grant unseen tools. Retired exact denies survive a
        # removal, including removal of every tool in the inventory.
        if isinstance(states, dict) and (states.get(command_id) == "block" or states.get(OTHER_COMMAND_ID) == "block"):
            return "blocked"
        return "review"
    if not isinstance(states, dict):
        return None
    tool_state = states.get(command_id, "inherit")
    if tool_state == "review":
        return "review"
    if tool_state == "allow":
        from .runtime.composio_contract import composio_requires_action_review

        if composio_requires_action_review(_mcp_tool_name(artifact)):
            return None
        if current_action == "require-reapproval":
            return None
        if grant.get("catalog") is not None or (
            connection_identity_hash is not None and grant.get("identity_hash") == connection_identity_hash
        ):
            from .store_mcp_catalog import catalog_tool_authority_matches

            public_hash = artifact.metadata.get("mcp_tool_authority_hash")
            # An explicitly empty or invalid public hash must fail closed.
            authority_hash = (
                public_hash
                if public_hash is not None
                else artifact.runtime_private_metadata.get("mcp_tool_authority_hash")
            )
            if not catalog_tool_authority_matches(
                grant.get("catalog"),
                _mcp_tool_name(artifact),
                authority_hash,
            ):
                return "review"
        return "allowed"
    if tool_state == "block":
        return "blocked"
    return None


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


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
