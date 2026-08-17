"""This-device allow and block grants for unlisted CLIs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .models import GuardAction
from .runtime.local_cli_commands import (
    LocalCliCommand,
    resolve_command_id_for_text,
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
