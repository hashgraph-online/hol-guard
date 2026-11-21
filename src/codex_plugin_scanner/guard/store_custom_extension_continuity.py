"""Crash-atomic persistence for custom Extension continuity."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .runtime.local_cli_commands import (
    LocalCliCommand,
    LocalCliCommandState,
)
from .runtime.local_cli_identity import UnlistedCliIdentity
from .store_local_cli_capabilities import (
    LocalCliCapabilityError,
)
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_catalog import catalog_change_ids
from .store_mcp_provider_permissions import ProviderUpdate


@dataclass(frozen=True, slots=True)
class CustomExtensionContinuityMutation:
    """Preflighted continuity writes that may join policy activation."""

    expected_revision: int
    authority_updates: tuple[tuple[UnlistedCliIdentity, str, Mapping[str, LocalCliCommandState]], ...]
    sync_payloads: Mapping[str, Mapping[str, object]]
    events: tuple[tuple[str, Mapping[str, object]], ...]
    updated_at: str
    sync_preconditions: Mapping[str, object]
    observation_preconditions: Mapping[str, object]
    requires_protected_extension_authority: bool = False
    required_negotiated_capability: str | None = None
    provider_updates: Mapping[str, Sequence[ProviderUpdate]] | None = None
    catalog_seeds: Mapping[str, Sequence[LocalCliCommand]] | None = None
    # Only the local authority apply sets this; signed continuity never does.
    capability_updates: Mapping[str, Mapping[str, str]] | None = None
    # The MCP catalog revision each saved choice set was made against.
    catalog_reviews: Mapping[str, int] | None = None
    # Command ids for the flagged tool names, resolved before the write lock.
    catalog_change_ids: Mapping[str, str] | None = None


_CAPABILITY_ERRORS = frozenset(
    {"invalid_capabilities", "capabilities_require_cli_surface", "capabilities_require_allowed_grant"}
)


class StoreCustomExtensionContinuityMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

        def _native_store_call(
            self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
        ) -> Any: ...

    def apply_custom_extension_continuity_transaction(
        self,
        *,
        expected_revision: int,
        authority_updates: Sequence[tuple[UnlistedCliIdentity, str, Mapping[str, LocalCliCommandState]]],
        sync_payloads: Mapping[str, Mapping[str, object]],
        events: Sequence[tuple[str, Mapping[str, object]]],
        updated_at: str,
        sync_preconditions: Mapping[str, object] | None = None,
        observation_preconditions: Mapping[str, object] | None = None,
        provider_updates: Mapping[str, Sequence[ProviderUpdate]] | None = None,
        catalog_seeds: Mapping[str, Sequence[LocalCliCommand]] | None = None,
        capability_updates: Mapping[str, Mapping[str, str]] | None = None,
        catalog_reviews: Mapping[str, int] | None = None,
    ) -> int:
        """Commit exact local authority, continuity state, and receipts together.

        The native store writes all of it in one ``begin immediate``. Payloads
        and events are encoded here so the stored text is what ``json.dumps``
        writes.
        """

        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            change_ids = catalog_change_ids(connection, catalog_reviews or {})
        args = continuity_wire(
            expected_revision=expected_revision,
            authority_updates=authority_updates,
            sync_payloads=sync_payloads,
            events=events,
            updated_at=updated_at,
            sync_preconditions=sync_preconditions,
            observation_preconditions=observation_preconditions,
            provider_updates=provider_updates,
            catalog_seeds=catalog_seeds,
            capability_updates=capability_updates,
            catalog_reviews=catalog_reviews,
            catalog_change_ids=change_ids,
        )
        return _native_grant_write(self, "apply_custom_extension_continuity", args)


def continuity_wire(
    *,
    expected_revision: int,
    authority_updates: Sequence[tuple[UnlistedCliIdentity, str, Mapping[str, LocalCliCommandState]]],
    sync_payloads: Mapping[str, Mapping[str, object]],
    events: Sequence[tuple[str, Mapping[str, object]]],
    updated_at: str,
    sync_preconditions: Mapping[str, object] | None,
    observation_preconditions: Mapping[str, object] | None,
    provider_updates: Mapping[str, Sequence[ProviderUpdate]] | None,
    catalog_seeds: Mapping[str, Sequence[LocalCliCommand]] | None,
    capability_updates: Mapping[str, Mapping[str, str]] | None,
    catalog_reviews: Mapping[str, int] | None,
    catalog_change_ids: Mapping[str, str] | None,
) -> dict[str, object]:
    """The native ``apply_custom_extension_continuity`` arguments.

    Payloads and events are encoded here so the stored text is what
    ``json.dumps`` writes.
    """

    return {
        "expected_revision": expected_revision,
        "updated_at": updated_at,
        "updates": [
            {
                "cli_id": identity.cli_id,
                "identity_hash": identity.identity_hash,
                "state": state,
                "command_states": dict(command_states),
            }
            for identity, state, command_states in authority_updates
        ],
        "provider_updates": {
            cli_id: [list(update) for update in updates] for cli_id, updates in (provider_updates or {}).items()
        },
        "capability_updates": {cli_id: dict(choices) for cli_id, choices in (capability_updates or {}).items()},
        "catalog_reviews": dict(catalog_reviews or {}),
        "catalog_change_ids": dict(catalog_change_ids or {}),
        "catalog_seeds": {
            cli_id: [_command_wire(command) for command in commands]
            for cli_id, commands in (catalog_seeds or {}).items()
        },
        "sync_preconditions": dict(sync_preconditions or {}),
        "observation_preconditions": dict(observation_preconditions or {}),
        "sync_payloads": {state_key: json.dumps(payload) for state_key, payload in sync_payloads.items()},
        "events": [[event_name, json.dumps(payload)] for event_name, payload in events],
    }


def mutation_wire(mutation: CustomExtensionContinuityMutation) -> dict[str, object]:
    """The native arguments of a preflighted mutation that joins policy activation."""

    return continuity_wire(
        expected_revision=mutation.expected_revision,
        authority_updates=mutation.authority_updates,
        sync_payloads=mutation.sync_payloads,
        events=mutation.events,
        updated_at=mutation.updated_at,
        sync_preconditions=mutation.sync_preconditions,
        observation_preconditions=mutation.observation_preconditions,
        provider_updates=mutation.provider_updates,
        catalog_seeds=mutation.catalog_seeds,
        capability_updates=mutation.capability_updates,
        catalog_reviews=mutation.catalog_reviews,
        catalog_change_ids=mutation.catalog_change_ids,
    )


def _command_wire(command: LocalCliCommand) -> dict[str, object]:
    return {
        "command_id": command.command_id,
        "name": command.name,
        "usage": command.usage,
        "description": command.description,
        "parent_id": command.parent_id,
    }


def _native_grant_write(store: Any, method: str, args: Mapping[str, object]) -> int:
    try:
        revision = store._native_store_call(method, args)
    except ValueError as error:
        if str(error) in _CAPABILITY_ERRORS:
            raise LocalCliCapabilityError(str(error)) from error
        raise
    if type(revision) is not int:
        raise ValueError("invalid local CLI row")
    return revision


def _local_cli_observation_snapshot(connection: sqlite3.Connection, cli_id: str) -> dict[str, object] | None:
    row = connection.execute(
        """
        select identity_hash, kind, name, interpreter_name, example_label, observed_count, surface
        from local_cli_observation where cli_id = ?
        """,
        (cli_id,),
    ).fetchone()
    if row is None:
        return None
    command_rows = connection.execute(
        "select command_id from local_cli_command where cli_id = ? order by sort_index asc, command_id asc",
        (cli_id,),
    ).fetchall()
    return {
        "identity_hash": row["identity_hash"],
        "kind": row["kind"],
        "name": row["name"],
        "interpreter_name": row["interpreter_name"],
        "example_label": row["example_label"],
        "observed_count": row["observed_count"],
        "surface": row["surface"],
        "command_ids": [str(command_row["command_id"]) for command_row in command_rows],
    }


def _row_int(value: object) -> int:
    if type(value) is not int:
        raise ValueError("invalid local CLI row")
    return value
