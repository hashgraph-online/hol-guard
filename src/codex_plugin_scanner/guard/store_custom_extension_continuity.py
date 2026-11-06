"""Crash-atomic persistence for custom Extension continuity."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .runtime.local_cli_commands import (
    OTHER_COMMAND_ID,
    ROOT_COMMAND_ID,
    LocalCliCommand,
    LocalCliCommandState,
    is_local_cli_command_id,
    is_local_cli_command_state,
)
from .runtime.local_cli_identity import UnlistedCliIdentity, is_local_cli_id
from .store_local_cli_capabilities import (
    LocalCliCapabilityError,
    clear_local_cli_capabilities,
    write_local_cli_capabilities,
)
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_catalog import acknowledge_catalog_changes, catalog_change_ids
from .store_mcp_provider_permissions import ProviderUpdate, write_provider_choices


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
        args: dict[str, object] = {
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
            "catalog_change_ids": change_ids,
            "catalog_seeds": {
                cli_id: [_command_wire(command) for command in commands]
                for cli_id, commands in (catalog_seeds or {}).items()
            },
            "sync_preconditions": dict(sync_preconditions or {}),
            "observation_preconditions": dict(observation_preconditions or {}),
            "sync_payloads": {state_key: json.dumps(payload) for state_key, payload in sync_payloads.items()},
            "events": [[event_name, json.dumps(payload)] for event_name, payload in events],
        }
        return _native_grant_write(self, "apply_custom_extension_continuity", args)

    def _custom_extension_continuity_transaction_boundary(self, _stage: str) -> None:
        """Fault-injection seam for the policy activation path; production does no work here."""


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


def apply_custom_extension_continuity_mutation_locked(
    connection: sqlite3.Connection,
    mutation: CustomExtensionContinuityMutation,
    *,
    boundary: Callable[[str], None] = lambda _stage: None,
) -> int:
    """Apply a preflighted mutation inside an existing immediate transaction.

    Only policy activation still calls this, inside its own Python
    transaction; ``apply_custom_extension_continuity_transaction`` is native.
    """

    _validate_authority_updates(mutation.authority_updates)
    updated_ids = {identity.cli_id for identity, _, _ in mutation.authority_updates}
    if set(mutation.provider_updates or {}) - updated_ids:
        raise ValueError("provider choices require matching extension authority")
    if set(mutation.capability_updates or {}) - updated_ids:
        raise ValueError("capability choices require matching extension authority")
    ensure_local_cli_schema(connection)
    current_revision = _authority_revision(connection)
    if current_revision != mutation.expected_revision:
        raise ValueError("local_cli_revision_conflict")
    _require_sync_preconditions(connection, mutation.sync_preconditions)
    _require_observation_preconditions(connection, mutation.observation_preconditions)
    _seed_default_catalogs(connection, mutation.catalog_seeds or {})
    for identity, state, command_states in mutation.authority_updates:
        current_revision = _write_local_cli_grant(
            connection,
            identity=identity,
            state=state,
            current_revision=current_revision,
            updated_at=mutation.updated_at,
            command_states=command_states,
            reviewed_catalog_revision=(mutation.catalog_reviews or {}).get(identity.cli_id),
            catalog_change_ids=mutation.catalog_change_ids,
        )
        updates = (mutation.provider_updates or {}).get(identity.cli_id, ())
        if updates:
            if state == "unset":
                raise ValueError("provider choices cannot accompany removal")
            write_provider_choices(
                connection,
                cli_id=identity.cli_id,
                identity_hash=identity.identity_hash,
                updates=updates,
                updated_at=mutation.updated_at,
            )
        capabilities = (mutation.capability_updates or {}).get(identity.cli_id)
        if capabilities:
            if state == "unset":
                raise LocalCliCapabilityError("capabilities_require_allowed_grant")
            write_local_cli_capabilities(
                connection,
                cli_id=identity.cli_id,
                choices=capabilities,
                revision=current_revision,
                updated_at=mutation.updated_at,
            )
    boundary("after_authority")
    _write_sync_payloads(connection, mutation.sync_payloads, updated_at=mutation.updated_at)
    boundary("after_sync_state")
    _write_events(connection, mutation.events, occurred_at=mutation.updated_at)
    boundary("after_event")
    return current_revision


def _seed_default_catalogs(
    connection: sqlite3.Connection,
    seeds: Mapping[str, Sequence[LocalCliCommand]],
) -> None:
    """Store a curated catalog only where the stored one holds just the defaults.

    Runs after the revision check, so a rejected mutation leaves the catalog
    untouched. Default commands stay in the seed, so no saved rule is dropped.
    """

    for cli_id, commands in seeds.items():
        rows = connection.execute("select command_id from local_cli_command where cli_id = ?", (cli_id,)).fetchall()
        if any(str(row[0]) not in {ROOT_COMMAND_ID, OTHER_COMMAND_ID} for row in rows):
            continue
        if not {ROOT_COMMAND_ID, OTHER_COMMAND_ID} <= {command.command_id for command in commands}:
            raise ValueError("invalid local CLI catalog seed")
        _ = connection.execute("delete from local_cli_command where cli_id = ?", (cli_id,))
        for index, command in enumerate(commands):
            if not is_local_cli_command_id(command.command_id):
                raise ValueError("invalid local CLI command id")
            _ = connection.execute(
                """
                insert into local_cli_command (
                    cli_id, command_id, name, usage, description, parent_id, sort_index
                ) values (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cli_id,
                    command.command_id,
                    command.name[:120],
                    command.usage[:160],
                    command.description[:240],
                    command.parent_id,
                    index,
                ),
            )


def _validate_authority_updates(
    updates: Sequence[tuple[UnlistedCliIdentity, str, Mapping[str, LocalCliCommandState]]],
) -> None:
    for identity, state, command_states in updates:
        if not is_local_cli_id(identity.cli_id) or state not in {"allowed", "blocked", "unset"}:
            raise ValueError("invalid local CLI continuity update")
        if any(
            not is_local_cli_command_id(command_id) or not is_local_cli_command_state(command_state)
            for command_id, command_state in command_states.items()
        ):
            raise ValueError("invalid local CLI continuity command update")


def _authority_revision(connection: sqlite3.Connection) -> int:
    row = connection.execute("select revision from local_cli_authority where singleton = 1").fetchone()
    return 0 if row is None else _row_int(row[0])


def _require_sync_preconditions(connection: sqlite3.Connection, expected: Mapping[str, object]) -> None:
    for state_key, expected_payload in expected.items():
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (state_key,),
        ).fetchone()
        actual_payload: object = None if row is None else json.loads(str(row["payload_json"]))
        if actual_payload != expected_payload:
            raise ValueError("custom_extension_continuity_sync_precondition_changed")


def _require_observation_preconditions(connection: sqlite3.Connection, expected: Mapping[str, object]) -> None:
    for cli_id, expected_observation in expected.items():
        if _local_cli_observation_snapshot(connection, cli_id) != expected_observation:
            raise ValueError("custom_extension_continuity_observation_changed")


def _write_sync_payloads(
    connection: sqlite3.Connection,
    payloads: Mapping[str, Mapping[str, object]],
    *,
    updated_at: str,
) -> None:
    for state_key, payload in payloads.items():
        _ = connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at)
            values (?, ?, ?)
            on conflict(state_key) do update set
              payload_json = excluded.payload_json,
              updated_at = excluded.updated_at
            """,
            (state_key, json.dumps(payload), updated_at),
        )


def _write_events(
    connection: sqlite3.Connection,
    events: Sequence[tuple[str, Mapping[str, object]]],
    *,
    occurred_at: str,
) -> None:
    for event_name, payload in events:
        _ = connection.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, ?)",
            (event_name, json.dumps(payload), occurred_at),
        )


def _write_local_cli_grant(
    connection: sqlite3.Connection,
    *,
    identity: UnlistedCliIdentity,
    state: str,
    current_revision: int,
    updated_at: str,
    command_states: Mapping[str, LocalCliCommandState] | None,
    reviewed_catalog_revision: int | None = None,
    catalog_change_ids: Mapping[str, str] | None = None,
) -> int:
    from .store_local_cli import _write_command_states

    next_revision = current_revision + 1
    previous = connection.execute(
        "select identity_hash, state from local_cli_grant where cli_id = ?", (identity.cli_id,)
    ).fetchone()
    if state != "allowed" or previous is None or previous[0] != identity.identity_hash or previous[1] != state:
        # Capabilities were chosen for one exact allowed grant. A grant that is
        # blocked, reviewed, removed or re-identified, or that comes back from
        # such a state, never inherits rows (including salvaged orphans).
        clear_local_cli_capabilities(connection, identity.cli_id)
    if state == "unset":
        connection.execute("delete from local_mcp_provider_grant where cli_id = ?", (identity.cli_id,))
        _ = connection.execute("delete from local_cli_grant where cli_id = ?", (identity.cli_id,))
        _ = connection.execute("delete from local_cli_command_grant where cli_id = ?", (identity.cli_id,))
    else:
        _upsert_grant(connection, identity=identity, state=state, revision=next_revision, updated_at=updated_at)
        if command_states is not None:
            observation = connection.execute(
                "select surface from local_cli_observation where cli_id = ?",
                (identity.cli_id,),
            ).fetchone()
            if observation is not None and observation[0] == "mcp":
                # The visible payload omits retired tools. Preserve their Deny
                # and Ask tombstones while replacing choices for listed tools.
                connection.execute(
                    "delete from local_cli_command_grant where cli_id = ? "
                    "and (state not in ('block', 'review') or command_id in "
                    "(select command_id from local_cli_command where cli_id = ?))",
                    (identity.cli_id, identity.cli_id),
                )
            else:
                _ = connection.execute("delete from local_cli_command_grant where cli_id = ?", (identity.cli_id,))
            _write_command_states(connection, identity.cli_id, command_states)
            if observation is not None and observation[0] == "mcp" and reviewed_catalog_revision is not None:
                acknowledge_catalog_changes(
                    connection,
                    identity.cli_id,
                    identity.identity_hash,
                    set(command_states),
                    catalog_revision=reviewed_catalog_revision,
                    change_ids=catalog_change_ids or {},
                )
    _ = connection.execute("update local_cli_authority set revision = ? where singleton = 1", (next_revision,))
    return next_revision


def _upsert_grant(
    connection: sqlite3.Connection,
    *,
    identity: UnlistedCliIdentity,
    state: str,
    revision: int,
    updated_at: str,
) -> None:
    _ = connection.execute(
        """
        insert into local_cli_grant (cli_id, identity_hash, state, revision, updated_at)
        values (?, ?, ?, ?, ?)
        on conflict(cli_id) do update set
            identity_hash = excluded.identity_hash,
            state = excluded.state,
            revision = excluded.revision,
            updated_at = excluded.updated_at
        """,
        (identity.cli_id, identity.identity_hash, state, revision, updated_at),
    )


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
