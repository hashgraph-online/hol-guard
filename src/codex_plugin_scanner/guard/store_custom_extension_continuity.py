"""Crash-atomic persistence for custom Extension continuity."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .runtime.local_cli_commands import (
    LocalCliCommandState,
    is_local_cli_command_id,
    is_local_cli_command_state,
)
from .runtime.local_cli_identity import UnlistedCliIdentity, is_local_cli_id
from .store_local_cli_schema import ensure_local_cli_schema


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


class StoreCustomExtensionContinuityMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

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
    ) -> int:
        """Commit exact local authority, continuity state, and receipts together."""

        mutation = CustomExtensionContinuityMutation(
            expected_revision=expected_revision,
            authority_updates=tuple(authority_updates),
            sync_payloads=sync_payloads,
            events=tuple(events),
            updated_at=updated_at,
            sync_preconditions=sync_preconditions or {},
            observation_preconditions=observation_preconditions or {},
        )
        with self._connect() as connection:
            _ = connection.execute("begin immediate")
            return apply_custom_extension_continuity_mutation_locked(
                connection,
                mutation,
                boundary=self._custom_extension_continuity_transaction_boundary,
            )

    def _custom_extension_continuity_transaction_boundary(self, _stage: str) -> None:
        """Fault-injection seam; production deliberately performs no work here."""


def apply_custom_extension_continuity_mutation_locked(
    connection: sqlite3.Connection,
    mutation: CustomExtensionContinuityMutation,
    *,
    boundary: Callable[[str], None] = lambda _stage: None,
) -> int:
    """Apply a preflighted mutation inside an existing immediate transaction."""

    _validate_authority_updates(mutation.authority_updates)
    ensure_local_cli_schema(connection)
    current_revision = _authority_revision(connection)
    if current_revision != mutation.expected_revision:
        raise ValueError("local_cli_revision_conflict")
    _require_sync_preconditions(connection, mutation.sync_preconditions)
    _require_observation_preconditions(connection, mutation.observation_preconditions)
    for identity, state, command_states in mutation.authority_updates:
        current_revision = _write_local_cli_grant(
            connection,
            identity=identity,
            state=state,
            current_revision=current_revision,
            updated_at=mutation.updated_at,
            command_states=command_states,
        )
    boundary("after_authority")
    _write_sync_payloads(connection, mutation.sync_payloads, updated_at=mutation.updated_at)
    boundary("after_sync_state")
    _write_events(connection, mutation.events, occurred_at=mutation.updated_at)
    boundary("after_event")
    return current_revision


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
) -> int:
    from .store_local_cli import _write_command_states

    next_revision = current_revision + 1
    if state == "unset":
        _ = connection.execute("delete from local_cli_grant where cli_id = ?", (identity.cli_id,))
        _ = connection.execute("delete from local_cli_command_grant where cli_id = ?", (identity.cli_id,))
    else:
        _upsert_grant(connection, identity=identity, state=state, revision=next_revision, updated_at=updated_at)
        if command_states is not None:
            _ = connection.execute("delete from local_cli_command_grant where cli_id = ?", (identity.cli_id,))
            _write_command_states(connection, identity.cli_id, command_states)
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
