"""Persistence for observed unlisted CLIs and this-device grants."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, cast

from .runtime.local_cli_commands import (
    LocalCliCommand,
    LocalCliCommandState,
    is_local_cli_command_id,
    is_local_cli_command_state,
    local_cli_command_state,
)
from .runtime.local_cli_identity import UnlistedCliIdentity, is_local_cli_id, is_suggestable_custom_tool
from .store_local_cli_schema import ensure_local_cli_schema


class StoreLocalCliMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def record_local_cli_observation(
        self,
        identity: UnlistedCliIdentity,
        *,
        seen_at: str,
        source_path: str | None = None,
        help_status: str | None = None,
        surface: str = "cli",
        server_identity_hash: str | None = None,
        server_command: str | None = None,
        server_args_hash: str | None = None,
    ) -> None:
        if not is_local_cli_id(identity.cli_id):
            raise ValueError("invalid local CLI id")
        surface_value = surface if surface in {"cli", "mcp"} else "cli"
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            current = connection.execute(
                "select observed_count from local_cli_observation where cli_id = ?",
                (identity.cli_id,),
            ).fetchone()
            if current is None:
                _ = connection.execute(
                    """
                    insert into local_cli_observation (
                        cli_id, identity_hash, kind, name, interpreter_name, example_label,
                        observed_count, last_seen_at, source_path, help_status, surface,
                        server_identity_hash, server_command, server_args_hash
                    ) values (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identity.cli_id,
                        identity.identity_hash,
                        identity.kind,
                        identity.name,
                        identity.interpreter_name,
                        identity.example_label,
                        seen_at,
                        source_path,
                        help_status,
                        surface_value,
                        server_identity_hash,
                        server_command,
                        server_args_hash,
                    ),
                )
                return
            _ = connection.execute(
                """
                update local_cli_observation
                set identity_hash = ?, kind = ?, name = ?, interpreter_name = ?,
                    example_label = ?, observed_count = observed_count + 1, last_seen_at = ?,
                    source_path = coalesce(?, source_path),
                    help_status = coalesce(?, help_status),
                    surface = ?,
                    server_identity_hash = coalesce(?, server_identity_hash),
                    server_command = coalesce(?, server_command),
                    server_args_hash = coalesce(?, server_args_hash)
                where cli_id = ?
                """,
                (
                    identity.identity_hash,
                    identity.kind,
                    identity.name,
                    identity.interpreter_name,
                    identity.example_label,
                    seen_at,
                    source_path,
                    help_status,
                    surface_value,
                    server_identity_hash,
                    server_command,
                    server_args_hash,
                    identity.cli_id,
                ),
            )

    def list_local_cli_items(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            observation_rows = connection.execute(
                """
                select cli_id, identity_hash, kind, name, interpreter_name, example_label,
                       observed_count, last_seen_at, source_path, help_status, surface,
                       server_identity_hash
                from local_cli_observation
                order by last_seen_at desc, cli_id asc
                """
            ).fetchall()
            grant_rows = connection.execute(
                "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant"
            ).fetchall()
            revision_row = connection.execute("select revision from local_cli_authority where singleton = 1").fetchone()
            command_map = _load_commands_by_cli(connection)
        grants = {_row_text(row, 0): _grant_from_row(row) for row in grant_rows}
        items: list[dict[str, object]] = []
        seen: set[str] = set()
        for row in observation_rows:
            item = _observation_from_row(row)
            cli_id = str(item["cli_id"])
            seen.add(cli_id)
            grant = grants.get(cli_id)
            items.append(_with_suggestable(_merge_item(item, grant)))
        for cli_id, grant in sorted(grants.items()):
            if cli_id in seen:
                continue
            items.append(
                _with_suggestable(
                    {
                        "cli_id": cli_id,
                        "name": cli_id.removeprefix("local-cli."),
                        "kind": "executable",
                        "identity_hash": grant["identity_hash"],
                        "example_label": cli_id.removeprefix("local-cli."),
                        "interpreter_name": None,
                        "observed_count": 0,
                        "last_seen_at": None,
                        "source_path": None,
                        "help_status": None,
                        "surface": "cli",
                        "server_identity_hash": None,
                        "state": grant["state"],
                        "stale": False,
                        "grant_revision": grant["revision"],
                    }
                )
            )
        authority_revision = 0 if revision_row is None else _row_int(revision_row[0])
        for item in items:
            item["authority_revision"] = authority_revision
            item["commands"] = command_map.get(str(item["cli_id"]), [])
        return items

    def read_local_cli_grant(self, cli_id: str) -> dict[str, object] | None:
        if not is_local_cli_id(cli_id):
            return None
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            row = connection.execute(
                "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant where cli_id = ?",
                (cli_id,),
            ).fetchone()
        return None if row is None else _grant_from_row(row)

    def read_local_cli_revision(self) -> int:
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            row = connection.execute("select revision from local_cli_authority where singleton = 1").fetchone()
        return 0 if row is None else _row_int(row[0])

    def upsert_local_cli_grant(
        self,
        *,
        identity: UnlistedCliIdentity,
        state: str,
        expected_revision: int,
        updated_at: str,
        command_states: Mapping[str, LocalCliCommandState] | None = None,
    ) -> int:
        if state not in {"allowed", "blocked", "unset"}:
            raise ValueError("invalid local CLI grant state")
        if not is_local_cli_id(identity.cli_id):
            raise ValueError("invalid local CLI id")
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            current = connection.execute("select revision from local_cli_authority where singleton = 1").fetchone()
            current_revision = 0 if current is None else _row_int(current[0])
            if current_revision != expected_revision:
                raise ValueError("local_cli_revision_conflict")
            next_revision = current_revision + 1
            if state == "unset":
                _ = connection.execute("delete from local_cli_grant where cli_id = ?", (identity.cli_id,))
                _ = connection.execute("delete from local_cli_command_grant where cli_id = ?", (identity.cli_id,))
            else:
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
                    (identity.cli_id, identity.identity_hash, state, next_revision, updated_at),
                )
            _ = connection.execute(
                "update local_cli_authority set revision = ? where singleton = 1",
                (next_revision,),
            )
            if state != "unset" and command_states:
                _write_command_states(connection, identity.cli_id, command_states)
        return next_revision

    def replace_local_cli_commands(self, cli_id: str, commands: Sequence[LocalCliCommand]) -> None:
        if not is_local_cli_id(cli_id):
            raise ValueError("invalid local CLI id")
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
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
            known = {command.command_id for command in commands}
            existing = connection.execute(
                "select command_id from local_cli_command_grant where cli_id = ?",
                (cli_id,),
            ).fetchall()
            for row in existing:
                command_id = str(_row_values(row, 1)[0])
                if command_id not in known:
                    _ = connection.execute(
                        "delete from local_cli_command_grant where cli_id = ? and command_id = ?",
                        (cli_id, command_id),
                    )

    def upsert_local_cli_command_states(
        self,
        cli_id: str,
        states: Mapping[str, LocalCliCommandState],
    ) -> None:
        if not is_local_cli_id(cli_id):
            raise ValueError("invalid local CLI id")
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            _write_command_states(connection, cli_id, states)

    def read_local_cli_command_catalog(self, cli_id: str) -> list[LocalCliCommand]:
        if not is_local_cli_id(cli_id):
            return []
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            rows = connection.execute(
                """
                select command_id, name, usage, description, parent_id
                from local_cli_command
                where cli_id = ?
                order by sort_index asc, command_id asc
                """,
                (cli_id,),
            ).fetchall()
        catalog: list[LocalCliCommand] = []
        for row in rows:
            command_id, name, usage, description, parent_id = _row_values(row, 5)
            if (
                isinstance(command_id, str)
                and isinstance(name, str)
                and isinstance(usage, str)
                and isinstance(description, str)
                and (parent_id is None or isinstance(parent_id, str))
            ):
                catalog.append(
                    LocalCliCommand(
                        command_id=command_id,
                        name=name,
                        usage=usage,
                        description=description,
                        parent_id=parent_id if isinstance(parent_id, str) else None,
                    )
                )
        return catalog

    def read_local_cli_command_states(self, cli_id: str) -> dict[str, LocalCliCommandState]:
        if not is_local_cli_id(cli_id):
            return {}
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            rows = connection.execute(
                "select command_id, state from local_cli_command_grant where cli_id = ?",
                (cli_id,),
            ).fetchall()
        states: dict[str, LocalCliCommandState] = {}
        for row in rows:
            command_id, raw_state = _row_values(row, 2)
            parsed_state = local_cli_command_state(raw_state)
            if isinstance(command_id, str) and parsed_state is not None:
                states[command_id] = parsed_state
        return states


def _write_command_states(
    connection: sqlite3.Connection,
    cli_id: str,
    states: Mapping[str, LocalCliCommandState],
) -> None:
    known = {
        str(_row_values(row, 1)[0])
        for row in connection.execute(
            "select command_id from local_cli_command where cli_id = ?",
            (cli_id,),
        ).fetchall()
    }
    for command_id, state in states.items():
        if command_id not in known or not is_local_cli_command_id(command_id):
            raise ValueError("invalid local CLI command id")
        if not is_local_cli_command_state(state):
            raise ValueError("invalid local CLI command state")
        _ = connection.execute(
            """
            insert into local_cli_command_grant (cli_id, command_id, state)
            values (?, ?, ?)
            on conflict(cli_id, command_id) do update set state = excluded.state
            """,
            (cli_id, command_id, state),
        )


def _load_commands_by_cli(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    catalog_rows = connection.execute(
        """
        select cli_id, command_id, name, usage, description, parent_id
        from local_cli_command
        order by cli_id asc, sort_index asc, command_id asc
        """
    ).fetchall()
    state_rows = connection.execute("select cli_id, command_id, state from local_cli_command_grant").fetchall()
    states: dict[tuple[str, str], str] = {}
    for row in state_rows:
        cli_id, command_id, state = _row_values(row, 3)
        if isinstance(cli_id, str) and isinstance(command_id, str) and isinstance(state, str):
            states[(cli_id, command_id)] = state
    grouped: dict[str, list[dict[str, object]]] = {}
    for row in catalog_rows:
        cli_id, command_id, name, usage, description, parent_id = _row_values(row, 6)
        if not isinstance(cli_id, str) or not isinstance(command_id, str):
            continue
        grouped.setdefault(cli_id, []).append(
            {
                "command_id": command_id,
                "name": name,
                "usage": usage,
                "description": description,
                "parent_id": parent_id,
                "state": states.get((cli_id, command_id), "inherit"),
            }
        )
    return grouped


def _with_suggestable(item: dict[str, object]) -> dict[str, object]:
    kind = item.get("kind")
    name = item.get("name")
    item["suggestable"] = (
        isinstance(kind, str)
        and isinstance(name, str)
        and is_suggestable_custom_tool(
            name=name,
            kind="script" if kind == "script" else "executable",
        )
    )
    return item


def _observation_from_row(row: object) -> dict[str, object]:
    values = _row_values(row, 12)
    surface = values[10] if values[10] in {"cli", "mcp"} else "cli"
    return {
        "cli_id": values[0],
        "identity_hash": values[1],
        "kind": values[2],
        "name": values[3],
        "interpreter_name": values[4],
        "example_label": values[5],
        "observed_count": values[6],
        "last_seen_at": values[7],
        "source_path": values[8],
        "help_status": values[9],
        "surface": surface,
        "server_identity_hash": values[11],
    }


def _grant_from_row(row: object) -> dict[str, object]:
    values = _row_values(row, 5)
    return {
        "cli_id": values[0],
        "identity_hash": values[1],
        "state": values[2],
        "revision": values[3],
        "updated_at": values[4],
    }


def _merge_item(observation: dict[str, object], grant: Mapping[str, object] | None) -> dict[str, object]:
    state = "unset"
    stale = False
    grant_revision = None
    if grant is not None:
        state = str(grant["state"])
        stale = str(grant["identity_hash"]) != str(observation["identity_hash"])
        grant_revision = grant["revision"]
    return {
        **observation,
        "state": state,
        "stale": stale,
        "grant_revision": grant_revision,
    }


def _row_values(row: object, count: int) -> tuple[object, ...]:
    if isinstance(row, sqlite3.Row):
        values = tuple(cast(object, row[index]) for index in range(count))
        if len(values) != count:
            raise ValueError("invalid local CLI row")
        return values
    if isinstance(row, tuple):
        values = cast(tuple[object, ...], row)
        if len(values) != count:
            raise ValueError("invalid local CLI row")
        return values
    raise ValueError("invalid local CLI row")


def _row_int(value: object) -> int:
    if type(value) is not int:
        raise ValueError("invalid local CLI row")
    return value


def _row_text(row: object, index: int) -> str:
    values = _row_values(row, 5)
    value = values[index]
    if not isinstance(value, str):
        raise ValueError("invalid local CLI row")
    return value
