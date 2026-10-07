"""Persistence for observed unlisted CLIs and this-device grants."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING

from .local_cli_errors import LocalCliCatalogLimitError
from .runtime.local_cli_commands import (
    LocalCliCommand,
    LocalCliCommandState,
    is_local_cli_command_id,
    is_local_cli_command_state,
    local_cli_command_state,
)
from .runtime.local_cli_identity import UnlistedCliIdentity, is_local_cli_id
from .runtime.local_mcp_stdio import McpCatalogResult
from .runtime.mcp_classification import classify_mcp_action
from .store_custom_extension_continuity import _write_local_cli_grant
from .store_local_cli_rows import (
    _grant_from_row,
    _merge_item,
    _observation_from_row,
    _row_int,
    _row_text,
    _row_values,
    _with_suggestable,
)
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_catalog import load_mcp_catalogs, review_catalog_changes, write_mcp_catalog
from .store_mcp_provider_catalog import load_provider_catalog_summaries


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
        surface_value = surface if surface in {"cli", "mcp", "package-scripts"} else "cli"
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
                       server_identity_hash, source_label, server_command
                from local_cli_observation
                order by last_seen_at desc, cli_id asc
                """
            ).fetchall()
            grant_rows = connection.execute(
                "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant"
            ).fetchall()
            revision_row = connection.execute("select revision from local_cli_authority where singleton = 1").fetchone()
            command_map = _load_commands_by_cli(connection)
            catalog_map = load_mcp_catalogs(connection)
            provider_map = load_provider_catalog_summaries(connection)
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
                        "source_label": None,
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
            catalog = catalog_map.get(str(item["cli_id"]))
            if catalog is not None and item.get("surface") == "mcp" and catalog[0] == item.get("identity_hash"):
                item["mcp_catalog"] = catalog[1]
                definitions = catalog[1].get("tools")
                by_name = (
                    {
                        tool["name"]: tool
                        for tool in definitions
                        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
                    }
                    if isinstance(definitions, list)
                    else {}
                )
                for command in command_map.get(str(item["cli_id"]), []):
                    definition = by_name.get(command.get("usage"))
                    if definition is not None:
                        command["classification"] = classify_mcp_action(
                            str(definition["name"]),
                            definition.get("inputSchema"),
                            annotations=definition.get("annotations"),
                        )
            if str(item["cli_id"]) in provider_map:
                item["provider_catalog"] = provider_map[str(item["cli_id"])]
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
            next_revision = _write_local_cli_grant(
                connection,
                identity=identity,
                state=state,
                current_revision=current_revision,
                updated_at=updated_at,
                command_states=command_states,
            )
        return next_revision

    def replace_local_cli_commands(
        self,
        cli_id: str,
        commands: Sequence[LocalCliCommand],
        *,
        mcp_catalog: McpCatalogResult | None = None,
        identity_hash: str | None = None,
        seen_at: str | None = None,
        expected_catalog_revision: int | None = None,
    ) -> None:
        if not is_local_cli_id(cli_id):
            raise ValueError("invalid local CLI id")
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            connection.commit()
            connection.execute("begin immediate")
            review_ids = (
                write_mcp_catalog(
                    connection,
                    cli_id,
                    identity_hash=identity_hash,
                    catalog=mcp_catalog,
                    seen_at=seen_at,
                    expected_revision=expected_catalog_revision,
                )
                if mcp_catalog is not None
                else set()
            )
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
            review_catalog_changes(connection, cli_id, review_ids, known, seen_at)
            existing = connection.execute(
                "select command_id, state from local_cli_command_grant where cli_id = ?",
                (cli_id,),
            ).fetchall()
            for row in existing:
                command_id, state = _row_values(row, 2)
                command_id = str(command_id)
                if mcp_catalog is not None and state in {"block", "review"}:
                    continue
                if command_id not in known:
                    _ = connection.execute(
                        "delete from local_cli_command_grant where cli_id = ? and command_id = ?",
                        (cli_id, command_id),
                    )

    def merge_local_cli_commands(
        self,
        cli_id: str,
        commands: Sequence[LocalCliCommand],
        *,
        limit: int,
        mcp_catalog: McpCatalogResult | None = None,
        identity_hash: str | None = None,
        seen_at: str | None = None,
        expected_catalog_revision: int | None = None,
    ) -> None:
        """Append observed tools atomically without deleting existing choices."""
        if not is_local_cli_id(cli_id) or limit < 1:
            raise ValueError("invalid local CLI catalog")
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            connection.commit()
            connection.execute("begin immediate")
            review_ids = (
                write_mcp_catalog(
                    connection,
                    cli_id,
                    identity_hash=identity_hash,
                    catalog=mcp_catalog,
                    seen_at=seen_at,
                    expected_revision=expected_catalog_revision,
                )
                if mcp_catalog is not None
                else set()
            )
            rows = connection.execute(
                "select command_id from local_cli_command where cli_id = ?",
                (cli_id,),
            ).fetchall()
            known = {str(row[0]) for row in rows}
            if any(not is_local_cli_command_id(command.command_id) for command in commands):
                raise ValueError("invalid local CLI command id")
            incoming = {command.command_id for command in commands}
            if len(known | incoming) > limit:
                raise LocalCliCatalogLimitError("local_cli_catalog_limit")
            for command in commands:
                if command.command_id in known:
                    continue
                connection.execute(
                    """insert into local_cli_command
                    (cli_id, command_id, name, usage, description, parent_id, sort_index)
                    values (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        cli_id,
                        command.command_id,
                        command.name[:120],
                        command.usage[:160],
                        command.description[:240],
                        command.parent_id,
                        len(known),
                    ),
                )
                known.add(command.command_id)
            review_catalog_changes(connection, cli_id, review_ids, known, seen_at)

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
            return _read_command_catalog(connection, cli_id)

    def read_local_cli_command_states(self, cli_id: str) -> dict[str, LocalCliCommandState]:
        if not is_local_cli_id(cli_id):
            return {}
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            return _read_command_states(connection, cli_id)


def _command_id_filter(command_ids: Sequence[str] | None) -> tuple[str, tuple[str, ...]]:
    if command_ids is None:
        return "", ()
    if not command_ids:
        # An empty filter must never turn into a full permission read.
        return " and 0", ()
    return f" and command_id in ({','.join('?' for _ in command_ids)})", tuple(command_ids)


def _read_command_catalog(
    connection: sqlite3.Connection, cli_id: str, command_ids: Sequence[str] | None = None
) -> list[LocalCliCommand]:
    selection, parameters = _command_id_filter(command_ids)
    rows = connection.execute(
        f"""
        select command_id, name, usage, description, parent_id
        from local_cli_command
        where cli_id = ?{selection}
        order by sort_index asc, command_id asc
        """,
        (cli_id, *parameters),
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
                    parent_id=parent_id,
                )
            )
    return catalog


def _read_command_states(
    connection: sqlite3.Connection, cli_id: str, command_ids: Sequence[str] | None = None
) -> dict[str, LocalCliCommandState]:
    selection, parameters = _command_id_filter(command_ids)
    rows = connection.execute(
        f"select command_id, state from local_cli_command_grant where cli_id = ?{selection}",
        (cli_id, *parameters),
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
    if "review" in states.values():
        row = connection.execute("select surface from local_cli_observation where cli_id = ?", (cli_id,)).fetchone()
        if row is None or _row_values(row, 1)[0] != "mcp":
            raise ValueError("explicit review is supported only for MCP tools")
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
