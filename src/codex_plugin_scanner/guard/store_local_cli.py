"""Persistence for observed unlisted CLIs and this-device grants."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any, cast

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
from .runtime.mcp_classification import McpClassificationUnavailableError, classify_mcp_actions
from .store_custom_extension_continuity import _write_local_cli_grant
from .store_local_cli_capabilities import LocalCliCapabilityState, capability_map, load_local_cli_capabilities
from .store_local_cli_context import implied_capabilities, note_capability_cause
from .store_local_cli_retention import mark_shared_enrolled_servers, utc_now_iso
from .store_local_cli_rows import (
    _grant_from_row,
    _merge_item,
    _observation_from_row,
    _row_int,
    _row_text,
    _row_values,
    _with_suggestions,
    local_cli_rules_exist,
)
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_catalog import load_mcp_catalogs
from .store_mcp_provider_catalog import load_provider_catalog_summaries

if TYPE_CHECKING:
    from .store import GuardStore


def _catalog_args(
    cli_id: str,
    commands: Sequence[LocalCliCommand],
    *,
    mcp_catalog: McpCatalogResult | None,
    identity_hash: str | None,
    seen_at: str | None,
    expected_catalog_revision: int | None,
) -> dict[str, object]:
    """The wire shape both catalog writes share."""
    return {
        "cli_id": cli_id,
        "commands": [
            {
                "command_id": command.command_id,
                "name": command.name,
                "usage": command.usage,
                "description": command.description,
                "parent_id": command.parent_id,
            }
            for command in commands
        ],
        "identity_hash": identity_hash,
        "seen_at": seen_at,
        "expected_catalog_revision": expected_catalog_revision,
        "mcp_catalog": None if mcp_catalog is None else _catalog_payload(mcp_catalog),
    }


def _catalog_payload(catalog: McpCatalogResult) -> dict[str, object]:
    return {
        "tools": list(catalog.tools),
        "complete": catalog.complete,
        "reason": catalog.reason,
        "pages": catalog.pages,
        "protocol_version": catalog.protocol_version,
        "server_info": catalog.server_info,
        "capabilities": catalog.capabilities,
        "cache_ttl_ms": catalog.cache_ttl_ms,
        "cache_scope": catalog.cache_scope,
        "cache_received_at": catalog.cache_received_at,
        "skills": list(catalog.skills),
        "skills_complete": catalog.skills_complete,
        "skills_reason": catalog.skills_reason,
    }


class StoreLocalCliMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

        def _native_store_call(
            self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
        ) -> Any: ...

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
        only_if_missing: bool = False,
        replayed_at: str | None = None,
    ) -> None:
        _ = self._native_store_call(
            "record_local_cli_observation",
            {
                "cli_id": identity.cli_id,
                "identity_hash": identity.identity_hash,
                "kind": identity.kind,
                "name": identity.name,
                "interpreter_name": identity.interpreter_name,
                "example_label": identity.example_label,
                "seen_at": seen_at,
                "source_path": source_path,
                "help_status": help_status,
                "surface": surface,
                "server_identity_hash": server_identity_hash,
                "server_command": server_command,
                "server_args_hash": server_args_hash,
                "only_if_missing": only_if_missing,
                "replayed_at": replayed_at,
                "clock": utc_now_iso(),
            },
        )

    def list_local_cli_items(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            observation_rows = connection.execute(
                """
                select cli_id, identity_hash, kind, name, interpreter_name, example_label,
                       observed_count, last_seen_at, source_path, help_status, surface,
                       server_identity_hash, source_label, server_command,
                       remote_origin, declared_sources_json
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
            capability_rows = load_local_cli_capabilities(connection)
            implied = implied_capabilities(connection)
        grants = {_row_text(row, 0): _grant_from_row(row) for row in grant_rows}
        items: list[dict[str, object]] = []
        seen: set[str] = set()
        for row in observation_rows:
            item = _observation_from_row(row)
            cli_id = str(item["cli_id"])
            seen.add(cli_id)
            grant = grants.get(cli_id)
            items.append(_merge_item(item, grant))
        for cli_id, grant in sorted(grants.items()):
            if cli_id in seen:
                continue
            items.append(
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
        _with_suggestions(items)
        undescribed: list[tuple[dict[str, object], Mapping[str, object]]] = []
        mark_shared_enrolled_servers(items, grants)
        authority_revision = 0 if revision_row is None else _row_int(revision_row[0])
        for item in items:
            item["authority_revision"] = authority_revision
            item["commands"] = command_map.get(str(item["cli_id"]), [])
            # Capabilities exist only for a CLI connector; absent reads as off.
            item["capabilities"] = (
                capability_map(capability_rows.get(str(item["cli_id"]))) if item.get("surface") == "cli" else {}
            )
            suggested = _suggested_capability(item, implied.get(str(item["cli_id"])))
            if suggested is not None:
                item["suggested_capability"] = suggested
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
                        undescribed.append((command, definition))
            if str(item["cli_id"]) in provider_map:
                item["provider_catalog"] = provider_map[str(item["cli_id"])]
        try:
            described = classify_mcp_actions(
                [
                    {
                        "name": str(definition["name"]),
                        "schema": definition.get("inputSchema"),
                        "annotations": definition.get("annotations"),
                    }
                    for _, definition in undescribed
                ],
                guard_home=cast("GuardStore", self).guard_home,
            )
        except McpClassificationUnavailableError:
            # The classification is advisory display evidence. Without the
            # resident it is simply absent: listing a CLI, its identity and its
            # grant state never depended on it.
            return items
        for (command, _), classification in zip(undescribed, described, strict=True):
            if classification is not None:
                command["classification"] = classification
        return items

    def read_local_cli_surface(self, cli_id: str) -> str | None:
        """The observed surface of ``cli_id``, or ``None`` when never observed."""

        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            row = connection.execute("select surface from local_cli_observation where cli_id = ?", (cli_id,)).fetchone()
        return None if row is None or not isinstance(row[0], str) else row[0]

    def note_local_cli_capability_cause(self, *, cli_id: str, identity_hash: str, cause: str) -> int:
        """Keep the capability cause a contained run of an allowed CLI was denied."""

        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            return note_capability_cause(connection, cli_id=cli_id, identity_hash=identity_hash, cause=cause)

    def read_local_cli_capabilities(self, cli_id: str) -> dict[str, LocalCliCapabilityState]:
        """The full ``{name: on|off}`` map stored for ``cli_id``."""

        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            return capability_map(load_local_cli_capabilities(connection).get(cli_id))

    def read_local_cli_grant(self, cli_id: str) -> dict[str, object] | None:
        grant = self._native_store_call("read_local_cli_grant", {"cli_id": cli_id})
        if grant is not None and not isinstance(grant, dict):
            raise sqlite3.DatabaseError("native_local_cli_grant_invalid")
        return grant

    def has_local_cli_block_rules(self) -> bool:
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            return local_cli_rules_exist(connection, blocks_only=True)

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
        reviewed_catalog_revision: int | None = None,
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
                reviewed_catalog_revision=reviewed_catalog_revision,
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
        _ = self._native_store_call(
            "replace_local_cli_commands",
            _catalog_args(
                cli_id,
                commands,
                mcp_catalog=mcp_catalog,
                identity_hash=identity_hash,
                seen_at=seen_at,
                expected_catalog_revision=expected_catalog_revision,
            ),
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
        args = _catalog_args(
            cli_id,
            commands,
            mcp_catalog=mcp_catalog,
            identity_hash=identity_hash,
            seen_at=seen_at,
            expected_catalog_revision=expected_catalog_revision,
        )
        args["limit"] = limit
        try:
            _ = self._native_store_call("merge_local_cli_commands", args)
        except ValueError as error:
            # The runtime reports the bound as the same message the Python
            # owner raised; callers select on the type, not the text.
            if str(error) == "local_cli_catalog_limit":
                raise LocalCliCatalogLimitError("local_cli_catalog_limit") from error
            raise

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
        rows = self._native_store_call("read_local_cli_command_catalog", {"cli_id": cli_id})
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise sqlite3.DatabaseError("native_local_cli_command_catalog_invalid")
        return [LocalCliCommand(**row) for row in rows]

    def read_local_cli_command_states(self, cli_id: str) -> dict[str, LocalCliCommandState]:
        states = self._native_store_call("read_local_cli_command_states", {"cli_id": cli_id})
        if not isinstance(states, dict):
            raise sqlite3.DatabaseError("native_local_cli_command_states_invalid")
        return {
            command_id: state
            for command_id, raw_state in states.items()
            if (state := local_cli_command_state(raw_state)) is not None
        }


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


def _suggested_capability(item: Mapping[str, object], implied: tuple[str, str] | None) -> str | None:
    """The capability an allowed CLI's recorded cause points at while it is still off."""

    if implied is None or item.get("state") != "allowed" or item.get("stale") is True:
        return None
    identity_hash, capability = implied
    if identity_hash != item.get("identity_hash"):
        return None
    capabilities = item.get("capabilities")
    on = isinstance(capabilities, Mapping) and capabilities.get(capability) == "on"
    return None if on else capability
