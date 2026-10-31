"""Persistence for observed unlisted CLIs and this-device grants."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Any

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
from .store_custom_extension_continuity import _write_local_cli_grant
from .store_local_cli_capabilities import LocalCliCapabilityState, capability_map, load_local_cli_capabilities
from .store_local_cli_context import note_capability_cause
from .store_local_cli_retention import utc_now_iso
from .store_local_cli_rows import _row_int, _row_values, local_cli_rules_exist
from .store_local_cli_schema import ensure_local_cli_schema

# How many times one listing starts over because the inventory changed between
# its pages. Each restart means a connector was observed or granted mid-walk;
# a store still changing after this many is reported rather than read forever.
_LIST_RESTART_LIMIT = 4


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
        """Every observed CLI and this-device grant, as the resident assembles it.

        A connector carries its whole command catalog, so a device with many
        of them holds more inventory than one reply may frame. The resident
        answers a page at a time, names the offset the next page starts at and
        the snapshot of the list those offsets index into. Each later page
        sends that snapshot back; when the list changed in between, the
        resident asks for a restart rather than letting the walk skip or
        repeat an item.
        """

        items: list[dict[str, object]] = []
        offset = 0
        snapshot: str | None = None
        restarts = 0
        while True:
            args: dict[str, object] = {"offset": offset}
            if snapshot is not None:
                args["snapshot"] = snapshot
            page = self._native_store_call("list_local_cli_items", args)
            if not isinstance(page, dict) or not isinstance(page.get("snapshot"), str):
                raise sqlite3.DatabaseError("native_local_cli_items_invalid")
            if page.get("restart") is True:
                restarts += 1
                if restarts > _LIST_RESTART_LIMIT:
                    raise sqlite3.DatabaseError("native_local_cli_items_unsettled")
                items, offset, snapshot = [], 0, page["snapshot"]
                continue
            snapshot = page["snapshot"]
            listed = page.get("items")
            if not isinstance(listed, list) or any(not isinstance(item, dict) for item in listed):
                raise sqlite3.DatabaseError("native_local_cli_items_invalid")
            items.extend(listed)
            following = page.get("next_offset")
            if following is None:
                return items
            if type(following) is not int or following <= offset or not listed:
                raise sqlite3.DatabaseError("native_local_cli_items_invalid")
            offset = following

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
