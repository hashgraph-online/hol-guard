"""This-device MCP custom-extension grant lookup."""

from __future__ import annotations

import shlex
import sqlite3
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .runtime.approval_context import build_configured_environment_hash
from .runtime.composio_contract import composio_tool_role
from .runtime.composio_discovery import ComposioActionSchema
from .runtime.composio_workflows import ComposioWorkflowProposal
from .runtime.local_cli_commands import OTHER_COMMAND_ID, slug_local_cli_command_id
from .runtime.local_cli_identity import UnlistedCliIdentity, is_local_cli_id
from .runtime.mcp_protection import McpServerIdentity, build_mcp_server_identity, resolved_package_launcher_executable
from .runtime.observed_mcp_tools import ObservedMcpTool, observed_mcp_tool
from .store_local_cli import _grant_from_row, _read_command_catalog, _read_command_states, _row_values
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_catalog import read_mcp_skill_page, read_mcp_tool_authority
from .store_mcp_provider_catalog import read_provider_actions, write_composio_metadata

if TYPE_CHECKING:
    from .store import GuardStore


class StoreLocalMcpMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def read_mcp_provider_choices(self) -> dict[str, str]:
        from .store_mcp_provider_permissions import read_native_provider_choices

        with self._connect() as connection:
            connection.execute("begin")
            ensure_local_cli_schema(connection, for_read=True)
            return read_native_provider_choices(connection)

    def read_mcp_provider_authority_hash(self) -> str | None:
        from .store_mcp_provider_catalog import read_provider_authority

        with self._connect() as connection:
            connection.execute("begin")
            ensure_local_cli_schema(connection, for_read=True)
            return read_provider_authority(connection)

    def record_composio_discovery(
        self,
        source: ObservedMcpTool,
        actions: tuple[ComposioActionSchema, ...],
        *,
        seen_at: str,
        proposals: tuple[ComposioWorkflowProposal, ...] = (),
    ) -> str:
        if observed_mcp_tool(source.harness, source.qualified_name) != source or (
            composio_tool_role(source.qualified_name) != "discovery"
        ):
            raise ValueError("invalid provider discovery source")
        server = source.server_identity
        cli_id = self.ensure_local_mcp_observation(
            source.identity,
            seen_at=seen_at,
            server_identity_hash=server.identity_hash,
            server_command=server.command,
            server_args_hash=server.args_hash,
            source_label=f"{source.harness.title()} · observed provider metadata",
        )
        from .native_policy_snapshot import notify_native_policy_mutation

        barrier_closed = False
        guard_home = cast("GuardStore", self).guard_home

        def before_change() -> None:
            nonlocal barrier_closed
            barrier_closed = True
            notify_native_policy_mutation(guard_home)

        try:
            with self._connect() as connection:
                ensure_local_cli_schema(connection)
                connection.commit()
                connection.execute("begin immediate")
                write_composio_metadata(
                    connection,
                    source,
                    actions,
                    cli_id=cli_id,
                    seen_at=seen_at,
                    before_authority_change=before_change,
                )
                from .store_mcp_workflows import write_workflow_proposals

                write_workflow_proposals(connection, cli_id, source.identity.identity_hash, proposals, seen_at=seen_at)
        finally:
            if barrier_closed:
                notify_native_policy_mutation(guard_home)
        return cli_id

    def read_local_mcp_workflows(self, cli_id: str, *, offset: int = 0) -> dict[str, object]:
        if not is_local_cli_id(cli_id):
            raise ValueError("invalid provider connection")
        from .store_mcp_workflows import read_workflow_proposals

        with self._connect() as connection:
            connection.execute("begin deferred")
            ensure_local_cli_schema(connection, for_read=True)
            return read_workflow_proposals(connection, cli_id, offset=offset)

    def read_local_mcp_provider_actions(
        self,
        cli_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        search: str = "",
        expected_token: str | None = None,
    ) -> dict[str, object]:
        if not is_local_cli_id(cli_id):
            raise ValueError("invalid provider connection")
        with self._connect() as connection:
            connection.execute("begin deferred")
            ensure_local_cli_schema(connection, for_read=True)
            observation = connection.execute(
                "select identity_hash from local_cli_observation where cli_id = ? and surface = 'mcp'",
                (cli_id,),
            ).fetchone()
            if observation is None:
                raise ValueError("provider connection not found")
            return read_provider_actions(
                connection,
                cli_id,
                observation[0],
                limit=limit,
                offset=offset,
                search=search,
                expected_token=expected_token,
            )

    def read_local_mcp_skills(
        self,
        cli_id: str,
        *,
        offset: int,
        search: str,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        if not is_local_cli_id(cli_id):
            raise ValueError("mcp_skills_unavailable")
        with self._connect() as connection:
            connection.execute("begin deferred")
            ensure_local_cli_schema(connection, for_read=True)
            observation = connection.execute(
                "select identity_hash from local_cli_observation where cli_id = ? and surface = 'mcp'",
                (cli_id,),
            ).fetchone()
            if observation is None:
                raise ValueError("mcp_skills_unavailable")
            return read_mcp_skill_page(
                connection,
                cli_id,
                observation[0],
                offset=offset,
                search=search,
                expected_revision=expected_revision,
            )

    def find_local_mcp_observation(
        self,
        *,
        cli_id: str | None = None,
        server_identity_hash: str | None = None,
        command: str | None = None,
        args_hash: str | None = None,
    ) -> dict[str, object] | None:
        hash_value = _normalized_identity_hash(server_identity_hash)
        lookup_cli_id = cli_id if isinstance(cli_id, str) and is_local_cli_id(cli_id) else None
        if hash_value is None and (not command or not args_hash) and lookup_cli_id is None:
            return None
        # A stronger supplied identity must never fall through to a similar launch.
        if lookup_cli_id is not None:
            predicate, parameters = "cli_id = ?", (lookup_cli_id,)
        elif hash_value is not None:
            predicate, parameters = "(server_identity_hash = ? or identity_hash = ?)", (hash_value, hash_value)
        else:
            predicate, parameters = "server_command = ? and server_args_hash = ?", (command, args_hash)
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            rows = connection.execute(
                f"""
                select cli_id, identity_hash, kind, name, interpreter_name, example_label,
                       server_identity_hash, server_command, server_args_hash, source_label
                from local_cli_observation
                where surface = 'mcp'
                  and ({predicate})
                order by last_seen_at desc, cli_id asc
                limit 2
                """,
                parameters,
            ).fetchall()
        return _observation_from_values(rows[0]) if len(rows) == 1 else None

    def ensure_local_mcp_observation(
        self,
        identity: UnlistedCliIdentity,
        *,
        seen_at: str,
        server_identity_hash: str,
        server_command: str,
        server_args_hash: str,
        source_label: str | None = None,
        connection_identity_hash: str | None = None,
    ) -> str:
        """Insert or refresh an MCP observation without incrementing observed_count."""

        if not is_local_cli_id(identity.cli_id):
            raise ValueError("invalid local CLI id")
        existing = self.find_local_mcp_observation(
            server_identity_hash=connection_identity_hash or server_identity_hash,
            command=server_command,
            args_hash=server_args_hash,
        )
        legacy_candidate = False
        if existing is None and connection_identity_hash and connection_identity_hash != server_identity_hash:
            with self._connect() as lookup:
                ensure_local_cli_schema(lookup, for_read=True)
                legacy_candidate = _legacy_mcp_observation_exists(
                    lookup, server_identity_hash, server_command, server_args_hash
                )
        guard_home = cast("GuardStore", self).guard_home if legacy_candidate else None
        with _notify_legacy_mcp_denial(guard_home), self._connect() as connection:
            ensure_local_cli_schema(connection)
            if legacy_candidate:
                connection.commit()
                connection.execute("begin immediate")
            legacy_deny = legacy_candidate and _matching_legacy_mcp_denial(
                connection, server_identity_hash, server_command, server_args_hash
            )
            if existing is None:
                inserted = _insert_mcp_observation(
                    connection,
                    identity,
                    seen_at=seen_at,
                    server_identity_hash=server_identity_hash,
                    server_command=server_command,
                    server_args_hash=server_args_hash,
                    source_label=source_label,
                )
                if inserted is not None:
                    if legacy_deny:
                        _carry_legacy_mcp_denial(connection, inserted, identity.identity_hash, seen_at)
                    return inserted
                existing = _observation_from_values(
                    connection.execute(
                        """
                        select cli_id, identity_hash, kind, name, interpreter_name, example_label,
                               server_identity_hash, server_command, server_args_hash, source_label
                        from local_cli_observation
                        where cli_id = ?
                        """,
                        (identity.cli_id,),
                    ).fetchone()
                )
                if existing is None:
                    return identity.cli_id
                if not _same_mcp_observation(existing, identity, server_command, server_args_hash):
                    retry = _insert_mcp_observation(
                        connection,
                        identity,
                        seen_at=seen_at,
                        server_identity_hash=server_identity_hash,
                        server_command=server_command,
                        server_args_hash=server_args_hash,
                        source_label=source_label,
                        cli_id=_collision_cli_id(identity.identity_hash),
                    )
                    if retry is not None:
                        if legacy_deny:
                            _carry_legacy_mcp_denial(connection, retry, identity.identity_hash, seen_at)
                        return retry
                    return str(existing["cli_id"])
            cli_id = str(existing["cli_id"])
            if legacy_deny and _same_mcp_observation(existing, identity, server_command, server_args_hash):
                _carry_legacy_mcp_denial(connection, cli_id, identity.identity_hash, seen_at)
            _ = connection.execute(
                """
                update local_cli_observation
                set name = ?, example_label = ?, last_seen_at = ?,
                    server_identity_hash = coalesce(server_identity_hash, ?),
                    server_command = coalesce(server_command, ?),
                    server_args_hash = coalesce(server_args_hash, ?),
                    source_label = coalesce(?, source_label)
                where cli_id = ?
                """,
                (
                    identity.name,
                    identity.example_label,
                    seen_at,
                    server_identity_hash,
                    server_command,
                    server_args_hash,
                    source_label,
                    cli_id,
                ),
            )
            return cli_id

    def read_local_mcp_grant(
        self,
        server_identity_hash: str,
        *,
        command: str | None = None,
        args_hash: str | None = None,
        package_name: str | None = None,
        package_version: str | None = None,
        package_source: str | None = None,
        env_values_hash: str | None = None,
        connection_identity_hash: str | None = None,
        tool_name: str | None = None,
    ) -> dict[str, object] | None:
        hash_value = _normalized_identity_hash(server_identity_hash)
        if hash_value is None:
            return None
        server_identity_hash = hash_value
        with self._connect() as connection:
            # SELECT alone does not start a sqlite3 transaction. Hold one read
            # snapshot across the identity, grant, catalog, and tool choices.
            if not connection.in_transaction:
                connection.execute("begin deferred")
            ensure_local_cli_schema(connection, for_read=True)
            # Configured connections are host/configuration scoped. A legacy
            # server-wide row must never satisfy a different connection's call.
            lookup_hash = connection_identity_hash or server_identity_hash
            observation = connection.execute(
                """
                select cli_id, identity_hash
                from local_cli_observation
                where surface = 'mcp' and identity_hash = ?
                  and (server_identity_hash = ? or server_identity_hash is null)
                order by last_seen_at desc, cli_id asc
                limit 1
                """,
                (lookup_hash, server_identity_hash),
            ).fetchone()
            if observation is None and connection_identity_hash is not None:
                # Compatibility with pre-connection grants is safe only before
                # this server has any configured connection. Once discovered,
                # a missing exact host/configuration match must stay missing.
                configured = connection.execute(
                    """select 1 from local_cli_observation where surface = 'mcp'
                       and server_identity_hash = ? and identity_hash != ? limit 1""",
                    (server_identity_hash, server_identity_hash),
                ).fetchone()
                if configured is not None:
                    return None
                observation = connection.execute(
                    """select cli_id, identity_hash from local_cli_observation
                       where surface = 'mcp' and identity_hash = ?
                         and (server_identity_hash = ? or server_identity_hash is null)
                       order by last_seen_at desc, cli_id asc limit 1""",
                    (server_identity_hash, server_identity_hash),
                ).fetchone()
            if observation is None:
                observation = _equivalent_package_launcher_observation(
                    connection,
                    command=command,
                    package_name=package_name,
                    package_version=package_version,
                    package_source=package_source,
                    env_values_hash=env_values_hash,
                )
            if observation is None:
                return None
            cli_id, identity_hash = _row_values(observation, 2)
            if not isinstance(cli_id, str) or not isinstance(identity_hash, str):
                return None
            grant_row = connection.execute(
                "select cli_id, identity_hash, state, revision, updated_at from local_cli_grant where cli_id = ?",
                (cli_id,),
            ).fetchone()
            if grant_row is None:
                return None
            grant = _grant_from_row(grant_row)
            if grant["identity_hash"] != identity_hash:
                return None
            if grant["state"] == "blocked":
                grant["commands"] = []
                grant["command_states"] = {}
                return grant
            # An empty live name still needs the Other-tools denial; only
            # callers omitting a tool request the full inventory.
            if tool_name is None:
                grant["commands"] = _read_command_catalog(connection, cli_id)
                grant["command_states"] = _read_command_states(connection, cli_id)
            else:
                # The authorization path needs the called tool and the unseen-tool
                # fallback only. Keep both configured and observed command IDs in
                # the same read snapshot as the grant and authority digest.
                command_ids = tuple(
                    dict.fromkeys(
                        (
                            slug_local_cli_command_id(tool_name),
                            "tool-" + sha256(tool_name.encode()).hexdigest()[:24],
                            OTHER_COMMAND_ID,
                        )
                    )
                )
                grant["commands"] = _read_command_catalog(connection, cli_id, command_ids)
                grant["command_states"] = _read_command_states(connection, cli_id, command_ids)
            grant["catalog"] = read_mcp_tool_authority(connection, cli_id, identity_hash, tool_name)
            return grant


@contextmanager
def _notify_legacy_mcp_denial(guard_home: Path | None) -> Iterator[None]:
    from .native_policy_snapshot import notify_native_policy_mutation

    if guard_home is not None:
        notify_native_policy_mutation(guard_home)
    try:
        yield
    finally:
        if guard_home is not None:
            notify_native_policy_mutation(guard_home)


def _legacy_mcp_observation_exists(
    connection: sqlite3.Connection, server_hash: str, command: str, args_hash: str
) -> bool:
    return (
        connection.execute(
            """select 1 from local_cli_observation
           where surface = 'mcp' and identity_hash = ?
             and (server_identity_hash = ? or server_identity_hash is null)
             and server_command = ? and server_args_hash = ? limit 1""",
            (server_hash, server_hash, command, args_hash),
        ).fetchone()
        is not None
    )


def _matching_legacy_mcp_denial(connection: sqlite3.Connection, server_hash: str, command: str, args_hash: str) -> bool:
    row = connection.execute(
        """select 1 from local_cli_observation observation
           join local_cli_grant grant_row on grant_row.cli_id = observation.cli_id
             and grant_row.identity_hash = observation.identity_hash
           where observation.surface = 'mcp' and observation.identity_hash = ?
             and (observation.server_identity_hash = ? or observation.server_identity_hash is null)
             and observation.server_command = ? and observation.server_args_hash = ?
             and (grant_row.state = 'blocked' or exists (
               select 1 from local_cli_command_grant choice
               where choice.cli_id = observation.cli_id and choice.state = 'block'))
           limit 1""",
        (server_hash, server_hash, command, args_hash),
    ).fetchone()
    return row is not None


def _carry_legacy_mcp_denial(connection: sqlite3.Connection, cli_id: str, identity_hash: str, seen_at: str) -> None:
    # A legacy Deny may cover multiple new host connections. Carry it to each;
    # old Allow authority never crosses the new connection identity boundary.
    inserted = connection.execute(
        """insert or ignore into local_cli_grant (cli_id, identity_hash, state, revision, updated_at)
           values (?, ?, 'blocked', 1, ?)""",
        (cli_id, identity_hash, seen_at),
    )
    if inserted.rowcount:
        connection.execute("update local_cli_authority set revision = revision + 1 where singleton = 1")


def _equivalent_package_launcher_observation(
    connection: sqlite3.Connection,
    *,
    command: str | None,
    package_name: str | None,
    package_version: str | None,
    package_source: str | None,
    env_values_hash: str | None,
) -> tuple[str, str] | None:
    """Match a this-device MCP grant for the same package launcher and package."""

    requested = resolved_package_launcher_executable(command or "")
    runtime_package = package_name.strip() if isinstance(package_name, str) else ""
    if requested is None or not runtime_package:
        return None
    # Launcher aliases may be compatible, but they cannot substitute for a
    # configured account/environment binding. Exact hashes handle those cases.
    if env_values_hash != build_configured_environment_hash(None):
        return None
    runtime_version = _normalized_package_version(package_version)
    if not isinstance(package_source, str) or not package_source.strip():
        return None
    runtime_source = package_source.strip()
    rows = connection.execute(
        """
        select o.cli_id, o.identity_hash, o.server_command, o.example_label, g.state
        from local_cli_observation as o
        join local_cli_grant as g
          on g.cli_id = o.cli_id and g.identity_hash = o.identity_hash
        where o.surface = 'mcp'
        order by case when g.state = 'blocked' then 0 else 1 end, o.last_seen_at desc, o.cli_id asc
        """
    ).fetchall()
    matches: list[tuple[str, str]] = []
    for row in rows:
        cli_id, identity_hash, server_command, example_label, _grant_state = _row_values(row, 5)
        if not isinstance(cli_id, str) or not isinstance(identity_hash, str):
            continue
        stored_identity = _observation_launch_identity(
            server_command if isinstance(server_command, str) else None,
            example_label if isinstance(example_label, str) else None,
        )
        if stored_identity is None or stored_identity.identity_hash != identity_hash:
            continue
        if (
            stored_identity.package_name != runtime_package
            or _normalized_package_version(stored_identity.package_version) != runtime_version
            or stored_identity.package_source != runtime_source
        ):
            continue
        stored = resolved_package_launcher_executable(str(server_command or ""))
        if stored is not None and stored == requested:
            matches.append((cli_id, identity_hash))
    return matches[0] if len(matches) == 1 else None


def _observation_launch_identity(
    server_command: str | None,
    example_label: str | None,
) -> McpServerIdentity | None:
    if not isinstance(example_label, str) or not example_label.strip():
        return None
    try:
        parts = shlex.split(example_label)
    except ValueError:
        return None
    if not parts:
        return None
    command = server_command or parts[0]
    return build_mcp_server_identity(
        config_path="",
        command=command,
        args=tuple(parts[1:]),
        transport="stdio",
    )


def _normalized_package_version(value: str | None) -> str:
    if not isinstance(value, str):
        return "latest"
    text = value.strip()
    return text or "latest"


def _normalized_identity_hash(value: str | None) -> str | None:
    if not isinstance(value, str) or len(value) != 64:
        return None
    lowered = value.lower()
    if any(character not in "0123456789abcdef" for character in lowered):
        return None
    return lowered


def _observation_from_values(row: object | None) -> dict[str, object] | None:
    if row is None:
        return None
    values = _row_values(row, 10)
    cli_id = values[0]
    identity_hash = values[1]
    if not isinstance(cli_id, str) or not isinstance(identity_hash, str):
        return None
    return {
        "cli_id": cli_id,
        "identity_hash": identity_hash,
        "kind": values[2],
        "name": values[3],
        "interpreter_name": values[4],
        "example_label": values[5],
        "server_identity_hash": values[6],
        "server_command": values[7],
        "server_args_hash": values[8],
        "source_label": values[9],
    }


def _same_mcp_observation(
    existing: dict[str, object],
    identity: UnlistedCliIdentity,
    server_command: str,
    server_args_hash: str,
) -> bool:
    return existing.get("identity_hash") == identity.identity_hash


def _collision_cli_id(identity_hash: str) -> str:
    return f"local-cli.mcp-{identity_hash[:12]}"


def _insert_mcp_observation(
    connection: sqlite3.Connection,
    identity: UnlistedCliIdentity,
    *,
    seen_at: str,
    server_identity_hash: str,
    server_command: str,
    server_args_hash: str,
    source_label: str | None = None,
    cli_id: str | None = None,
) -> str | None:
    target_id = cli_id or identity.cli_id
    if not is_local_cli_id(target_id):
        return None
    try:
        _ = connection.execute(
            """
            insert into local_cli_observation (
                cli_id, identity_hash, kind, name, interpreter_name, example_label,
                observed_count, last_seen_at, source_path, help_status, surface,
                server_identity_hash, server_command, server_args_hash, source_label
            ) values (?, ?, ?, ?, ?, ?, 1, ?, null, null, 'mcp', ?, ?, ?, ?)
            """,
            (
                target_id,
                identity.identity_hash,
                identity.kind,
                identity.name,
                identity.interpreter_name,
                identity.example_label,
                seen_at,
                server_identity_hash,
                server_command,
                server_args_hash,
                source_label,
            ),
        )
    except sqlite3.IntegrityError:
        return None
    return target_id
