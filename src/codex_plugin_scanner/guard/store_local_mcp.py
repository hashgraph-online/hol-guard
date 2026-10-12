"""This-device MCP custom-extension grant lookup."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .runtime.composio_contract import composio_tool_role
from .runtime.composio_discovery import ComposioActionSchema
from .runtime.composio_workflows import ComposioWorkflowProposal
from .runtime.local_cli_identity import UnlistedCliIdentity, is_local_cli_id
from .runtime.observed_mcp_tools import ObservedMcpTool, observed_mcp_tool
from .store_local_cli import _row_values
from .store_local_cli_retention import (
    LocalCliReplaySkippedError,
    later_timestamp,
    prune_expired_local_cli_observations,
    replay_allowed,
)
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_catalog import read_mcp_skill_page
from .store_mcp_provider_catalog import read_provider_actions, write_composio_metadata

if TYPE_CHECKING:
    from .store import GuardStore

_OBSERVED_MCP_ACTIONS = frozenset({"allow", "review", "block"})


class StoreLocalMcpMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

        def _native_store_call(
            self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
        ) -> Any: ...

    def read_mcp_provider_choices(self) -> dict[str, str]:
        from .store_mcp_provider_permissions import read_native_provider_choices

        with self._connect() as connection:
            connection.execute("begin")
            ensure_local_cli_schema(connection, for_read=True)
            return read_native_provider_choices(connection)

    def read_observed_mcp_tool_actions(self) -> dict[str, str]:
        """Return the operator's exact choices for observed MCP connectors."""

        # The resident reads only the current schema; migrate an older store first.
        with self._connect() as connection:
            ensure_local_cli_schema(connection, for_read=True)
            # The snapshot publisher reads this on every policy observation.
            # Without an observed connector the resident would return no
            # actions, so skip the round trip.
            observed = connection.execute(
                "select 1 from local_cli_observation "
                "where surface = 'mcp' and server_command like 'observed-mcp:%' limit 1"
            ).fetchone()
        if observed is None:
            return {}
        actions = self._native_store_call("observed_mcp_tool_actions", {})
        if not isinstance(actions, dict) or any(
            not isinstance(key, str) or action not in _OBSERVED_MCP_ACTIONS
            for key, action in cast(dict[object, object], actions).items()
        ):
            raise sqlite3.DatabaseError("native_observed_mcp_tool_actions_invalid")
        return cast(dict[str, str], actions)

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
        replayed: bool = False,
        replay_now: str | None = None,
    ) -> str:
        """Insert or refresh an MCP observation without incrementing observed_count.

        ``replayed`` marks ``seen_at`` as a history timestamp: it never moves
        ``last_seen_at`` backward and does not run retention pruning. The
        replay check runs in the write transaction, so a concurrent Forget is
        not undone; a skipped entry raises ``LocalCliReplaySkippedError``.
        """

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
            if legacy_candidate or replayed:
                connection.commit()
                connection.execute("begin immediate")
            if replayed and not replay_allowed(connection, identity.identity_hash, seen_at, now=replay_now):
                raise LocalCliReplaySkippedError(identity.cli_id)
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
                    if not replayed:
                        _ = prune_expired_local_cli_observations(connection, now=seen_at, throttle=True)
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
            refreshed_at = seen_at
            if replayed:
                stored = connection.execute(
                    "select last_seen_at from local_cli_observation where cli_id = ?", (cli_id,)
                ).fetchone()
                refreshed_at = later_timestamp(stored[0] if stored is not None else None, seen_at)
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
                    refreshed_at,
                    server_identity_hash,
                    server_command,
                    server_args_hash,
                    source_label,
                    cli_id,
                ),
            )
            if not replayed:
                _ = prune_expired_local_cli_observations(connection, now=seen_at, throttle=True)
            return cli_id


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
