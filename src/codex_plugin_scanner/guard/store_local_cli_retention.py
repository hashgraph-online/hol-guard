"""Forget and age out observed custom extensions that the user never enrolled."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from .runtime.local_cli_identity import is_local_cli_id
from .store_local_cli_schema import ensure_local_cli_schema

LOCAL_CLI_OBSERVATION_RETENTION_DAYS = 30

# Inventory rows only. Grants and other authority rows are never touched here.
_OBSERVATION_TABLES = (
    "local_cli_command",
    "local_mcp_catalog",
    "local_mcp_provider_action",
    "local_mcp_workflow_proposal",
    "local_cli_observation",
)

# An observation can be forgotten only when nothing enrolled depends on it.
# MCP connections that share a server with an enrolled record stay: their
# presence keeps a legacy server-wide grant from covering a different
# configured connection (see read_local_mcp_grant).
_FORGETTABLE_PREDICATE = """
    observation.cli_id not in (select cli_id from local_cli_grant)
    and not (
        observation.surface = 'mcp'
        and observation.server_identity_hash is not null
        and observation.server_identity_hash in (
            select enrolled.server_identity_hash
            from local_cli_observation enrolled
            join local_cli_grant grant_row on grant_row.cli_id = enrolled.cli_id
            where enrolled.server_identity_hash is not null
        )
    )
"""


class LocalCliForgetError(ValueError):
    """Raised when an observed record cannot be forgotten."""


class StoreLocalCliRetentionMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def forget_local_cli_observation(self, cli_id: str, *, identity_hash: str) -> None:
        """Delete one un-enrolled observed record and its inventory rows.

        The record comes back on its own if the host still runs it.
        """

        if not is_local_cli_id(cli_id):
            raise LocalCliForgetError("invalid_cli_id")
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            row = connection.execute(
                "select identity_hash from local_cli_observation where cli_id = ?",
                (cli_id,),
            ).fetchone()
            if row is None:
                raise LocalCliForgetError("local_cli_not_found")
            if str(row[0]) != identity_hash:
                raise LocalCliForgetError("identity_changed")
            if connection.execute("select 1 from local_cli_grant where cli_id = ?", (cli_id,)).fetchone():
                raise LocalCliForgetError("local_cli_enrolled")
            forgettable = connection.execute(
                "select 1 from local_cli_observation observation "
                f"where observation.cli_id = ? and {_FORGETTABLE_PREDICATE}",
                (cli_id,),
            ).fetchone()
            if forgettable is None:
                raise LocalCliForgetError("local_cli_shared_server_enrolled")
            _delete_observations(connection, (cli_id,))

    def prune_inactive_local_cli_observations(
        self,
        *,
        now: datetime | None = None,
        retention_days: int = LOCAL_CLI_OBSERVATION_RETENTION_DAYS,
    ) -> list[str]:
        """Delete un-enrolled observed records not seen within the retention window."""

        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            return prune_expired_local_cli_observations(connection, now=now, retention_days=retention_days)


def prune_expired_local_cli_observations(
    connection: sqlite3.Connection,
    *,
    now: datetime | str | None = None,
    retention_days: int = LOCAL_CLI_OBSERVATION_RETENTION_DAYS,
) -> list[str]:
    """Delete expired un-enrolled observations inside the caller's transaction."""

    current = _parse_timestamp(now) if isinstance(now, str) else now
    cutoff = (current or datetime.now(timezone.utc)) - timedelta(days=retention_days)
    rows = connection.execute(
        f"select observation.cli_id, observation.last_seen_at from local_cli_observation observation "
        f"where {_FORGETTABLE_PREDICATE}"
    ).fetchall()
    expired = tuple(str(cli_id) for cli_id, last_seen_at in rows if _seen_before(last_seen_at, cutoff))
    if expired:
        _delete_observations(connection, expired)
    return list(expired)


def _seen_before(value: object, cutoff: datetime) -> bool:
    seen = _parse_timestamp(value) if isinstance(value, str) else None
    return seen is not None and seen < cutoff


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _delete_observations(connection: sqlite3.Connection, cli_ids: tuple[str, ...]) -> None:
    for table in _OBSERVATION_TABLES:
        connection.executemany(f"delete from {table} where cli_id = ?", [(cli_id,) for cli_id in cli_ids])
