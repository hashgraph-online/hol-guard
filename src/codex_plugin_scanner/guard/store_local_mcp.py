"""This-device MCP custom-extension grant lookup."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING

from .runtime.local_cli_commands import LocalCliCommand, LocalCliCommandState
from .store_local_cli import _grant_from_row, _row_values
from .store_local_cli_schema import ensure_local_cli_schema


class StoreLocalMcpMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

        def read_local_cli_command_catalog(self, cli_id: str) -> list[LocalCliCommand]: ...

        def read_local_cli_command_states(self, cli_id: str) -> dict[str, LocalCliCommandState]: ...

    def read_local_mcp_grant(
        self,
        server_identity_hash: str,
        *,
        command: str | None = None,
        args_hash: str | None = None,
    ) -> dict[str, object] | None:
        if not isinstance(server_identity_hash, str) or len(server_identity_hash) != 64:
            return None
        server_identity_hash = server_identity_hash.lower()
        if any(character not in "0123456789abcdef" for character in server_identity_hash):
            return None
        with self._connect() as connection:
            ensure_local_cli_schema(connection)
            observation = connection.execute(
                """
                select cli_id, identity_hash
                from local_cli_observation
                where surface = 'mcp'
                  and (
                    server_identity_hash = ?
                    or identity_hash = ?
                    or (
                      ? is not null and ? is not null
                      and server_command = ? and server_args_hash = ?
                    )
                  )
                order by last_seen_at desc, cli_id asc
                limit 1
                """,
                (
                    server_identity_hash,
                    server_identity_hash,
                    command,
                    args_hash,
                    command,
                    args_hash,
                ),
            ).fetchone()
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
        grant["commands"] = self.read_local_cli_command_catalog(cli_id)
        grant["command_states"] = self.read_local_cli_command_states(cli_id)
        return grant
