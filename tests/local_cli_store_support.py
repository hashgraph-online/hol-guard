"""Test-side writes to the local CLI store that no production path makes."""

from __future__ import annotations

from collections.abc import Mapping

from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommandState
from codex_plugin_scanner.guard.runtime.local_cli_identity import is_local_cli_id
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_local_cli import _write_command_states
from codex_plugin_scanner.guard.store_local_cli_schema import ensure_local_cli_schema


def upsert_local_cli_command_states(
    store: GuardStore,
    cli_id: str,
    states: Mapping[str, LocalCliCommandState],
) -> None:
    """Write per-command grant states for an observed CLI straight into ``guard.db``."""

    if not is_local_cli_id(cli_id):
        raise ValueError("invalid local CLI id")
    with store._connect() as connection:
        ensure_local_cli_schema(connection)
        _write_command_states(connection, cli_id, states)
