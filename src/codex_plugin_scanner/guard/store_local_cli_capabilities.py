"""This-device capabilities of an allowed local CLI grant.

A capability widens what an allowed CLI may do inside the workspace sandbox
(loopback network, reading or writing its own state directory). A missing row
reads as ``off``. ``write_local_cli_capabilities`` is the only writer that can
turn a capability on, and only the extension-control authority apply (preview,
one-use proof, apply) reaches it. Removing a grant, or re-granting a changed
identity, clears the rows so a capability never outlives the grant it was
chosen for.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Final, Literal

from .store_local_cli_context import CAPABILITY_BY_CAUSE

LOCAL_CLI_CAPABILITIES: Final = ("loopback-network", "state-dir-read", "state-dir-write")
LocalCliCapabilityState = Literal["on", "off"]
_STATES: Final = frozenset({"on", "off"})


class LocalCliCapabilityError(ValueError):
    """A capability choice the authority must refuse."""


def ensure_local_cli_capability_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """create table if not exists local_cli_grant_capability (
            cli_id text not null,
            capability text not null
                check (capability in ('loopback-network', 'state-dir-read', 'state-dir-write')),
            state text not null check (state in ('on', 'off')),
            revision integer not null check (revision >= 1),
            updated_at text not null,
            primary key (cli_id, capability)
        )"""
    )


def validated_capability_choices(raw: object) -> dict[str, LocalCliCapabilityState]:
    """Return ``{name: on|off}`` or raise for unknown names, states or shapes."""

    if raw is None:
        return {}
    if not isinstance(raw, dict) or len(raw) > len(LOCAL_CLI_CAPABILITIES):
        raise LocalCliCapabilityError("invalid_capabilities")
    choices: dict[str, LocalCliCapabilityState] = {}
    for name, state in raw.items():
        # A list or object is unhashable; check the type before the set lookup.
        if not isinstance(name, str) or name not in LOCAL_CLI_CAPABILITIES:
            raise LocalCliCapabilityError("invalid_capabilities")
        if not isinstance(state, str) or state not in _STATES:
            raise LocalCliCapabilityError("invalid_capabilities")
        choices[name] = "on" if state == "on" else "off"
    return choices


def capability_choices_digest(choices: Mapping[str, str]) -> str:
    """Stable text the approval subject binds, so a proof covers these choices."""

    return ",".join(f"{name}={choices[name]}" for name in sorted(choices))


def write_local_cli_capabilities(
    connection: sqlite3.Connection,
    *,
    cli_id: str,
    choices: Mapping[str, str],
    revision: int,
    updated_at: str,
) -> None:
    """Persist capability choices after the grant row of the same apply.

    Runs inside the authority transaction. A capability is only for a
    ``surface='cli'`` connector, and ``on`` needs the grant to be allowed.
    """

    checked = validated_capability_choices(dict(choices))
    if not checked:
        return
    observation = connection.execute("select surface from local_cli_observation where cli_id = ?", (cli_id,)).fetchone()
    if observation is None or observation[0] != "cli":
        raise LocalCliCapabilityError("capabilities_require_cli_surface")
    if "on" in checked.values():
        grant = connection.execute("select state from local_cli_grant where cli_id = ?", (cli_id,)).fetchone()
        if grant is None or grant[0] != "allowed":
            raise LocalCliCapabilityError("capabilities_require_allowed_grant")
    for name, state in sorted(checked.items()):
        connection.execute(
            """
            insert into local_cli_grant_capability (cli_id, capability, state, revision, updated_at)
            values (?, ?, ?, ?, ?)
            on conflict(cli_id, capability) do update set
                state = excluded.state,
                revision = excluded.revision,
                updated_at = excluded.updated_at
            """,
            (cli_id, name, state, revision, updated_at),
        )
    _clear_resolved_causes(connection, cli_id, [name for name, state in checked.items() if state == "on"])


def _clear_resolved_causes(connection: sqlite3.Connection, cli_id: str, enabled: list[str]) -> None:
    """Drop a blocked cause once the capability it points at is on."""

    causes = tuple(cause for cause, capability in CAPABILITY_BY_CAUSE.items() if capability in enabled)
    if not causes:
        return
    columns = {str(row[1]) for row in connection.execute("pragma table_info(local_cli_observation)")}
    if "first_blocked_cause" not in columns:
        return
    marks = ", ".join("?" for _ in causes)
    connection.execute(
        f"update local_cli_observation set first_blocked_cause = null "
        f"where cli_id = ? and first_blocked_cause in ({marks})",
        (cli_id, *causes),
    )


def clear_local_cli_capabilities(connection: sqlite3.Connection, cli_id: str) -> None:
    """Drop every capability of ``cli_id``; this only ever narrows."""

    connection.execute("delete from local_cli_grant_capability where cli_id = ?", (cli_id,))


def load_local_cli_capabilities(connection: sqlite3.Connection) -> dict[str, dict[str, LocalCliCapabilityState]]:
    """Every CLI's full ``{name: on|off}`` map, unknown rows ignored."""

    exists = connection.execute(
        "select 1 from sqlite_master where type = 'table' and name = 'local_cli_grant_capability'"
    ).fetchone()
    if exists is None:
        return {}
    stored: dict[str, dict[str, LocalCliCapabilityState]] = {}
    for cli_id, name, state in connection.execute(
        "select cli_id, capability, state from local_cli_grant_capability"
    ).fetchall():
        if isinstance(cli_id, str) and name in LOCAL_CLI_CAPABILITIES and state == "on":
            stored.setdefault(cli_id, {})[name] = "on"
    return stored


def capability_map(enabled: Mapping[str, str] | None) -> dict[str, LocalCliCapabilityState]:
    """The full map for one CLI, with absent capabilities ``off``."""

    current = enabled or {}
    return {name: "on" if current.get(name) == "on" else "off" for name in LOCAL_CLI_CAPABILITIES}


__all__ = [
    "LOCAL_CLI_CAPABILITIES",
    "LocalCliCapabilityError",
    "LocalCliCapabilityState",
    "capability_choices_digest",
    "capability_map",
    "clear_local_cli_capabilities",
    "ensure_local_cli_capability_table",
    "load_local_cli_capabilities",
    "validated_capability_choices",
    "write_local_cli_capabilities",
]
