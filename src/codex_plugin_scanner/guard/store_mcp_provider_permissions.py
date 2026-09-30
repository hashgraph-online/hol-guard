"""Identity-bound provider choices, committed with protected extension authority."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

from .runtime.mcp_provider_permissions import provider_action_selector
from .runtime.observed_mcp_tools import OBSERVED_MCP_PREFIX, ObservedMcpTool, observed_mcp_tool

ProviderUpdate = tuple[str, str, int]


def write_provider_choices(
    connection: sqlite3.Connection,
    *,
    cli_id: str,
    identity_hash: str,
    updates: Sequence[ProviderUpdate],
    updated_at: str,
) -> None:
    if len(updates) > 100 or len({slug for slug, _, _ in updates}) != len(updates):
        raise ValueError("invalid provider action choices")
    for slug, state, revision in updates:
        if state not in {"review", "block"} or type(revision) is not int or revision < 1:
            raise ValueError("invalid provider action choice")
        row = connection.execute(
            "select a.revision, a.source_tool from local_mcp_provider_action a "
            "join local_cli_observation o on o.cli_id = a.cli_id and o.identity_hash = a.identity_hash "
            "where a.cli_id = ? and a.identity_hash = ? and a.tool_slug = ? and o.surface = 'mcp'",
            (cli_id, identity_hash, slug),
        ).fetchone()
        if row is None or row[0] != revision:
            raise ValueError("provider_action_revision_conflict")
        # Cached metadata cannot invent a different authority namespace.
        marker = connection.execute(
            "select server_command from local_cli_observation where cli_id = ?",
            (cli_id,),
        ).fetchone()[0]
        source = _source(marker)
        if source is None or source.server_identity.identity_hash != identity_hash:
            raise ValueError("invalid provider authority identity")
        provider_action_selector(source, slug)
        connection.execute(
            "insert into local_mcp_provider_grant values (?, ?, ?, ?, ?) "
            "on conflict(cli_id, identity_hash, tool_slug) do update set "
            "state = excluded.state, updated_at = excluded.updated_at",
            (cli_id, identity_hash, slug, state, updated_at),
        )


def _source(marker: object) -> ObservedMcpTool | None:
    if not isinstance(marker, str) or not marker.startswith(OBSERVED_MCP_PREFIX):
        return None
    harness, separator, namespace = marker[len(OBSERVED_MCP_PREFIX) :].partition(":")
    source = observed_mcp_tool(harness, namespace + "probe") if separator else None
    return source if source is not None and source.namespace == namespace else None


def read_native_provider_choices(connection: sqlite3.Connection) -> dict[str, str]:
    rows = connection.execute(
        "select o.server_command, o.identity_hash, p.tool_slug, p.state "
        "from local_mcp_provider_grant p "
        "join local_cli_observation o on o.cli_id = p.cli_id and o.identity_hash = p.identity_hash "
        "join local_cli_grant g on g.cli_id = p.cli_id and g.identity_hash = p.identity_hash "
        "where o.surface = 'mcp' and g.state in ('allowed', 'blocked') and p.state = 'block'",
    ).fetchall()
    result: dict[str, str] = {}
    for marker, identity_hash, slug, state in rows:
        source = _source(marker)
        if source is None or source.server_identity.identity_hash != identity_hash:
            raise ValueError("invalid provider authority identity")
        result[provider_action_selector(source, slug)] = state
    return result


def provider_choices_digest(updates: Sequence[ProviderUpdate]) -> str:
    import json
    from hashlib import sha256

    return sha256(json.dumps(sorted(updates), separators=(",", ":")).encode()).hexdigest()
