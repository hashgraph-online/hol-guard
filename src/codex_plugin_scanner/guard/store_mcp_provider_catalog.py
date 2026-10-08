"""Private provider action metadata, separate from a complete MCP tools catalog."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from hashlib import sha256

from .runtime.composio_discovery import ComposioActionSchema
from .runtime.mcp_classification import classify_mcp_action
from .runtime.observed_mcp_tools import ObservedMcpTool

_MAX_ACTIONS = 10_000
_MAX_BYTES = 2_000_000


def write_composio_metadata(
    connection: sqlite3.Connection,
    source: ObservedMcpTool,
    actions: tuple[ComposioActionSchema, ...],
    *,
    cli_id: str,
    seen_at: str,
    before_authority_change: Callable[[], None] = lambda: None,
) -> bool:
    identity_hash = source.server_identity.identity_hash
    observation = connection.execute(
        "select identity_hash, server_command from local_cli_observation where cli_id = ? and surface = 'mcp'",
        (cli_id,),
    ).fetchone()
    if observation is None or observation[0] != identity_hash or observation[1] != source.server_identity.command:
        raise ValueError("provider metadata connection changed")
    authority_changed = False
    for action in actions:
        raw = json.dumps(action.input_schema, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        authority_hash = sha256(
            json.dumps(
                {"toolkit": action.toolkit, "tool_slug": action.tool_slug, "input_schema": action.input_schema},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        previous = connection.execute(
            "select revision, authority_hash, full_schema from local_mcp_provider_action "
            "where cli_id = ? and identity_hash = ? and provider = 'composio' and tool_slug = ?",
            (cli_id, identity_hash, action.tool_slug),
        ).fetchone()
        revision = (
            1
            if previous is None
            else previous[0] + int(previous[1] != authority_hash or previous[2] != int(action.full_schema))
        )
        if previous is None or revision != previous[0]:
            authority_changed = True
        connection.execute(
            """insert into local_mcp_provider_action
            (cli_id, identity_hash, provider, tool_slug, toolkit, description, input_schema_json,
             authority_hash, full_schema, source_tool, revision, updated_at)
            values (?, ?, 'composio', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(cli_id, identity_hash, provider, tool_slug) do update set
            toolkit = excluded.toolkit, description = excluded.description,
            input_schema_json = excluded.input_schema_json, authority_hash = excluded.authority_hash,
            full_schema = excluded.full_schema, source_tool = excluded.source_tool,
            revision = excluded.revision, updated_at = excluded.updated_at""",
            (
                cli_id,
                identity_hash,
                action.tool_slug,
                action.toolkit,
                action.description,
                raw,
                authority_hash,
                int(action.full_schema),
                source.qualified_name,
                revision,
                seen_at,
            ),
        )
    count, size = connection.execute(
        "select count(*), coalesce(sum(length(cast(input_schema_json as blob)) "
        "+ length(cast(description as blob))), 0) "
        "from local_mcp_provider_action where cli_id = ? and identity_hash = ?",
        (cli_id, identity_hash),
    ).fetchone()
    if count > _MAX_ACTIONS or size > _MAX_BYTES:
        raise ValueError("provider metadata catalog capacity exceeded")
    if authority_changed:
        before_authority_change()
        rebuild_provider_authority(connection, cli_id, identity_hash)
    return authority_changed


def rebuild_provider_authority(connection: sqlite3.Connection, cli_id: str, identity_hash: str) -> None:
    fingerprint = sha256(identity_hash.encode())
    for row in connection.execute(
        """select tool_slug, authority_hash, full_schema from local_mcp_provider_action
        where cli_id = ? and identity_hash = ? order by tool_slug""",
        (cli_id, identity_hash),
    ):
        fingerprint.update(json.dumps(tuple(row), separators=(",", ":")).encode())
    connection.execute(
        "insert into local_mcp_provider_authority values (?, ?, ?) "
        "on conflict(cli_id, identity_hash) do update set digest = excluded.digest",
        (cli_id, identity_hash, fingerprint.hexdigest()),
    )


def read_provider_authority(connection: sqlite3.Connection) -> str | None:
    rows = connection.execute(
        """select a.cli_id, a.identity_hash, a.digest from local_mcp_provider_authority a
        join local_cli_observation o on o.cli_id = a.cli_id and o.identity_hash = a.identity_hash
        where o.surface = 'mcp' order by a.cli_id, a.identity_hash"""
    ).fetchall()
    if not rows:
        return None
    return sha256(json.dumps([tuple(row) for row in rows], separators=(",", ":")).encode()).hexdigest()


def load_provider_catalog_summaries(connection: sqlite3.Connection) -> dict[str, dict[str, object]]:
    rows = connection.execute(
        """select p.cli_id, count(*), sum(p.full_schema), max(p.updated_at)
        from local_mcp_provider_action p join local_cli_observation o
        on p.cli_id = o.cli_id and p.identity_hash = o.identity_hash
        group by p.cli_id"""
    ).fetchall()
    return {
        cli_id: {
            "provider": "composio",
            "known_count": count,
            "full_schema_count": full_count,
            "updated_at": updated_at,
            "coverage": "discovery-subset",
            "account_binding": "unverified",
        }
        for cli_id, count, full_count, updated_at in rows
    }


def read_provider_actions(
    connection: sqlite3.Connection,
    cli_id: str,
    identity_hash: str,
    *,
    limit: int = 100,
    offset: int = 0,
    search: str = "",
    expected_token: str | None = None,
) -> dict[str, object]:
    if not 1 <= limit <= 100 or offset < 0 or len(search) > 128:
        raise ValueError("invalid provider catalog page")
    fingerprint = sha256(identity_hash.encode())
    for row in connection.execute(
        """select a.tool_slug, a.toolkit, a.authority_hash, a.full_schema, a.revision,
        a.description, a.updated_at, coalesce(g.state, 'review')
        from local_mcp_provider_action a left join local_mcp_provider_grant g
        on g.cli_id = a.cli_id and g.identity_hash = a.identity_hash and g.tool_slug = a.tool_slug
        where a.cli_id = ? and a.identity_hash = ? order by a.tool_slug""",
        (cli_id, identity_hash),
    ):
        fingerprint.update(json.dumps(tuple(row), separators=(",", ":"), ensure_ascii=True).encode())
    token = fingerprint.hexdigest()
    if expected_token is not None and expected_token != token:
        raise ValueError("provider_catalog_changed")
    search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{search}%"
    rows = connection.execute(
        """select a.tool_slug, a.toolkit, a.description, a.full_schema, a.revision, a.updated_at,
        coalesce(g.state, 'review'), a.input_schema_json
        from local_mcp_provider_action a
        left join local_mcp_provider_grant g on g.cli_id = a.cli_id
          and g.identity_hash = a.identity_hash and g.tool_slug = a.tool_slug
        where a.cli_id = ? and a.identity_hash = ?
        and (a.tool_slug like ? escape '\\' or a.toolkit like ? escape '\\' or a.description like ? escape '\\')
        order by a.toolkit asc, a.tool_slug asc limit ? offset ?""",
        (cli_id, identity_hash, pattern, pattern, pattern, limit + 1, offset),
    ).fetchall()
    return {
        "actions": [
            {
                "tool_slug": slug,
                "toolkit": toolkit,
                "description": description,
                "full_schema": bool(full),
                "revision": revision,
                "updated_at": updated_at,
                "permission_state": state,
                "allow_supported": False,
                "account_binding": "unverified",
                "source": "observed-provider-result",
                "classification": classify_mcp_action(
                    slug,
                    json.loads(raw_schema),
                    provider="composio",
                    full_schema=bool(full),
                ),
            }
            for slug, toolkit, description, full, revision, updated_at, state, raw_schema in rows[:limit]
        ],
        "next_offset": offset + limit if len(rows) > limit else None,
        "coverage": "discovery-subset",
        "catalog_token": token,
    }
