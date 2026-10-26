"""Private provider action metadata, separate from a complete MCP tools catalog."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from typing import cast

from .runtime.mcp_classification import McpClassificationUnavailableError, classify_mcp_actions


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


def describe_provider_actions(
    page: dict[str, object],
    declarations: Sequence[dict[str, object]],
    *,
    guard_home: Path,
) -> dict[str, object]:
    """Attach the resident's advisory classification to a page of actions.

    The classification is display evidence, not authority: a page without a
    resident still names every action and its permission state, so an absent
    description leaves the entry out rather than failing the read.
    """

    actions = cast("list[dict[str, object]]", page["actions"])
    if not actions:
        return page
    try:
        described = classify_mcp_actions(list(declarations), guard_home=guard_home)
    except McpClassificationUnavailableError:
        return page
    for action, classification in zip(actions, described, strict=True):
        if classification is not None:
            action["classification"] = classification
    return page
