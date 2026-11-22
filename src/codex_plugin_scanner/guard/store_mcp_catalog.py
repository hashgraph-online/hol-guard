"""Identity-bound discovery evidence, independent of permission authority."""

from __future__ import annotations

import json
import sqlite3
from hashlib import sha256

_MAX_SNAPSHOT_BYTES = 2_000_000
_MAX_SNAPSHOT_TOOLS = 10_000


def tool_definition_authority_hash(definition: object) -> str | None:
    if not isinstance(definition, dict) or not isinstance(definition.get("inputSchema"), dict):
        return None
    try:
        return sha256(_authority_shape(definition).encode("utf-8")).hexdigest()
    except (ValueError, TypeError, RecursionError):
        return None


def _authority_shape(tool: dict[str, object]) -> str:
    return json.dumps(
        {key: tool.get(key) for key in ("inputSchema", "outputSchema", "annotations")},
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def _decode_snapshot(raw: object) -> dict[str, object] | None:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
        return None
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("complete"), bool):
        return None
    tools = payload.get("tools")
    if not isinstance(tools, list) or len(tools) > _MAX_SNAPSHOT_TOOLS:
        return None
    return payload


def rebuild_tool_authority(
    connection: sqlite3.Connection,
    cli_id: str,
    identity_hash: str,
    raw: object,
    revision: int,
) -> None:
    """Backfill the v10 to v11 migration only; live catalog writes rebuild this natively."""
    payload = _decode_snapshot(raw)
    tools = payload.get("tools") if payload is not None else None
    connection.execute("delete from local_mcp_tool_authority where cli_id = ?", (cli_id,))
    if not isinstance(tools, list) or len(tools) > _MAX_SNAPSHOT_TOOLS:
        return
    rows: dict[str, tuple[object, ...]] = {}
    for tool in tools:
        digest = tool_definition_authority_hash(tool)
        name = tool.get("name") if isinstance(tool, dict) else None
        if isinstance(name, str) and digest is not None:
            if name in rows:
                return
            rows[name] = (cli_id, identity_hash, name, revision, digest)
    connection.executemany("insert into local_mcp_tool_authority values (?, ?, ?, ?, ?)", rows.values())
