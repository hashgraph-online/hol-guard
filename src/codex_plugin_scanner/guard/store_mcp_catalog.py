"""Identity-bound discovery evidence, independent of permission authority."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from hashlib import sha256

from .runtime.local_cli_commands import slug_local_cli_command_ids

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


def acknowledge_catalog_changes(
    connection: sqlite3.Connection,
    cli_id: str,
    identity_hash: str,
    reviewed: set[str],
    *,
    catalog_revision: int,
    change_ids: Mapping[str, str],
) -> None:
    """A saved choice for a new or changed tool reviews that change.

    Without this, ``changes`` keeps flagging every tool from the first listing
    until the next one, so a reviewed extension stays under Needs review. The
    catalog revision and tool authority are untouched; the next listing still
    diffs against the known tools and flags anything new again.

    Only the catalog revision the choices were made against is reviewed, so a
    save from an older view cannot clear a change a later listing recorded.
    A tool is matched by its command id, so a saved Other-tools choice reviews
    the tools folded into it, while a real tool named ``other`` has its own id.
    ``change_ids`` comes from ``catalog_change_ids``; a name it lacks stays
    flagged.
    """

    row = connection.execute(
        "select catalog_json, revision from local_mcp_catalog where cli_id = ? and identity_hash = ?",
        (cli_id, identity_hash),
    ).fetchone()
    if row is None or int(row[1]) != catalog_revision:
        return
    payload = _decode_snapshot(row[0])
    changes = payload.get("changes") if payload is not None else None
    if payload is None or not isinstance(changes, dict):
        return
    listed = {key: names for key in ("added", "changed") if isinstance(names := changes.get(key), list)}
    updated = dict(changes)
    for key, names in listed.items():
        updated[key] = [name for name in names if not (isinstance(name, str) and change_ids.get(name) in reviewed)]
    if updated == changes:
        return
    payload["changes"] = updated
    raw = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    connection.execute(
        "update local_mcp_catalog set catalog_json = ? where cli_id = ? and identity_hash = ?",
        (raw, cli_id, identity_hash),
    )


def catalog_change_ids(connection: sqlite3.Connection, cli_ids: Iterable[str]) -> dict[str, str]:
    """Command ids for the flagged tool names, resolved by the resident before the write lock."""

    texts: set[str] = set()
    for cli_id in cli_ids:
        rows = connection.execute("select catalog_json from local_mcp_catalog where cli_id = ?", (cli_id,))
        for (raw,) in rows.fetchall():
            changes = (_decode_snapshot(raw) or {}).get("changes")
            for names in (changes.get("added"), changes.get("changed")) if isinstance(changes, dict) else ():
                if isinstance(names, list):
                    texts.update(name for name in names if isinstance(name, str))
    ordered = sorted(texts)
    try:
        return dict(zip(ordered, slug_local_cli_command_ids(ordered), strict=True)) if ordered else {}
    except ValueError:
        # Without the resident the changes stay flagged for review.
        return {}


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
