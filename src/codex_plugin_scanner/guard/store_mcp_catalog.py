"""Identity-bound discovery evidence, independent of permission authority."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from hashlib import sha256

from .runtime.local_cli_commands import slug_local_cli_command_id
from .runtime.local_mcp_stdio import McpCatalogResult
from .runtime.mcp_skills import mcp_skills_declared

_MAX_SNAPSHOT_BYTES = 2_000_000
_MAX_SNAPSHOT_TOOLS = 10_000


def load_mcp_catalogs(connection: sqlite3.Connection) -> dict[str, tuple[str, dict[str, object]]]:
    catalogs: dict[str, tuple[str, dict[str, object]]] = {}
    rows = connection.execute(
        "select cli_id, identity_hash, catalog_json, revision, updated_at, last_complete_at from local_mcp_catalog"
    ).fetchall()
    for cli_id, identity_hash, raw, revision, updated_at, last_complete_at in rows:
        payload = _decode_snapshot(raw)
        if payload is None:
            continue
        payload.update(revision=revision, updated_at=updated_at, last_complete_at=last_complete_at)
        catalogs[str(cli_id)] = (str(identity_hash), payload)
    return catalogs


def read_mcp_catalog(connection: sqlite3.Connection, cli_id: str, identity_hash: str) -> dict[str, object] | None:
    row = connection.execute(
        "select catalog_json from local_mcp_catalog where cli_id = ? and identity_hash = ?",
        (cli_id, identity_hash),
    ).fetchone()
    return _decode_snapshot(row[0]) if row is not None else None


def read_mcp_skill_page(
    connection: sqlite3.Connection,
    cli_id: str,
    identity_hash: str,
    *,
    offset: int,
    search: str,
    expected_revision: int | None,
) -> dict[str, object]:
    if (
        type(offset) is not int
        or not 0 <= offset <= 1000
        or not isinstance(search, str)
        or len(search) > 128
        or (expected_revision is not None and (type(expected_revision) is not int or expected_revision < 1))
    ):
        raise ValueError("invalid_mcp_skill_page")
    row = connection.execute(
        "select catalog_json, revision from local_mcp_catalog where cli_id = ? and identity_hash = ?",
        (cli_id, identity_hash),
    ).fetchone()
    if row is None:
        raise ValueError("mcp_skills_unavailable")
    snapshot = _decode_snapshot(row[0])
    if snapshot is None:
        raise ValueError("mcp_skills_unavailable")
    if expected_revision is not None and row[1] != expected_revision:
        raise ValueError("mcp_skill_catalog_changed")
    catalog = snapshot.get("skills_catalog")
    entries = catalog.get("entries") if isinstance(catalog, dict) else None
    if not isinstance(entries, list) or len(entries) > 1000:
        raise ValueError("mcp_skills_unavailable")
    if any(not isinstance(entry, dict) or entry.get("connection_identity_hash") != identity_hash for entry in entries):
        raise ValueError("mcp_skills_unavailable")
    selected = [
        entry
        for entry in entries
        if search.casefold()
        in f"{entry.get('name', '')} {entry.get('description', '')} {entry.get('uri', '')}".casefold()
    ]
    selected.sort(key=lambda entry: (str(entry.get("name", "")), str(entry.get("uri", ""))))
    return {
        "entries": selected[offset : offset + 50],
        "revision": row[1],
        "next_offset": offset + 50 if offset + 50 < len(selected) else None,
        "known_count": len(entries),
        "matched_count": len(selected),
        "activation_supported": False,
    }


def catalog_tool_authority_matches(catalog: object, name: str, live_authority_hash: object) -> bool:
    if not isinstance(catalog, dict) or not isinstance(live_authority_hash, str):
        return False
    hashes = catalog.get("authority_hashes")
    if isinstance(hashes, dict):
        return hashes.get(name) == live_authority_hash
    tools = catalog.get("tools")
    if not isinstance(tools, list):
        return False
    cached = next((tool for tool in tools if isinstance(tool, dict) and tool.get("name") == name), None)
    if cached is None:
        return False
    return tool_definition_authority_hash(cached) == live_authority_hash


def read_mcp_tool_authority(
    connection: sqlite3.Connection,
    cli_id: str,
    identity_hash: str,
    tool_name: str | None,
) -> dict[str, object] | None:
    row = connection.execute(
        "select revision from local_mcp_catalog where cli_id = ? and identity_hash = ?",
        (cli_id, identity_hash),
    ).fetchone()
    if row is None:
        return None
    query = """select tool_name, authority_hash from local_mcp_tool_authority
               where cli_id = ? and identity_hash = ? and catalog_revision = ?"""
    parameters: tuple[object, ...] = (cli_id, identity_hash, row[0])
    if tool_name is not None:
        query += " and tool_name = ?"
        parameters += (tool_name,)
    return {"authority_hashes": dict(connection.execute(query, parameters).fetchall())}


def rebuild_tool_authority(
    connection: sqlite3.Connection,
    cli_id: str,
    identity_hash: str,
    raw: object,
    revision: int,
) -> None:
    """Rebuild inside the catalog transaction; invalid/missing evidence never permits a tool."""
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


def tool_definition_authority_hash(definition: object) -> str | None:
    if not isinstance(definition, dict) or not isinstance(definition.get("inputSchema"), dict):
        return None
    try:
        return sha256(_authority_shape(definition).encode("utf-8")).hexdigest()
    except (ValueError, TypeError, RecursionError):
        return None


def write_mcp_catalog(
    connection: sqlite3.Connection,
    cli_id: str,
    *,
    identity_hash: str | None,
    catalog: McpCatalogResult,
    seen_at: str | None,
    expected_revision: int | None = None,
) -> set[str]:
    """Called inside the same transaction as the command catalog update."""

    observation = connection.execute(
        "select identity_hash, surface from local_cli_observation where cli_id = ?", (cli_id,)
    ).fetchone()
    if not identity_hash or not seen_at or observation is None:
        raise ValueError("MCP catalog requires an observed identity and refresh time")
    if observation[0] != identity_hash or observation[1] != "mcp":
        raise ValueError("MCP catalog identity changed during discovery")
    prior_row = connection.execute(
        "select identity_hash, catalog_json, revision, last_complete_at from local_mcp_catalog where cli_id = ?",
        (cli_id,),
    ).fetchone()
    current_revision = int(prior_row[2]) if prior_row is not None and prior_row[0] == identity_hash else 0
    if expected_revision is not None and expected_revision != current_revision:
        raise ValueError("mcp_catalog_revision_conflict")
    prior: dict[str, object] = {}
    last_complete_at: str | None = None
    revision = 1
    if prior_row is not None:
        revision = int(prior_row[2]) + 1
        if prior_row[0] == identity_hash:
            prior = _decode_snapshot(prior_row[1]) or {}
            last_complete_at = prior_row[3]
    tools_by_name: dict[str, dict[str, object]] = {}
    previous_tools = prior.get("tools")
    previous_by_name = (
        {tool["name"]: tool for tool in previous_tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)}
        if isinstance(previous_tools, list)
        else {}
    )
    review_ids: set[str] = set()
    added: set[str] = set()
    authority_changed: set[str] = set()
    listed: set[str] = set()
    if not catalog.complete and isinstance(previous_tools, list):
        for tool in previous_tools:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                tools_by_name[tool["name"]] = tool
    for tool in catalog.tools:
        name = tool.get("name")
        if not isinstance(name, str) or not name or name != name.strip():
            raise ValueError("invalid MCP catalog tool identity")
        previous = previous_by_name.get(name)
        listed.add(name)
        if previous is None:
            added.add(name)
        elif _authority_shape(previous) != _authority_shape(tool):
            authority_changed.add(name)
        if name in added or name in authority_changed:
            review_ids.add(slug_local_cli_command_id(name))
        tools_by_name[name] = tool
    missing = set(previous_by_name) - listed
    removed = missing if catalog.complete else set()
    review_ids.update(slug_local_cli_command_id(name) for name in removed)
    if len(tools_by_name) > _MAX_SNAPSHOT_TOOLS:
        raise ValueError("MCP catalog snapshot exceeds its tool limit")
    payload: dict[str, object] = {
        "tools": list(tools_by_name.values()),
        "complete": catalog.complete,
        "stale": not catalog.complete and bool(prior),
        "reason": catalog.reason,
        "pages": catalog.pages,
        "cache_scope": catalog.cache_scope,
        "cache_ttl_ms": catalog.cache_ttl_ms,
        "fresh_until": (
            _fresh_until(catalog.cache_received_at or seen_at, catalog.cache_ttl_ms) if catalog.complete else None
        ),
        "listed_count": len(catalog.tools),
        "known_count": len(tools_by_name),
        "changes": {
            "added": sorted(added),
            "changed": sorted(authority_changed),
            "removed": sorted(removed),
            "stale": sorted(missing) if not catalog.complete else [],
        },
        "protocol_version": catalog.protocol_version or prior.get("protocol_version"),
        "server_info": catalog.server_info if catalog.server_info is not None else prior.get("server_info"),
        "capabilities": catalog.capabilities if catalog.capabilities is not None else prior.get("capabilities"),
        "skills_catalog": _skill_metadata_snapshot(catalog, prior, identity_hash=identity_hash),
    }
    raw = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(raw.encode("utf-8")) > _MAX_SNAPSHOT_BYTES:
        raise ValueError("MCP catalog snapshot exceeds its byte limit")
    if catalog.complete:
        last_complete_at = seen_at
    connection.execute(
        """insert into local_mcp_catalog
        (cli_id, identity_hash, catalog_json, revision, updated_at, last_complete_at)
        values (?, ?, ?, ?, ?, ?)
        on conflict(cli_id) do update set identity_hash = excluded.identity_hash,
        catalog_json = excluded.catalog_json, revision = excluded.revision,
        updated_at = excluded.updated_at, last_complete_at = excluded.last_complete_at""",
        (cli_id, identity_hash, raw, revision, seen_at, last_complete_at),
    )
    rebuild_tool_authority(connection, cli_id, identity_hash, raw, revision)
    return review_ids


def _skill_metadata_snapshot(
    catalog: McpCatalogResult,
    prior: dict[str, object],
    *,
    identity_hash: str,
) -> dict[str, object]:
    declared = mcp_skills_declared(catalog.capabilities, protocol_version=catalog.protocol_version or "")
    previous = prior.get("skills_catalog")
    origin_changed = any(entry.get("connection_identity_hash") != identity_hash for entry in catalog.skills)
    complete = catalog.skills_complete is True and not origin_changed
    reason = "skill_origin_changed" if origin_changed else catalog.skills_reason
    known: dict[str, dict[str, object]] = {}
    if not complete and isinstance(previous, dict):
        entries = previous.get("entries")
        if isinstance(entries, list):
            known.update(
                {
                    entry["uri"]: entry
                    for entry in entries
                    if isinstance(entry, dict) and isinstance(entry.get("uri"), str)
                }
            )
    for entry in catalog.skills:
        if entry.get("connection_identity_hash") != identity_hash:
            continue
        uri = entry.get("uri")
        if isinstance(uri, str):
            if uri not in known and len(known) >= 1000:
                complete, reason = False, "skill_catalog_capacity"
                continue
            known[uri] = entry
    return {
        "declared": declared,
        "complete": complete,
        "stale": not complete and bool(known),
        "reason": reason or (None if complete else "skills_not_checked"),
        "known_count": len(known),
        "entries": list(known.values()),
        "activation_supported": False,
    }


def _fresh_until(seen_at: str | None, ttl_ms: int) -> str | None:
    # A zero TTL provides no freshness window, rather than an expired deadline.
    if not isinstance(seen_at, str) or type(ttl_ms) is not int or not 0 < ttl_ms <= 86_400_000:
        return None
    try:
        received = datetime.fromisoformat(seen_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if received.tzinfo is None:
        return None
    return (received + timedelta(milliseconds=ttl_ms)).isoformat()


def _authority_shape(tool: dict[str, object]) -> str:
    return json.dumps(
        {key: tool.get(key) for key in ("inputSchema", "outputSchema", "annotations")},
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def review_catalog_changes(
    connection: sqlite3.Connection,
    cli_id: str,
    review_ids: set[str],
    known: set[str],
    seen_at: str | None,
) -> None:
    """Reset changed/new authority to Ask while retaining explicit Deny."""

    changed = False
    # Retain decisions for retired tools as tombstones. A tool that returns
    # must not recover an old Allow or escape an explicit Deny.
    saved = {
        row[0]
        for row in connection.execute(
            "select command_id from local_cli_command_grant where cli_id = ?",
            (cli_id,),
        )
    }
    for command_id in sorted(review_ids & (known | saved)):
        previous = connection.execute(
            "select state from local_cli_command_grant where cli_id = ? and command_id = ?",
            (cli_id, command_id),
        ).fetchone()
        if previous is not None and previous[0] in {"block", "review"}:
            continue
        connection.execute(
            "insert into local_cli_command_grant (cli_id, command_id, state) values (?, ?, 'review') "
            "on conflict(cli_id, command_id) do update set state = 'review'",
            (cli_id, command_id),
        )
        changed = True
    if changed and connection.execute("select 1 from local_cli_grant where cli_id = ?", (cli_id,)).fetchone():
        connection.execute("update local_cli_authority set revision = revision + 1 where singleton = 1")
        connection.execute(
            "update local_cli_grant set revision = (select revision from local_cli_authority where singleton = 1), "
            "updated_at = ? where cli_id = ?",
            (seen_at, cli_id),
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
