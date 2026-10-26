"""Inventory collection and transmission planning for ``fleet-posture/v1``.

Items come from the local inventory table. Each send is planned against the last
snapshot Guard Cloud accepted: a first send, a requested refresh or a weekly refresh
goes out as ``full`` (or as a stream of deltas when the inventory does not fit one
request), everything else as a ``delta``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .fleet_posture_common import (
    FULL_REFRESH_AFTER,
    HARNESS_IDS,
    MAX_ITEMS_PER_SYNC,
    clip,
    digest_rows,
    keyed_digest,
    normalized_hash,
    normalized_timestamp,
    parse_timestamp,
)

if TYPE_CHECKING:
    from ..store import GuardStore

_ITEM_KINDS = {
    "skill": "skill",
    "skill_file": "skill",
    "mcp_server": "mcp_server",
    "plugin": "plugin",
    "plugin-file": "plugin",
    "extension": "plugin",
    "package": "package",
    "hook": "hook",
    "guard_hook": "hook",
}
_ITEM_SOURCES = {
    "marketplace": "marketplace",
    "project": "project",
    "workspace": "project",
    "global": "user",
    "user": "user",
    "lockfile": "lockfile",
    "config": "config",
}
# Scope names a local source can carry; ``_ITEM_SOURCES`` maps each to its contract source.
ITEM_SOURCE_SCOPES = frozenset(_ITEM_SOURCES)


def inventory_item_kind(artifact_type: object) -> str | None:
    """Contract kind of a local inventory artifact type, or ``None`` when it is not reported."""

    return _ITEM_KINDS.get(str(artifact_type or ""))


@dataclass(frozen=True)
class ReportableInventoryRow:
    """A local inventory row that fleet posture reports, with its normalized fields."""

    row: Mapping[str, object]
    kind: str
    harness: str
    name: str
    first_seen_at: str
    last_seen_at: str
    config_path: str | None


def reportable_inventory_rows(rows: Iterable[Mapping[str, object]]) -> list[ReportableInventoryRow]:
    """Rows fleet posture reports: installed, known kind and harness, named, validly timestamped.

    Rows that map to the same kind, harness, name (as sent, at most 200 characters) and config
    path collapse to the first one.
    ``inventory_items`` and the ``extensions list`` / ``mcp list`` commands both select through
    this function, so the commands show exactly what Guard Cloud can receive.
    """

    selected: dict[tuple[str, str, str, str], ReportableInventoryRow] = {}
    for row in rows:
        if row.get("removed_at"):
            continue
        if row.get("present") in (0, False, "0"):
            continue
        kind = inventory_item_kind(row.get("artifact_type"))
        harness = str(row.get("harness") or "")
        name = str(row.get("artifact_name") or "").strip()
        if kind is None or harness not in HARNESS_IDS or not name:
            continue
        first_seen = normalized_timestamp(row.get("first_seen_at"))
        last_seen = normalized_timestamp(row.get("last_seen_at"))
        if first_seen is None or last_seen is None:
            continue
        raw_path = row.get("config_path")
        config_path = raw_path if isinstance(raw_path, str) and raw_path else None
        selected.setdefault(
            (kind, harness, clip(name, 200), config_path or ""),
            ReportableInventoryRow(row, kind, harness, name, first_seen, last_seen, config_path),
        )
    return list(selected.values())


def inventory_items(store: GuardStore, *, hash_key: bytes) -> list[dict[str, object]]:
    """Installed items from the local inventory table and the last AIBOM collection, in contract shape.

    A failed read raises: an unreadable inventory must not look like an empty one,
    or an accepted sync would tell Guard Cloud that everything was uninstalled.
    """

    from .fleet_posture_aibom import fleet_inventory_rows

    items: dict[str, dict[str, object]] = {}
    for selected in reportable_inventory_rows(fleet_inventory_rows(store)):
        item: dict[str, object] = {
            "kind": selected.kind,
            "name": clip(selected.name, 200),
            "version": None,
            "hash": normalized_hash(selected.row.get("artifact_hash")),
            "harness": selected.harness,
            "source": _ITEM_SOURCES.get(str(selected.row.get("source_scope") or ""), "unknown"),
            "pathHash": keyed_digest(hash_key, selected.config_path) if selected.config_path else None,
            "firstSeenAt": selected.first_seen_at,
            "lastSeenAt": selected.last_seen_at,
        }
        items.setdefault(item_key(item), item)
    return [items[key] for key in sorted(items)]


def item_key(item: Mapping[str, object]) -> str:
    identity = "\0".join(str(item.get(part) or "") for part in ("kind", "harness", "name", "pathHash"))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def item_fingerprint(item: Mapping[str, object]) -> str:
    material = "\0".join(str(item.get(part) or "") for part in ("version", "hash", "source"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def item_digest(items: Iterable[Mapping[str, object]]) -> str:
    return digest_rows(
        (item.get("kind"), item.get("name"), item.get("version"), item.get("hash"), item.get("harness"))
        for item in items
    )


def group_by_harness(items: Iterable[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for item in items:
        grouped.setdefault(str(item["harness"]), []).append(item)
    return grouped


def previous_items(last: Mapping[str, object] | None) -> dict[str, dict[str, Any]] | None:
    if not isinstance(last, Mapping):
        return None
    raw = last.get("items")
    if not isinstance(raw, dict):
        return None
    return {str(key): dict(value) for key, value in raw.items() if isinstance(value, dict)}


def tracked(item: Mapping[str, object]) -> dict[str, object]:
    return {
        "k": item["kind"],
        "n": item["name"],
        "h": item["harness"],
        "x": item["hash"],
        "f": item_fingerprint(item),
    }


def removed_entry(tracked: Mapping[str, object]) -> dict[str, object]:
    return {"kind": tracked["k"], "name": tracked["n"], "harness": tracked["h"], "hash": tracked["x"]}


def _identity(item: Mapping[str, object]) -> tuple[object, object, object, object]:
    """What a removal entry can name: the contract carries no path hash for removals."""

    return (item.get("kind"), item.get("harness"), item.get("name"), item.get("hash"))


def stream_active(last: Mapping[str, object] | None) -> bool:
    return isinstance(last, Mapping) and last.get("fullStreaming") is True


def _needs_full(
    *,
    previous: Mapping[str, object] | None,
    last: Mapping[str, object] | None,
    force_full: bool,
    now: datetime,
) -> bool:
    """A full inventory is due on first send, on request, or after a week."""

    full_sent_at = parse_timestamp(last.get("fullSentAt")) if isinstance(last, Mapping) else None
    return force_full or previous is None or full_sent_at is None or now - full_sent_at > FULL_REFRESH_AFTER


@dataclass(frozen=True)
class InventoryPlan:
    mode: str
    items: list[dict[str, object]]
    removed: list[dict[str, object]]
    next_items: dict[str, dict[str, Any]]
    # A chunked full refresh still has items or removals left to send.
    streaming: bool
    # This send finished a full refresh.
    full_complete: bool


def plan_inventory(
    *,
    current: list[dict[str, object]],
    previous: dict[str, dict[str, Any]] | None,
    last: Mapping[str, object] | None,
    force_full: bool,
    detail: bool,
    now: datetime,
    limit: int = MAX_ITEMS_PER_SYNC,
) -> InventoryPlan:
    """Choose mode, items, removed and the next tracked-item snapshot.

    A refresh that does not fit one request streams as successive deltas. The
    tracked snapshot keeps every item and removal not yet sent, so a later request
    (including another ``full`` request from Guard Cloud) continues the stream
    instead of restarting it or forgetting pending removals.
    """

    by_key = {item_key(item): item for item in current}
    resuming = stream_active(last)
    if not detail:
        return InventoryPlan("digest_only", [], [], dict(previous or {}), resuming, False)
    refreshing = resuming or _needs_full(previous=previous, last=last, force_full=force_full, now=now)
    if refreshing and not resuming and len(current) <= limit:
        return InventoryPlan(
            "full", list(current), [], {key: tracked(item) for key, item in by_key.items()}, False, True
        )
    prior = previous or {}
    # Starting a refresh treats every current item as unknown to Guard Cloud.
    baseline = (
        prior if resuming or not refreshing else {key: value for key, value in prior.items() if key not in by_key}
    )
    changed = sorted(
        key for key, item in by_key.items() if key not in baseline or baseline[key].get("f") != item_fingerprint(item)
    )
    gone = sorted(key for key in baseline if key not in by_key)
    sent_changed = changed[:limit]
    sent_gone = gone[:limit]
    present = {_identity(item) for item in current}
    removed = [
        removed_entry(baseline[key])
        for key in sent_gone
        if (baseline[key].get("k"), baseline[key].get("h"), baseline[key].get("n"), baseline[key].get("x"))
        not in present
    ]
    next_items: dict[str, dict[str, Any]] = {key: dict(value) for key, value in baseline.items()}
    for key in sent_gone:
        next_items.pop(key, None)
    for key in sent_changed:
        next_items[key] = tracked(by_key[key])
    unfinished = len(changed) > limit or len(gone) > limit
    return InventoryPlan(
        "delta",
        [by_key[key] for key in sent_changed],
        removed,
        next_items,
        refreshing and unfinished,
        refreshing and not unfinished,
    )
