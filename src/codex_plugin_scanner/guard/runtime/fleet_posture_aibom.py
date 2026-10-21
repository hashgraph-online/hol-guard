"""AIBOM-detected items as fleet posture inventory rows.

Guard writes a row to its local inventory table only when it scans an artifact
itself: a launch through ``hol-guard run``, an install or a consumer scan. Machines
protected through hooks rarely take those paths, so their inventory table stays
empty while the AIBOM collection sees every skill, MCP server, plugin and hook on
the machine. Each AIBOM collection stores a compact copy of what it found here,
and fleet posture reports the union of both sources.

AIBOM items carry redacted paths (``{home}/...``). The collection's home and
workspace directories are stored with the rows so each path can be restored to
the absolute form the inventory table uses: the same artifact then dedupes and
hashes the same way whichever source saw it.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .fleet_posture_common import HARNESS_IDS, normalized_timestamp
from .fleet_posture_inventory import ITEM_SOURCE_SCOPES, inventory_item_kind

if TYPE_CHECKING:
    from ..store import GuardStore

AIBOM_ITEMS_STATE_KEY = "fleet_posture_aibom_items"
# One machine rarely carries more than a few hundred items; the cap bounds the stored row.
MAX_AIBOM_ROWS = 5_000
_PROJECT_SCOPES = frozenset({"project", "workspace"})


def _resolved(path: Path | None) -> Path | None:
    if path is None:
        return None
    try:
        return path.expanduser().resolve()
    except (OSError, RuntimeError):
        return None


def _absolute_path(redacted: object, home_dir: Path | None, workspace_dir: Path | None) -> str | None:
    """The absolute path an AIBOM ``configPath`` was redacted from, when it can be restored."""

    if not isinstance(redacted, str) or not redacted:
        return None
    for prefix, root in (("{home}/", home_dir), ("{workspace}/", workspace_dir)):
        if redacted.startswith(prefix):
            return str(root / redacted[len(prefix) :]) if root is not None else redacted
    return redacted


def _path_identity(path: object) -> str:
    if not isinstance(path, str) or not path:
        return ""
    return os.path.realpath(path) if os.path.isabs(path) else path


def _row_key(row: Mapping[str, object]) -> str:
    kind = inventory_item_kind(row.get("artifact_type")) or ""
    name = str(row.get("artifact_name") or "").strip()
    return "\0".join((str(row.get("harness") or ""), kind, name, _path_identity(row.get("config_path"))))


def _installed(row: Mapping[str, object]) -> bool:
    return not row.get("removed_at") and row.get("present") not in (0, False, "0")


def _source_scope(item_id: str, harness: str, config_path: str | None, workspace_dir: Path | None) -> str | None:
    """The item's scope from its id when the id names one, else from where its file lives."""

    for segment in item_id.split(":")[1:-1]:
        scope = segment.removeprefix(f"{harness}-")
        if scope in ITEM_SOURCE_SCOPES:
            return scope
    if not config_path or not os.path.isabs(config_path):
        return None
    # Without a scanned workspace the collection only reads user-wide configuration.
    if workspace_dir is not None and Path(config_path).is_relative_to(workspace_dir):
        return "project"
    return "global"


def _stored(store: GuardStore) -> dict[str, object]:
    raw = store.get_sync_payload(AIBOM_ITEMS_STATE_KEY)
    return raw if isinstance(raw, dict) else {}


def _stored_rows(store: GuardStore) -> list[dict[str, object]]:
    rows = _stored(store).get("rows")
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _item_rows(snapshot: Any, home_dir: Path | None, workspace_dir: Path | None) -> Iterable[dict[str, object]]:
    harness = str(getattr(snapshot, "agent_type", "") or "")
    seen_at = normalized_timestamp(getattr(snapshot, "generated_at", None))
    if harness not in HARNESS_IDS or seen_at is None:
        return
    for item in getattr(snapshot, "items", ()) or ():
        metadata = item.metadata if isinstance(getattr(item, "metadata", None), dict) else {}
        # An explicit artifact type decides; the item kind only stands in when there is none,
        # so a type fleet posture does not report (a Cline host, say) never becomes a plugin.
        artifact_type = str(metadata.get("artifactType") or getattr(item, "item_kind", "") or "")
        name = str(getattr(item, "display_name", "") or "").strip()
        if inventory_item_kind(artifact_type) is None or not name:
            continue
        config_path = _absolute_path(metadata.get("configPath"), home_dir, workspace_dir)
        yield {
            "artifact_type": artifact_type,
            "harness": harness,
            "artifact_name": name,
            "artifact_hash": getattr(item, "content_hash", None),
            "source_scope": _source_scope(str(getattr(item, "item_id", "") or ""), harness, config_path, workspace_dir),
            "config_path": config_path,
            "first_seen_at": seen_at,
            "last_seen_at": seen_at,
            "present": True,
        }


# The daemon refresh loop, request handlers and the CLI can collect at the same
# time. The thread lock orders collectors in one process and the store's
# advisory file lock orders processes, so one read-modify-write of the stored
# rows never drops another.
_ROWS_LOCK = threading.Lock()


def remember_aibom_items(
    store: GuardStore,
    snapshots: Iterable[Any],
    *,
    now: str,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
) -> int:
    """Store the reportable items of one AIBOM collection, keeping when each was first seen.

    The collection replaces the user-wide items and the project items of the
    workspace it scanned, so an item it no longer finds leaves the next fleet
    posture as a removal. Project items of other workspaces stay until a
    collection scans their workspace again.
    """

    home = _resolved(home_dir)
    workspace = _resolved(workspace_dir)
    with _ROWS_LOCK, store.hold_aibom_items_lock():
        return _replace_rows(store, snapshots, now=now, home=home, workspace=workspace)


def _replace_rows(
    store: GuardStore,
    snapshots: Iterable[Any],
    *,
    now: str,
    home: Path | None,
    workspace: Path | None,
) -> int:
    scanned = str(workspace) if workspace is not None else None
    previous = _stored_rows(store)
    first_seen = {_row_key(row): row.get("first_seen_at") for row in previous}
    rows: dict[str, dict[str, object]] = {}
    for snapshot in snapshots:
        for row in _item_rows(snapshot, home, workspace):
            key = _row_key(row)
            if key in rows or len(rows) >= MAX_AIBOM_ROWS:
                continue
            earlier = normalized_timestamp(first_seen.get(key))
            if earlier is not None:
                row["first_seen_at"] = earlier
            if row["source_scope"] in _PROJECT_SCOPES:
                row["collection_workspace"] = scanned
            rows[key] = row
    for row in previous:
        kept_workspace = row.get("collection_workspace")
        if row.get("source_scope") not in _PROJECT_SCOPES or kept_workspace is None or kept_workspace == scanned:
            continue
        key = _row_key(row)
        if key not in rows and len(rows) < MAX_AIBOM_ROWS:
            rows[key] = row
    store.set_sync_payload(AIBOM_ITEMS_STATE_KEY, {"collectedAt": now, "rows": list(rows.values())}, now)
    return len(rows)


def fleet_inventory_rows(store: GuardStore) -> list[dict[str, object]]:
    """Local inventory rows followed by the AIBOM-detected rows the table does not already hold."""

    table_rows = store.list_inventory()
    # A row Guard marked removed does not hide the same item found installed again.
    known = {_row_key(row) for row in table_rows if _installed(row)}
    return [*table_rows, *(row for row in _stored_rows(store) if _row_key(row) not in known)]
