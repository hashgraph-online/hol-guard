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

The native runtime (``fleet_aibom_rows``) decides which rows a collection
stores and which stored rows the table already holds; this module holds the
locks and reads and writes the stored state.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .fleet_posture_inventory import store_home

if TYPE_CHECKING:
    from ..store import GuardStore

AIBOM_ITEMS_STATE_KEY = "fleet_posture_aibom_items"
# The native request parser refuses any JSON array wider than this, so rows and
# items cross in chunks the runtime joins back in order.
_NATIVE_JSON_WIDTH = 4096
# The row fields the native runtime reads to key, dedupe and keep rows.
_ROW_FIELDS = (
    "harness",
    "artifact_type",
    "artifact_name",
    "config_path",
    "removed_at",
    "present",
    "first_seen_at",
    "source_scope",
    "collection_workspace",
)


def _chunks(values: list[Any]) -> list[list[Any]]:
    return [values[start : start + _NATIVE_JSON_WIDTH] for start in range(0, len(values), _NATIVE_JSON_WIDTH)]


def _projected(rows: Iterable[Mapping[str, object]]) -> list[list[dict[str, object]]]:
    return _chunks([{key: row.get(key) for key in _ROW_FIELDS if key in row} for row in rows])


def _resolved(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.expanduser().resolve())
    except (OSError, RuntimeError):
        return None


def _text(value: object) -> str:
    return str(value or "")


def _stored_rows(store: GuardStore) -> list[dict[str, object]]:
    raw = store.get_sync_payload(AIBOM_ITEMS_STATE_KEY)
    rows = raw.get("rows") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        return []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _snapshot_request(snapshot: Any) -> tuple[dict[str, object], list[Any]]:
    items: list[Any] = list(getattr(snapshot, "items", ()) or ())
    projected: list[dict[str, object]] = []
    for item in items:
        metadata = item.metadata if isinstance(getattr(item, "metadata", None), dict) else {}
        config_path = metadata.get("configPath")
        projected.append(
            {
                "item_id": _text(getattr(item, "item_id", "")),
                "item_kind": _text(getattr(item, "item_kind", "")),
                "artifact_type": _text(metadata.get("artifactType")),
                "name": _text(getattr(item, "display_name", "")),
                "config_path": config_path if isinstance(config_path, str) else None,
            }
        )
    generated_at = getattr(snapshot, "generated_at", None)
    request: dict[str, object] = {
        "harness": _text(getattr(snapshot, "agent_type", "")),
        "generated_at": generated_at if isinstance(generated_at, str) else None,
        "items": _chunks(projected),
    }
    return request, items


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
    collection scans their workspace again. The native runtime decides the
    rows; when it cannot answer, the stored rows stay as they were.
    """

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    requests = [_snapshot_request(snapshot) for snapshot in snapshots]
    with _ROWS_LOCK, store.hold_aibom_items_lock():
        previous = _stored_rows(store)
        try:
            payload = native_runner_authority(
                "fleet_aibom_rows",
                {
                    "op": "remember",
                    "snapshots": [request for request, _ in requests],
                    "previous": _projected(previous),
                    "home": _resolved(home_dir),
                    "workspace": _resolved(workspace_dir),
                },
                store_home(store),
            )
        except NativeRunnerAuthorityError:
            return 0
        rows: list[dict[str, object]] = []
        for row in payload["rows"]:
            item = requests[row.pop("snapshot")][1][row.pop("item")]
            rows.append({**row, "artifact_hash": getattr(item, "content_hash", None), "present": True})
        rows.extend(previous[index] for index in payload["kept"])
        store.set_sync_payload(AIBOM_ITEMS_STATE_KEY, {"collectedAt": now, "rows": rows}, now)
        return len(rows)


def fleet_inventory_rows(store: GuardStore) -> list[dict[str, object]]:
    """Local inventory rows followed by the AIBOM-detected rows the table does not already hold.

    A failed read raises, as the inventory table read does: an unreadable
    inventory must not look like an empty one.
    """

    from ..native_runner_authority import native_runner_authority

    table_rows = store.list_inventory()
    stored = _stored_rows(store)
    if not stored:
        return list(table_rows)
    payload = native_runner_authority(
        "fleet_aibom_rows",
        {"op": "union", "table": _projected(table_rows), "stored": _projected(stored)},
        store_home(store),
    )
    return [*table_rows, *(stored[index] for index in payload["kept"])]
