"""Inventory rows for ``fleet-posture/v1``.

The native runtime selects the rows fleet posture reports, shapes them into
contract items and plans each transmission (``fleet_posture_inventory.rs``).
This module reads the local rows and projects them across that boundary.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..store import GuardStore

# The native request parser refuses any JSON array or object wider than this, so
# rows and tracked items cross in chunks the runtime joins back in order.
_NATIVE_JSON_WIDTH = 4096
# The row fields the native selection reads.
_ROW_FIELDS = (
    "removed_at",
    "present",
    "artifact_type",
    "harness",
    "artifact_name",
    "first_seen_at",
    "last_seen_at",
    "config_path",
    "artifact_hash",
    "source_scope",
)


def projected_rows(rows: Iterable[Mapping[str, object]]) -> list[list[dict[str, object]]]:
    """Each row's selection fields, in order, in chunks the native request parser accepts."""

    projected = [{key: row.get(key) for key in _ROW_FIELDS if key in row} for row in rows]
    return [projected[start : start + _NATIVE_JSON_WIDTH] for start in range(0, len(projected), _NATIVE_JSON_WIDTH)]


def chunked_last(last: dict[str, Any] | None) -> dict[str, Any] | None:
    """The last sent state with its tracked items split into chunks the native request parser accepts."""

    items = last.get("items") if last is not None else None
    if last is None or not isinstance(items, dict):
        return last
    pairs = list(items.items())
    chunks = [dict(pairs[start : start + _NATIVE_JSON_WIDTH]) for start in range(0, len(pairs), _NATIVE_JSON_WIDTH)]
    return {**last, "items": chunks}


def committed_state(last: dict[str, Any] | None, next_state: dict[str, Any]) -> dict[str, Any]:
    """The state to commit: the runtime replies with a patch to the tracked items, not all of them."""

    stored = last.get("items") if last is not None else None
    items = dict(stored) if isinstance(stored, dict) else {}
    state = dict(next_state)
    patch = state.pop("itemsPatch", None)
    if isinstance(patch, dict):
        for key in patch.get("remove") or ():
            items.pop(key, None)
        items.update(patch.get("set") or {})
    state["items"] = items
    return state


def store_home(store: object) -> Path | None:
    home = getattr(store, "guard_home", None)
    return home if isinstance(home, Path) else None


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


def reportable_inventory_rows(
    rows: Iterable[Mapping[str, object]], *, guard_home: Path | None = None
) -> list[ReportableInventoryRow]:
    """Rows fleet posture reports, so ``extensions list`` and ``mcp list`` show what Guard Cloud can receive."""

    # Imported here: `extensions list` and `mcp list` sit on the CLI help path.
    from ..native_runner_authority import native_runner_authority

    source = list(rows)
    payload = native_runner_authority("fleet_inventory_rows", {"rows": projected_rows(source)}, guard_home)
    selected: list[Any] = payload["rows"]
    return [
        ReportableInventoryRow(
            source[entry["index"]],
            entry["kind"],
            entry["harness"],
            entry["name"],
            entry["first_seen_at"],
            entry["last_seen_at"],
            entry["config_path"],
        )
        for entry in selected
    ]


def inventory_items(store: GuardStore, *, hash_key: bytes) -> list[dict[str, object]]:
    """Installed items from the local inventory table and the last AIBOM collection, in contract shape.

    A failed read raises: an unreadable inventory must not look like an empty one,
    or an accepted sync would tell Guard Cloud that everything was uninstalled.
    """

    from ..native_runner_authority import native_runner_authority
    from .fleet_posture_aibom import fleet_inventory_rows

    payload = native_runner_authority(
        "fleet_inventory_items",
        {"rows": projected_rows(fleet_inventory_rows(store)), "hash_key": hash_key.decode("utf-8")},
        store_home(store),
    )
    items: list[dict[str, object]] = payload["items"]
    return items
