"""Adapters bridging GuardStore queries to MCP-safe result dicts.

These adapters call bounded GuardStore methods and produce raw dicts
that the sanitizers will clean before returning to the MCP client.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .schemas import (
    DEFAULT_SEARCH_LIMIT,
    MAX_SEARCH_LIMIT,
    make_opaque_id,
)

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.store import GuardStore


def search_receipts(store: GuardStore, query: str, limit: int = DEFAULT_SEARCH_LIMIT) -> list[dict[str, object]]:
    bounded_limit = min(max(limit, 1), MAX_SEARCH_LIMIT)
    receipts = store.list_receipts(limit=bounded_limit)
    results: list[dict[str, object]] = []
    q = query.lower().strip() if query else ""
    for r in receipts:
        artifact_name = str(r.get("artifact_name") or "")
        harness = str(r.get("harness") or "")
        decision = str(r.get("policy_decision") or "")
        if q and q not in f"{artifact_name} {harness} {decision}".lower():
            continue
        results.append(_receipt_to_search_result(r))
    return results[:bounded_limit]


def fetch_receipt(store: GuardStore, opaque_id: str) -> dict[str, object] | None:
    """Resolve a hash-based opaque ID back to a receipt."""
    from .schemas import make_opaque_id

    receipts = store.list_receipts(limit=MAX_SEARCH_LIMIT)
    for r in receipts:
        rid = str(r.get("receipt_id") or "")
        if make_opaque_id("receipt", rid) == opaque_id:
            return _receipt_to_fetch_result(r)
    return None


def search_inventory(store: GuardStore, query: str, limit: int = DEFAULT_SEARCH_LIMIT) -> list[dict[str, object]]:
    bounded_limit = min(max(limit, 1), MAX_SEARCH_LIMIT)
    items = store.list_inventory()
    results: list[dict[str, object]] = []
    q = query.lower().strip() if query else ""
    for item in items:
        name = str(item.get("artifact_name") or "")
        harness = str(item.get("harness") or "")
        if q and q not in f"{name} {harness}".lower():
            continue
        results.append(_inventory_to_search_result(item))
    return results[:bounded_limit]


def fetch_inventory(store: GuardStore, opaque_id: str) -> dict[str, object] | None:
    """Resolve a hash-based opaque ID back to an inventory item."""
    from .schemas import make_opaque_id

    items = store.list_inventory()
    for item in items:
        aid = str(item.get("artifact_id") or "")
        if make_opaque_id("inventory", aid) == opaque_id:
            return _inventory_to_fetch_result(item)
    return None


def get_status(store: GuardStore) -> dict[str, object]:
    receipt_count = store.count_receipts()
    try:
        inventory = store.list_inventory()
        inventory_count = len(inventory)
    except Exception:
        inventory_count = 0
    return {
        "cliAvailable": True,
        "receiptCount": receipt_count,
        "inventoryCount": inventory_count,
    }


def _receipt_to_search_result(r: dict[str, object]) -> dict[str, object]:
    return {
        "id": make_opaque_id("receipt", str(r.get("receipt_id") or "")),
        "title": str(r.get("artifact_name") or "Guard receipt"),
        "kind": "receipt",
        "harness": str(r.get("harness") or ""),
        "decision": str(r.get("policy_decision") or ""),
        "changedSinceLastApproval": bool(r.get("changed_capabilities")),
    }


def _receipt_to_fetch_result(r: dict[str, object]) -> dict[str, object]:
    text = (
        f"Decision: {r.get('policy_decision', 'unknown')}\n"
        f"Harness: {r.get('harness', 'unknown')}\n"
        f"Artifact: {r.get('artifact_name', 'unknown')}"
    )
    return {
        "id": make_opaque_id("receipt", str(r.get("receipt_id") or "")),
        "title": str(r.get("artifact_name") or "Guard receipt"),
        "kind": "receipt",
        "harness": str(r.get("harness") or ""),
        "decision": str(r.get("policy_decision") or ""),
        "text": text,
        "truncated": False,
        "changedSinceLastApproval": bool(r.get("changed_capabilities")),
    }


def _inventory_to_search_result(item: dict[str, object]) -> dict[str, object]:
    return {
        "id": make_opaque_id("inventory", str(item.get("artifact_id") or "")),
        "title": str(item.get("artifact_name") or "Inventory item"),
        "kind": "inventory",
        "harness": str(item.get("harness") or ""),
        "decision": str(item.get("last_policy_action") or "unknown"),
        "changedSinceLastApproval": item.get("last_changed_at") != item.get("last_approved_at"),
    }


def _inventory_to_fetch_result(item: dict[str, object]) -> dict[str, object]:
    text = (
        f"Artifact: {item.get('artifact_name', 'unknown')}\n"
        f"Harness: {item.get('harness', 'unknown')}\n"
        f"Type: {item.get('artifact_type', 'unknown')}\n"
        f"Present: {item.get('present', 'unknown')}"
    )
    return {
        "id": make_opaque_id("inventory", str(item.get("artifact_id") or "")),
        "title": str(item.get("artifact_name") or "Inventory item"),
        "kind": "inventory",
        "harness": str(item.get("harness") or ""),
        "decision": str(item.get("last_policy_action") or "unknown"),
        "text": text,
        "truncated": False,
        "changedSinceLastApproval": item.get("last_changed_at") != item.get("last_approved_at"),
    }
