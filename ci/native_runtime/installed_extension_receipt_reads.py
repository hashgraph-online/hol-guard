"""Durable native receipt reads shared by the installed extension probes."""

from __future__ import annotations

from codex_plugin_scanner.guard.native_guard_store import NativeGuardStoreUnavailable
from codex_plugin_scanner.guard.store import GuardStore


def persisted_native_receipt_ids(store: GuardStore) -> set[str]:
    """Return the durable receipt identities without exposing receipt contents."""

    with store._connect() as connection:
        rows = connection.execute("select decision_id from native_hook_decision_receipts").fetchall()
    return {row["decision_id"] for row in rows if isinstance(row["decision_id"], str)}


def readable_native_receipt(store: GuardStore, decision_id: str) -> dict[str, object] | None:
    """Read one receipt, treating a store that cannot answer yet as not persisted.

    A poll then keeps waiting and, at its deadline, reports its own diagnostic
    instead of stopping on the first unanswered read.
    """

    try:
        return store.get_native_decision_receipt(decision_id)
    except NativeGuardStoreUnavailable:
        return None
