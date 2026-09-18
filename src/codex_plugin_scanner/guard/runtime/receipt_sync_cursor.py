"""Monotonic receipt upload selection and bounded cursor recovery."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..store import GuardStore

_RECEIPT_SYNC_CURSOR_PAGE_SIZE = 200
_RECEIPT_SYNC_CURSOR_BACKFILL_ROWS = 200


def _receipt_sync_cursor_rowid(store: GuardStore) -> int | None:
    payload = store.get_sync_payload("receipt_sync_cursor")
    if not isinstance(payload, dict):
        return None
    value = payload.get("last_rowid")
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            return int(stripped)
    return None


def _receipt_sync_rows_for_upload(store: GuardStore, *, cursor_rowid: int | None) -> list[dict[str, object]]:
    if cursor_rowid is None:
        return store.list_receipts_since_rowid(after_rowid=None, limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    latest_rowid = store.latest_receipt_rowid()
    if latest_rowid is None:
        return []
    if cursor_rowid > latest_rowid:
        backfill_after = max(latest_rowid - _RECEIPT_SYNC_CURSOR_BACKFILL_ROWS, 0)
        return store.list_receipts_since_rowid(after_rowid=backfill_after, limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)
    return store.list_receipts_since_rowid(after_rowid=cursor_rowid, limit=_RECEIPT_SYNC_CURSOR_PAGE_SIZE)


def _receipt_sync_cursor_rowids_from_batch(
    receipt_batch: Sequence[Mapping[str, object]],
    *,
    cursor_receipt_ids: set[object],
) -> list[object]:
    return [item.get("receipt_rowid") for item in receipt_batch if item.get("receipt_id") in cursor_receipt_ids]


def _persist_receipt_sync_cursor(
    *,
    store: GuardStore,
    latest_uploaded_rowid: int | None,
    synced_at: str,
) -> None:
    if latest_uploaded_rowid is None:
        return
    payload: dict[str, object] = {
        "last_rowid": latest_uploaded_rowid,
        "synced_at": synced_at,
    }
    store.set_sync_payload("receipt_sync_cursor", payload, synced_at)
