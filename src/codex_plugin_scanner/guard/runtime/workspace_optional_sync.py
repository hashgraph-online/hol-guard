"""Optional telemetry admission cannot interrupt mandatory policy synchronization."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING

from .optional_telemetry_sync import sync_nonessential_telemetry as _sync_telemetry
from .workspace_preferences import effective_receipt_redaction_level, optional_upload_allowed

if TYPE_CHECKING:
    from ..store import GuardStore


def sync_nonessential_telemetry(
    store: GuardStore,
    *,
    pain_signals: Callable[[], int],
    guard_events: Callable[[], dict[str, object]],
    authorization_errors: tuple[type[BaseException], ...],
) -> dict[str, object]:
    if not optional_upload_allowed(store, telemetry=True):
        return {
            "telemetry_status": "paused",
            "pain_signals_uploaded": 0,
            "pain_signals_upload_status": "paused",
            "pain_signals_upload_reason": "optional_upload_paused",
            "guard_events_v1": None,
            "guard_events_upload_status": "paused",
            "guard_events_upload_reason": "optional_upload_paused",
        }
    return _sync_telemetry(
        store,
        pain_signals=pain_signals,
        guard_events=guard_events,
        authorization_errors=authorization_errors,
    )


def prepare_receipt_batch(
    store: GuardStore,
    *,
    workspace_id: str | None,
    receipt_batch: list[dict[str, object]],
    sync_context: dict[str, object],
    serialize: Callable[[list[dict[str, object]], str], object],
) -> tuple[list[dict[str, object]], bytes, bool]:
    """Recheck every send, including authentication retries, without rebinding captured rows."""
    if store.get_cloud_workspace_id() != workspace_id:
        raise ValueError("workspace_preferences_scope_changed")
    paused = bool(receipt_batch) and not optional_upload_allowed(store)
    sent_rows = [] if paused else receipt_batch
    body = json.dumps(
        {
            "receipts": serialize(sent_rows, effective_receipt_redaction_level(store)),
            "syncContext": sync_context,
        }
    ).encode("utf-8")
    if store.get_cloud_workspace_id() != workspace_id:
        raise ValueError("workspace_preferences_scope_changed")
    return sent_rows, body, paused
