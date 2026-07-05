"""Dedicated live request cloud sync with cursor-based pagination.

This module replaces the capped snapshot approach that was embedded in the
command queue lease flow. Instead of piggybacking a bounded snapshot on each
lease request, this module:

1. Builds events from the local approval_requests table using cursor-based
   pagination for ALL statuses (pending AND resolved).
2. POSTs them to the portal's /api/guard/live-requests/sync endpoint.
3. Persists the returned cursor for incremental sync on subsequent cycles.

This eliminates the root cause of stale "pending" rows accumulating in the
Cloud when >125 pending requests existed locally.
"""

import json
import logging
import urllib.error
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..redaction import redact_text
from ..review_contracts import (
    GuardReviewContractError,
    build_local_review_request_claim,
    guard_review_oauth_metadata,
)
from ..store import GuardStore
from .local_request_snapshots import (
    _cloud_safe_local_request_payload,
    _resolve_cloud_receipt_redaction_level,
)

if TYPE_CHECKING:
    pass

_LOGGER = logging.getLogger(__name__)

LIVE_REQUEST_SYNC_PROTOCOL_VERSION = "1"
LIVE_REQUEST_SYNC_BATCH_SIZE = 200
LIVE_REQUEST_SYNC_MAX_BATCHES = 10
LIVE_REQUEST_SYNC_CURSOR_KEY = "guard_live_request_sync_cursor"
LIVE_REQUEST_SYNC_STATE_KEY = "guard_live_request_sync_state"

_EVENT_TYPE_MAP = {
    "pending": "request_created",
    "resolved": "request_resolved",
    "expired": "request_expired",
    "superseded": "request_superseded",
}

_DISPLAY_PROVENANCE_REDACTED = "redacted"
_DISPLAY_PROVENANCE_RAW = "raw"
_DISPLAY_PROVENANCE_DERIVED = "derived"
_DISPLAY_PROVENANCE_WITHHELD = "withheld"

_LOCAL_EVENT_SEQUENCE_KEY = "guard_live_request_local_event_sequence"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_sync_url(auth_context: dict[str, object], path: str) -> str:
    sync_url = str(auth_context.get("sync_url") or "")
    if not sync_url:
        raise RuntimeError("Guard sync URL is not configured.")
    base = sync_url.rstrip("/")
    return f"{base}{path}"


def _load_sync_cursor(store: GuardStore) -> str | None:
    payload = store.get_sync_payload(LIVE_REQUEST_SYNC_CURSOR_KEY)
    if isinstance(payload, dict):
        cursor = payload.get("inbound_cursor")
        if isinstance(cursor, str) and cursor:
            return cursor
    return None


def _save_sync_cursor(store: GuardStore, cursor: str | None) -> None:
    store.set_sync_payload(
        LIVE_REQUEST_SYNC_CURSOR_KEY,
        {"inbound_cursor": cursor} if cursor else {},
        _now(),
    )


def _load_sync_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload(LIVE_REQUEST_SYNC_STATE_KEY)
    return dict(payload) if isinstance(payload, dict) else {}


def _save_sync_state(store: GuardStore, state: dict[str, object]) -> None:
    store.set_sync_payload(LIVE_REQUEST_SYNC_STATE_KEY, state, _now())


def _next_local_event_sequence(store: GuardStore) -> int:
    payload = store.get_sync_payload(_LOCAL_EVENT_SEQUENCE_KEY)
    if isinstance(payload, dict):
        seq = payload.get("sequence")
        if isinstance(seq, int) and seq >= 0:
            return seq + 1
    return 1


def _save_local_event_sequence(store: GuardStore, sequence: int) -> None:
    store.set_sync_payload(
        _LOCAL_EVENT_SEQUENCE_KEY,
        {"sequence": sequence},
        _now(),
    )


def _resolve_display_provenance(
    item: dict[str, object],
    redaction_level: str,
) -> str:
    if redaction_level == "none":
        return _DISPLAY_PROVENANCE_RAW
    if redaction_level == "full":
        return _DISPLAY_PROVENANCE_WITHHELD
    return _DISPLAY_PROVENANCE_REDACTED


def _build_display_command(item: dict[str, object], redaction_level: str) -> tuple[str, str, str | None, str | None]:
    action_identity = str(item.get("action_identity") or item.get("artifact_id") or "unknown")
    trigger_summary = str(item.get("trigger_summary") or item.get("why_now") or "Guard approval request")
    risk_headline = str(item.get("risk_headline") or item.get("risk_summary") or "")
    harness = str(item.get("harness") or "guard-review")

    display_command = f"{harness}: {action_identity}"
    display_summary = f"{trigger_summary}"
    if risk_headline:
        display_summary = f"{risk_headline} — {trigger_summary}"

    raw_command: str | None = None
    redacted_command: str | None = None
    if redaction_level == "none":
        raw_command = display_command
    elif redaction_level == "partial":
        raw_command = display_command
        redacted_command = redact_text(display_command, level="partial")
    else:
        redacted_command = redact_text(display_command, level="full")

    return display_command, display_summary, raw_command, redacted_command


def _build_live_request_event(
    item: dict[str, object],
    *,
    redaction_level: str,
    oauth: dict[str, object] | None,
    store: GuardStore,
    event_sequence: int,
) -> dict[str, object] | None:
    request_id = item.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return None

    status = str(item.get("status") or "pending")
    event_type = _EVENT_TYPE_MAP.get(status, "request_created")

    claim: dict[str, object] | None = None
    if oauth is not None:
        try:
            claim = build_local_review_request_claim(
                request_row=item,
                oauth=oauth,
                store=store,
            )
        except GuardReviewContractError:
            claim = None

    display_command, display_summary, raw_command, redacted_command = _build_display_command(item, redaction_level)
    display_provenance = _resolve_display_provenance(item, redaction_level)

    created_at = str(item.get("created_at") or _now())
    last_seen_at = str(item.get("last_seen_at") or created_at)
    expires_at = item.get("expires_at")

    request_payload = _cloud_safe_local_request_payload(item, redaction_level=redaction_level)

    return {
        "localRequestId": request_id,
        "localEventSequence": event_sequence,
        "eventType": event_type,
        "harnessId": str(item.get("harness") or "guard-review"),
        "requestKind": str(item.get("review_kind") or item.get("harness") or "guard-review"),
        "displayProvenance": display_provenance,
        "displayCommand": display_command,
        "displaySummary": display_summary,
        "rawCommand": raw_command,
        "redactedCommand": redacted_command,
        "reviewClaim": claim,
        "requestPayload": request_payload,
        "riskCategory": str(item.get("risk_category") or "") or None,
        "policyAction": str(item.get("policy_action") or "") or None,
        "recommendedScope": str(item.get("recommended_scope") or "") or None,
        "localCreatedAt": created_at,
        "localUpdatedAt": str(item.get("updated_at") or last_seen_at),
        "localLastSeenAt": last_seen_at,
        "localExpiresAt": str(expires_at) if isinstance(expires_at, str) and expires_at else None,
        "localEmittedAt": _now(),
        "sentAt": _now(),
    }


def _build_sync_events(
    store: GuardStore,
    *,
    cursor: str | None,
) -> list[dict[str, object]]:
    redaction_level = _resolve_cloud_receipt_redaction_level(store)
    try:
        oauth = guard_review_oauth_metadata(store)
    except GuardReviewContractError:
        oauth = None

    events: list[dict[str, object]] = []
    # Fetch both pending and resolved in a single pass using cursor pagination
    # The cursor ensures we only fetch NEW or UPDATED requests since last sync
    rows = store.list_approval_requests(
        status=None,
        limit=LIVE_REQUEST_SYNC_BATCH_SIZE + 1,
        cursor=cursor,
    )
    if not rows:
        return events

    page_rows = rows[:LIVE_REQUEST_SYNC_BATCH_SIZE]
    for item in page_rows:
        sequence = _next_local_event_sequence(store)
        event = _build_live_request_event(
            item,
            redaction_level=redaction_level,
            oauth=oauth,
            store=store,
            event_sequence=sequence,
        )
        if event is not None:
            events.append(event)
            _save_local_event_sequence(store, sequence)

    return events


def _post_sync_events(
    auth_context: dict[str, object],
    *,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
    cursor: str | None,
    events: list[dict[str, object]],
) -> dict[str, object]:
    from .command_queue import (
        _REQUEST_TIMEOUT_SECONDS,
        _RETRY_TIMEOUT_SECONDS,
        _guard_sync_request,
        _urlopen_json_with_timeout_retry,
    )

    request_url = _resolve_sync_url(auth_context, "/api/guard/live-requests/sync")
    payload: dict[str, object] = {
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "deviceId": machine_id,
        "workspaceId": workspace_id,
        "machineInstallationId": machine_installation_id,
        "inboundCursor": cursor,
        "events": events,
    }
    request = _guard_sync_request(
        auth_context,
        request_url=request_url,
        method="POST",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )
    return _urlopen_json_with_timeout_retry(
        request=request,
        timeout_seconds=_REQUEST_TIMEOUT_SECONDS,
        retry_timeout_seconds=_RETRY_TIMEOUT_SECONDS,
    )


def sync_live_requests_once(
    store: GuardStore,
    auth_context: dict[str, object],
) -> dict[str, object]:
    """Sync local approval requests to the Cloud live request table.

    Returns a status dict with synced/failed counts and cursor.
    """
    machine_id = str(auth_context.get("machine_id") or "")
    workspace_id = str(auth_context.get("workspace_id") or "")
    machine_installation_id = str(auth_context.get("machine_installation_id") or "")

    if not machine_id or not workspace_id or not machine_installation_id:
        raise RuntimeError("Guard live request sync requires machine_id, workspace_id, and machine_installation_id.")

    state = _load_sync_state(store)
    cursor = _load_sync_cursor(store)

    state.update(
        {
            "state": "syncing",
            "last_sync_attempt_at": _now(),
            "last_error": None,
        }
    )
    _save_sync_state(store, state)

    total_accepted = 0
    total_rejected = 0
    all_errors: list[str] = []
    new_cursor = cursor
    batches = 0

    try:
        while batches < LIVE_REQUEST_SYNC_MAX_BATCHES:
            events = _build_sync_events(store, cursor=new_cursor)
            if not events:
                break

            response = _post_sync_events(
                auth_context,
                workspace_id=workspace_id,
                machine_id=machine_id,
                machine_installation_id=machine_installation_id,
                cursor=new_cursor,
                events=events,
            )

            accepted = int(response.get("accepted") or 0)
            rejected = int(response.get("rejected") or 0)
            total_accepted += accepted
            total_rejected += rejected

            errors = response.get("errors")
            if isinstance(errors, list):
                all_errors.extend(str(e) for e in errors[:5])

            response_cursor = response.get("cursor")
            if isinstance(response_cursor, str) and response_cursor:
                new_cursor = response_cursor
            else:
                break

            if accepted == 0 and rejected == 0:
                break

            batches += 1

        _save_sync_cursor(store, new_cursor)

        state.update(
            {
                "state": "idle",
                "last_sync_at": _now(),
                "last_success_at": _now(),
                "synced_count": total_accepted,
                "rejected_count": total_rejected,
                "last_error": all_errors[0] if all_errors else None,
                "cursor": new_cursor,
            }
        )
        _save_sync_state(store, state)

        _LOGGER.info(
            "Guard live request sync complete: accepted=%d rejected=%d batches=%d",
            total_accepted,
            total_rejected,
            batches,
        )
        return {
            "synced": total_accepted,
            "rejected": total_rejected,
            "errors": all_errors[:5],
            "cursor": new_cursor,
            "batches": batches,
        }

    except urllib.error.HTTPError as error:
        error_msg = f"HTTP {error.code}: {error.reason}"
        state.update(
            {
                "state": "error",
                "last_error": error_msg,
                "last_error_at": _now(),
            }
        )
        _save_sync_state(store, state)
        _LOGGER.warning("Guard live request sync failed: %s", error_msg)
        raise
    except Exception as error:
        error_msg = str(error)
        state.update(
            {
                "state": "error",
                "last_error": error_msg,
                "last_error_at": _now(),
            }
        )
        _save_sync_state(store, state)
        _LOGGER.warning("Guard live request sync failed: %s", error_msg)
        raise


def live_request_sync_status(store: GuardStore) -> dict[str, object]:
    """Return the current live request sync status."""
    state = _load_sync_state(store)
    cursor = _load_sync_cursor(store)
    return {
        "state": state.get("state") or "not_configured",
        "last_sync_at": state.get("last_sync_at"),
        "last_success_at": state.get("last_success_at"),
        "last_error": state.get("last_error"),
        "synced_count": state.get("synced_count", 0),
        "rejected_count": state.get("rejected_count", 0),
        "cursor": cursor,
        "protocol_version": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
    }
