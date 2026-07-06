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

Live request cloud sync enhancements:
- Outbox persistence for durable event emission across restarts
- Independent background worker (started with daemon, not only command queue)
- Exponential backoff + jitter retry for transient failures
- Single 401 refresh+retry pass
- Per-source sync health tracking (healthy|stale|auth_failed|retrying|blocked|disabled|unknown)
- Event emission with monotonic sequence + stale rejection
- Atomic write with local approval where practical
- Lifecycle state machine: pending -> approved|blocked|expired|resolved_locally|
  delivery_failed|superseded
- Device capability affects available actions, not row visibility
- Offline preservation: Local Guard never weakens enforcement while offline
"""

import json
import logging
import math
import os
import random
import threading
import time
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ..redaction import redact_text
from ..review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
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

LIVE_REQUEST_SYNC_BATCH_SIZE = 200
LIVE_REQUEST_SYNC_MAX_BATCHES = 25
LIVE_REQUEST_SYNC_PROTOCOL_VERSION = "1"
_LIVE_REQUEST_SEQUENCE_LOCK = threading.Lock()
LIVE_REQUEST_SYNC_CURSOR_KEY = "guard_live_request_sync_cursor"
LIVE_REQUEST_SYNC_STATE_KEY = "guard_live_request_sync_state"

# Live request cloud sync constants
_OUTBOX_STATE_KEY = "guard_live_request_outbox_state"
_LIVE_REQUEST_EVENT_SEQUENCE_KEY = "guard_live_request_event_sequence"
_DEVICE_ID_KEY = "guard_device_id"
OUTBOX_MAX_QUEUE_SIZE_BYTES = 1 * 1024 * 1024  # 1 MiB
OUTBOX_MAX_QUEUE_EVENTS = 500
OUTBOX_BATCH_COUNT = 100
DEFAULT_POLL_INTERVAL_SECONDS = 5.0
DEFAULT_ERROR_BACKOFF_SECONDS = 30.0
_MIN_RETRY_WAIT_SECONDS = 0.5
_MAX_RETRY_WAIT_SECONDS = 300.0
_BACKOFF_JITTER_FRACTION = 0.25
_DEFAULT_401_REFRESH_RETRY_MAX = 1
_REFRESH_THROTTLE_SECONDS = 60.0
SYNC_HEALTH_SOURCES = frozenset(
    {"command_queue", "live_requests", "receipts", "inventory", "integrations", "devices", "policy"}
)
SYNC_HEALTH_STATES = frozenset({"healthy", "stale", "auth_failed", "retrying", "blocked", "disabled", "unknown"})
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
        redacted_command = redact_text(display_command).text
    else:
        redacted_command = redact_text(display_command).text
    return display_command, display_summary, raw_command, redacted_command


def _build_live_request_event(
    item: dict[str, object],
    *,
    oauth: GuardReviewOAuthMetadata | None,
    redaction_level: str,
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
    from .runner import _guard_sync_request, _urlopen_json_with_timeout_retry

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
        timeout_seconds=35,
        retry_timeout_seconds=60,
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

            accepted_val = response.get("accepted")
            rejected_val = response.get("rejected")
            accepted = int(accepted_val) if isinstance(accepted_val, (int, float)) else 0
            rejected = int(rejected_val) if isinstance(rejected_val, (int, float)) else 0
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
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
    }


# ===========================================================================
# Live request cloud sync: outbox, worker, retry, health, diagnostics
# ===========================================================================


# --- Live request cloud sync event types ------------------------------------

LIVE_REQUEST_EVENT_TYPES = frozenset(
    {
        "request_created",
        "request_refreshed",
        "request_expired",
        "request_resolved_locally",
        "decision_applied",
        "delivery_failed",
    }
)


# --- Live request cloud sync data models ------------------------------------


@dataclass(frozen=True, slots=True)
class LiveRequestSyncState:
    """Persistent sync progress and failure state."""

    sequence: int
    last_successful_sync_at: str | None = None
    last_failure_reason: str | None = None
    last_poll_at: str | None = None
    refresh_loop_count: int = 0
    last_refresh_at: str | None = None
    retry_count: int = 0
    error_streak: int = 0
    state: str = "idle"
    # Cloud mirror fields
    decision_queued_at: str | None = None
    decision_acked_at: str | None = None
    delivery_failed_at: str | None = None
    latest_failure_code: str | None = None
    latest_failure_message: str | None = None
    approval_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "lastSuccessfulSyncAt": self.last_successful_sync_at,
            "lastFailureReason": self.last_failure_reason,
            "lastPollAt": self.last_poll_at,
            "refreshLoopCount": self.refresh_loop_count,
            "lastRefreshAt": self.last_refresh_at,
            "retryCount": self.retry_count,
            "errorStreak": self.error_streak,
            "state": self.state,
            "decisionQueuedAt": self.decision_queued_at,
            "decisionAckedAt": self.decision_acked_at,
            "deliveryFailedAt": self.delivery_failed_at,
            "latestFailureCode": self.latest_failure_code,
            "latestFailureMessage": self.latest_failure_message,
            "approvalId": self.approval_id,
        }


@dataclass(frozen=True, slots=True)
class SyncHealthSnapshot:
    """Per-source sync health."""

    source: str
    state: str
    last_success_at: str | None = None
    last_attempt_at: str | None = None
    next_retry_at: str | None = None
    backlog_count: int = 0
    last_error_code: str | None = None
    auth_required: bool = False
    action_label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "state": self.state,
            "lastSuccessAt": self.last_success_at,
            "lastAttemptAt": self.last_attempt_at,
            "nextRetryAt": self.next_retry_at,
            "backlogCount": self.backlog_count,
            "lastErrorCode": self.last_error_code,
            "authRequired": self.auth_required,
            "actionLabel": self.action_label,
        }


@dataclass(frozen=True, slots=True)
class EventAck:
    """Ack result per emitted event."""

    local_request_id: str
    accepted: bool
    stale: bool
    status: str
    reason: str | None = None
    local_event_sequence: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "localRequestId": self.local_request_id,
            "accepted": self.accepted,
            "stale": self.stale,
            "status": self.status,
            "localEventSequence": self.local_event_sequence,
        }
        if self.reason:
            d["reason"] = self.reason
        return d


# --- Live request cloud sync sequence/state helpers -------------------------


def _get_cloud_sync_sync_state(store: GuardStore) -> dict[str, Any]:
    data = store.get_sync_payload(_LIVE_REQUEST_EVENT_SEQUENCE_KEY)
    if not isinstance(data, dict):
        data = {}
    return data


def _set_cloud_sync_sync_state(store: GuardStore, state: dict[str, Any]) -> None:
    store.set_sync_payload(_LIVE_REQUEST_EVENT_SEQUENCE_KEY, state, _now())


def _get_next_cloud_sync_sequence(store: GuardStore) -> int:
    with _LIVE_REQUEST_SEQUENCE_LOCK:
        state = _get_cloud_sync_sync_state(store)
        seq = int(state.get("cloud_sync_sequence", 0)) + 1
        state["cloud_sync_sequence"] = seq
        _set_cloud_sync_sync_state(store, state)
        return seq


def _get_current_cloud_sync_sequence(store: GuardStore) -> int:
    state = _get_cloud_sync_sync_state(store)
    return int(state.get("cloud_sync_sequence", 0))


def _cloud_sync_device_id(store: GuardStore) -> str:
    try:
        device_id = store.get_or_create_installation_id()
        if device_id:
            return device_id
    except Exception:
        pass
    existing = store.get_sync_payload(_DEVICE_ID_KEY)
    if isinstance(existing, str) and existing:
        return existing
    import uuid

    device_id = f"device-{uuid.uuid4().hex[:12]}"
    store.set_sync_payload(_DEVICE_ID_KEY, device_id, _now())
    return device_id


def _cloud_sync_workspace_id(store: GuardStore) -> str:
    try:
        workspace_id = store.get_cloud_workspace_id()
        if workspace_id:
            return workspace_id
    except Exception:
        pass
    state = _get_cloud_sync_sync_state(store)
    wid = state.get("workspaceId")
    if isinstance(wid, str) and wid:
        return wid
    import uuid

    wid = f"ws-{uuid.uuid4().hex[:8]}"
    state["workspaceId"] = wid
    _set_cloud_sync_sync_state(store, state)
    return wid


# --- Live request cloud sync event emission ---------------------------------


def emit_cloud_sync_event(
    store: GuardStore,
    event_type: str,
    local_request_id: str,
    *,
    sequence: int | None = None,
    display_command: str | None = None,
    display_summary: str | None = None,
    raw_command: str | None = None,
    redacted_command: str | None = None,
    risk_category: str | None = None,
    policy_action: str | None = None,
    recommended_scope: str | None = None,
    source_envelope_hash: str | None = None,
    request_payload: dict[str, Any] | None = None,
    first_seen_at: str | None = None,
    last_seen_at: str | None = None,
    resolved_at: str | None = None,
    decision_id: str | None = None,
    decision_status: str | None = None,
    decision_actor: str | None = None,
    decision_applied_at: str | None = None,
    failure_code: str | None = None,
    failure_message: str | None = None,
    review_claim: dict[str, Any] | None = None,
    harness_id: str | None = None,
    request_kind: str | None = None,
    display_provenance: str | None = None,
    artifact_links: list[dict[str, Any]] | None = None,
) -> int:
    """Emit a monotonic sequence live request cloud sync event.

    Ordering accepts only localEventSequence >= stored; duplicates are idempotent.
    """
    if event_type not in LIVE_REQUEST_EVENT_TYPES:
        raise ValueError(f"Unknown live_request event type: {event_type!r}")

    if sequence is None:
        sequence = _get_next_cloud_sync_sequence(store)
    else:
        # Ordering check: reject stale, accept duplicates idempotently
        current = _get_current_cloud_sync_sequence(store)
        if sequence < current:
            _LOGGER.debug("Live request cloud sync: stale event sequence %d < %d, rejecting", sequence, current)
            return sequence
        if sequence == current:
            _LOGGER.debug("Live request cloud sync: duplicate event sequence %d, skipping", sequence)
            return sequence

    now = _now()
    payload: dict[str, Any] = {
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "eventType": event_type,
        "localRequestId": local_request_id,
        "localEventSequence": sequence,
    }
    if display_command:
        payload["displayCommand"] = display_command
    if display_summary:
        payload["displaySummary"] = display_summary
    if raw_command:
        payload["rawCommand"] = raw_command
    if redacted_command:
        payload["redactedCommand"] = redacted_command
    if risk_category:
        payload["riskCategory"] = risk_category
    if policy_action:
        payload["policyAction"] = policy_action
    if recommended_scope:
        payload["recommendedScope"] = recommended_scope
    if source_envelope_hash:
        payload["sourceEnvelopeHash"] = source_envelope_hash
    if request_payload:
        payload["requestPayload"] = request_payload
    if first_seen_at:
        payload["firstSeenAt"] = first_seen_at
    if last_seen_at:
        payload["lastSeenAt"] = last_seen_at
    if resolved_at:
        payload["resolvedAt"] = resolved_at
    if decision_id:
        payload["decisionId"] = decision_id
    if decision_status:
        payload["decisionStatus"] = decision_status
    if decision_actor:
        payload["decisionActor"] = decision_actor
    if decision_applied_at:
        payload["decisionAppliedAt"] = decision_applied_at
    if failure_code:
        payload["failureCode"] = failure_code
    if failure_message:
        payload["failureMessage"] = failure_message
    if review_claim:
        payload["reviewClaim"] = review_claim
    if harness_id:
        payload["harnessId"] = harness_id
    if request_kind:
        payload["requestKind"] = request_kind
    if display_provenance:
        payload["displayProvenance"] = display_provenance
    if artifact_links:
        payload["artifactLinks"] = artifact_links

    store.set_sync_payload(
        f"guard_event:{sequence}",
        payload,
        now,
    )
    return sequence


# --- Convenience emission functions -----------------------------------------


def emit_request_created(
    store: GuardStore,
    local_request_id: str,
    *,
    display_command: str | None = None,
    display_summary: str | None = None,
    harness_id: str | None = None,
    request_kind: str | None = None,
    display_provenance: str | None = None,
    review_claim: dict[str, Any] | None = None,
    first_seen_at: str | None = None,
) -> int:
    """First persisted local approval request, status pending."""
    return emit_cloud_sync_event(
        store,
        "request_created",
        local_request_id,
        display_command=display_command,
        display_summary=display_summary,
        harness_id=harness_id,
        request_kind=request_kind,
        display_provenance=display_provenance,
        review_claim=review_claim,
        first_seen_at=first_seen_at or _now(),
    )


def emit_request_refreshed(
    store: GuardStore,
    local_request_id: str,
    *,
    display_command: str | None = None,
    display_summary: str | None = None,
    last_seen_at: str | None = None,
) -> int:
    """Pending row updated/re-seen, status remains pending."""
    return emit_cloud_sync_event(
        store,
        "request_refreshed",
        local_request_id,
        display_command=display_command,
        display_summary=display_summary,
        last_seen_at=last_seen_at or _now(),
    )


def emit_request_expired(
    store: GuardStore,
    local_request_id: str,
    *,
    resolved_at: str | None = None,
) -> int:
    """Local TTL expiry, status expired."""
    return emit_cloud_sync_event(
        store,
        "request_expired",
        local_request_id,
        resolved_at=resolved_at or _now(),
    )


def emit_request_resolved_locally(
    store: GuardStore,
    local_request_id: str,
    *,
    resolved_at: str | None = None,
    decision_status: str | None = None,
) -> int:
    """Local-only resolution, status resolved_locally."""
    return emit_cloud_sync_event(
        store,
        "request_resolved_locally",
        local_request_id,
        resolved_at=resolved_at or _now(),
        decision_status=decision_status,
    )


def emit_decision_applied(
    store: GuardStore,
    local_request_id: str,
    *,
    decision_id: str | None = None,
    decision_status: str | None = None,
    decision_actor: str | None = None,
    decision_applied_at: str | None = None,
    display_provenance: str | None = None,
) -> int:
    """Cloud decision applied locally, status approved or blocked."""
    return emit_cloud_sync_event(
        store,
        "decision_applied",
        local_request_id,
        decision_id=decision_id,
        decision_status=decision_status or "approved",
        decision_actor=decision_actor,
        decision_applied_at=decision_applied_at or _now(),
        display_provenance=display_provenance,
    )


def emit_delivery_failed(
    store: GuardStore,
    local_request_id: str,
    *,
    failure_code: str | None = None,
    failure_message: str | None = None,
    resolved_at: str | None = None,
) -> int:
    """Worker could not apply cloud decision after retry budget."""
    return emit_cloud_sync_event(
        store,
        "delivery_failed",
        local_request_id,
        failure_code=failure_code,
        failure_message=failure_message,
        resolved_at=resolved_at or _now(),
    )


# --- Live request cloud sync outbox persistence -----------------------------


def enqueue_outbox_request(
    store: GuardStore,
    local_request_id: str,
    *,
    action: str,
    display_command: str | None = None,
    display_summary: str | None = None,
    raw_command: str | None = None,
    redacted_command: str | None = None,
    signature: str | None = None,
    harness: str | None = None,
    agent: str | None = None,
    machine: str | None = None,
    workspace: str | None = None,
    source_hash: str | None = None,
    artifact_id: str | None = None,
    artifact_name: str | None = None,
    request_payload: dict[str, Any] | None = None,
    review_claim: dict[str, Any] | None = None,
    risk_category: str | None = None,
    policy_action: str | None = None,
    recommended_scope: str | None = None,
) -> int:
    """Queue a live request for cloud sync.

    Idempotency identity is (workspaceId, machineInstallationId, localRequestId).
    Stores display command, action signature, harness, agent, machine, workspace,
    source hash for persistence across restarts.
    """
    now = _now()
    seq = _get_next_cloud_sync_sequence(store)

    # Build live request cloud sync v1 envelope
    device_id = _cloud_sync_device_id(store)
    ws_id = _cloud_sync_workspace_id(store)
    machine_inst = machine or device_id
    batch_id = f"batch-{seq:06d}"

    envelope: dict[str, Any] = {
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "deviceId": device_id,
        "workspaceId": ws_id,
        "machineInstallationId": machine_inst,
        "batchId": batch_id,
        "inboundCursor": seq,
        "events": [
            {
                "localRequestId": local_request_id,
                "localEventSequence": seq,
                "eventType": "request_created",
                "harnessId": harness,
                "requestKind": "local",
                "displayProvenance": "raw",
                "displayCommand": display_command,
                "displaySummary": display_summary,
                "rawCommand": raw_command,
                "redactedCommand": redacted_command,
                "requestPayload": request_payload or {},
                "riskCategory": risk_category,
                "policyAction": policy_action,
                "recommendedScope": recommended_scope,
                "sourceEnvelopeHash": source_hash,
                "artifactLinks": ([{"artifactId": artifact_id, "name": artifact_name}] if artifact_id else None),
                "firstSeenAt": now,
                "lastSeenAt": now,
            }
        ],
    }

    item = {
        "local_request_id": local_request_id,
        "sequence_number": seq,
        "action": action,
        "envelope": envelope,
        "signature": signature,
        "harness": harness,
        "agent": agent,
        "machine": machine,
        "workspace": workspace,
        "source_hash": source_hash,
        "display_command": display_command,
        "display_summary": display_summary,
        "raw_command": raw_command,
        "redacted_command": redacted_command,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "created_at": now,
        "synced_at": None,
    }
    store.set_sync_payload(f"guard_outbox:{local_request_id}", item, now)
    store.set_sync_payload(f"guard_outbox_seq:{seq}", item, now)
    return seq


def dequeue_outbox_batch(
    store: GuardStore,
    limit: int = OUTBOX_BATCH_COUNT,
) -> list[dict[str, Any]]:
    """Return the next batch of unsynced outbox entries."""
    result: list[dict[str, Any]] = []
    state = _get_cloud_sync_sync_state(store)
    seq = _get_current_cloud_sync_sequence(store)
    cursor = int(state.get("outbox_cursor", 0))
    if seq <= 0:
        return result

    scan_order = list(range(cursor + 1, seq + 1)) + list(range(1, min(cursor, seq) + 1))
    next_cursor = cursor
    for i in scan_order:
        next_cursor = i
        key = f"guard_outbox_seq:{i}"
        item = store.get_sync_payload(key)
        if isinstance(item, dict) and item.get("synced_at") is None:
            result.append(item)
            if len(result) >= limit:
                break

    state["outbox_cursor"] = next_cursor
    _set_cloud_sync_sync_state(store, state)
    return result


def mark_outbox_synced(
    store: GuardStore,
    local_request_id: str,
    synced_at: str | None = None,
    *,
    sequence: int | None = None,
) -> None:
    """Mark an outbox request as synced + persist persisted_at on the event."""
    synced_at = synced_at or _now()
    key = f"guard_outbox:{local_request_id}"
    item = store.get_sync_payload(key)
    if isinstance(item, dict):
        item["synced_at"] = synced_at
        store.set_sync_payload(key, item, synced_at)
        sequence_number = item.get("sequence_number")
        if isinstance(sequence_number, int):
            store.set_sync_payload(f"guard_outbox_seq:{sequence_number}", item, synced_at)
    if sequence is not None:
        event_key = f"guard_event:{sequence}"
        event_data = store.get_sync_payload(event_key)
        if isinstance(event_data, dict):
            event_data["persisted_at"] = synced_at
            store.set_sync_payload(event_key, event_data, synced_at)


# --- Live request cloud sync atomic write -----------------------------------


def atomic_write_sync(
    store: GuardStore,
    local_request_id: str,
    action: str,
    approval_request: Any | None,
    *,
    display_command: str | None = None,
    display_summary: str | None = None,
    raw_command: str | None = None,
    redacted_command: str | None = None,
    signature: str | None = None,
    harness: str | None = None,
    agent: str | None = None,
    machine: str | None = None,
    workspace: str | None = None,
    source_hash: str | None = None,
    request_payload: dict[str, Any] | None = None,
) -> int:
    """Write outbox + approval atomically where practical.

    Local Guard never weakens enforcement while offline.
    The outbox entry is written first then the approval request update follows.
    """
    seq = enqueue_outbox_request(
        store,
        local_request_id,
        action=action,
        display_command=display_command,
        display_summary=display_summary,
        raw_command=raw_command,
        redacted_command=redacted_command,
        signature=signature,
        harness=harness,
        agent=agent,
        machine=machine,
        workspace=workspace,
        source_hash=source_hash,
        request_payload=request_payload,
    )

    if approval_request is not None:
        try:
            store.add_approval_request(approval_request, _now())
        except (AttributeError, TypeError, RuntimeError):
            _LOGGER.debug("atomic_write_sync: approval update unavailable (offline-safe)")
    return seq


# --- Live request cloud sync retry / exponential backoff + jitter -----------


def _cloud_sync_retry_wait_seconds(
    base: float,
    error_backoff: float,
    streak: int,
    max_wait: float = _MAX_RETRY_WAIT_SECONDS,
) -> float:
    """Exponential backoff with jitter."""
    if streak <= 0:
        return base
    raw = base * math.pow(2, min(streak - 1, 8))
    raw = min(raw, error_backoff * math.pow(2, min(streak - 1, 4)))
    raw = min(raw, max_wait)
    jitter = raw * _BACKOFF_JITTER_FRACTION * (2 * random.random() - 1)
    return max(_MIN_RETRY_WAIT_SECONDS, raw + jitter)


def _cloud_sync_retry_request(
    auth_context: dict[str, Any],
    *,
    method: str,
    path: str,
    payload: dict[str, Any],
    max_retries: int = 3,
) -> dict[str, Any]:
    """HTTP request with exponential backoff + jitter retry."""
    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _guard_sync_request,
        _urlopen_json_with_timeout_retry,
    )

    last_exc: Exception | None = None
    poll_interval = float(os.environ.get("GUARD_LIVE_REQUEST_POLL_INTERVAL", "5"))
    error_backoff = float(os.environ.get("GUARD_LIVE_REQUEST_ERROR_BACKOFF", "30"))

    for attempt in range(max_retries + 1):
        try:
            # Reuse _command_api_url logic from command_queue
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(str(auth_context.get("sync_url", "")))
            normalized_path = path if path.startswith("/") else f"/{path}"
            request_path = normalized_path if normalized_path.startswith("/api/") else f"/api/guard{normalized_path}"
            request_url = urlunparse((parsed.scheme, parsed.netloc, request_path, "", "", ""))
            request = _guard_sync_request(
                auth_context,
                request_url=request_url,
                method=method,
                data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            )
            return _urlopen_json_with_timeout_retry(
                request=request,
                timeout_seconds=35,
                retry_timeout_seconds=60,
            )
        except Exception as exc:
            if isinstance(exc, (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError)):
                raise
            last_exc = exc
            if attempt < max_retries:
                wait = _cloud_sync_retry_wait_seconds(poll_interval, error_backoff, attempt + 1)
                time.sleep(wait)
    raise RuntimeError(f"Live request sync failed after {max_retries} retries: {last_exc}") from last_exc


# --- Live request cloud sync 401 refresh + retry ----------------------------


def _cloud_sync_handle_401_refresh(
    store: GuardStore,
    auth_context: dict[str, Any],
    *,
    max_refresh_attempts: int = _DEFAULT_401_REFRESH_RETRY_MAX,
) -> dict[str, Any]:
    """Attempt a single OAuth refresh pass when 401 is encountered."""
    from .runner import GuardSyncAuthorizationExpiredError, _resolve_guard_sync_auth_context

    state = _get_cloud_sync_sync_state(store)
    refresh_count = int(state.get("refresh_loop_count", 0))

    if refresh_count >= max_refresh_attempts:
        _LOGGER.warning("Live request cloud sync: refresh loop limit reached (%d)", max_refresh_attempts)
        _cloud_sync_save_failure_reason(store, "Live request cloud sync: refresh loop limit reached")
        raise GuardSyncAuthorizationExpiredError("Guard Cloud authorization expired.")

    # Refresh throttle
    last_refresh = state.get("last_refresh_at")
    if last_refresh is not None:
        try:
            last_ts = datetime.fromisoformat(str(last_refresh)).timestamp()
            elapsed = time.time() - last_ts
            if elapsed < _REFRESH_THROTTLE_SECONDS:
                _LOGGER.debug("Live request cloud sync: refresh throttled (%.1fs since last refresh)", elapsed)
                raise GuardSyncAuthorizationExpiredError("Guard Cloud authorization expired (throttled).")
        except (ValueError, TypeError):
            pass

    try:
        refreshed_auth = _resolve_guard_sync_auth_context(store, force_refresh=True)
    except Exception as exc:
        _LOGGER.warning("Live request cloud sync: refresh failed: %s", exc)
        _cloud_sync_save_failure_reason(store, f"Live request cloud sync: refresh failed: {exc}")
        raise GuardSyncAuthorizationExpiredError("Live request cloud sync: OAuth refresh failed.") from exc

    new_state = {
        **state,
        "refresh_loop_count": refresh_count + 1,
        "last_refresh_at": _now(),
    }
    _set_cloud_sync_sync_state(store, new_state)
    return refreshed_auth


# --- Live request cloud sync failure persistence ----------------------------


def _cloud_sync_save_failure_reason(store: GuardStore, reason: str) -> None:
    """Persist a safe failure reason in live request cloud sync state."""
    state = _get_cloud_sync_sync_state(store)
    state["last_failure_reason"] = reason
    state["state"] = "error"
    state["last_poll_at"] = _now()
    state["retry_count"] = int(state.get("retry_count", 0)) + 1
    _set_cloud_sync_sync_state(store, state)


def _cloud_sync_clear_failure_state(store: GuardStore) -> None:
    """Clear failure state after a successful sync."""
    state = _get_cloud_sync_sync_state(store)
    state["last_failure_reason"] = None
    state["state"] = "idle"
    state["retry_count"] = 0
    state["error_streak"] = 0
    _set_cloud_sync_sync_state(store, state)


# --- Live request cloud sync batch push -------------------------------------


def _cloud_sync_build_batch_push_payload(
    store: GuardStore,
    batch: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the live request cloud sync v1 POST payload."""
    device_id = _cloud_sync_device_id(store)
    ws_id = _cloud_sync_workspace_id(store)
    events: list[dict[str, Any]] = []
    max_sequence = 0
    for entry in batch:
        envelope = entry.get("envelope")
        if not isinstance(envelope, dict):
            _cloud_sync_save_failure_reason(store, "delivery payload failed: missing envelope")
            continue
        raw_events = envelope.get("events")
        if not isinstance(raw_events, list) or not raw_events:
            _cloud_sync_save_failure_reason(store, "delivery payload failed: missing event")
            continue
        event = raw_events[0]
        if not isinstance(event, dict):
            _cloud_sync_save_failure_reason(store, "delivery payload failed: malformed event")
            continue
        events.append(event)
        seq = entry.get("sequence_number", event.get("localEventSequence"))
        if seq is None:
            _cloud_sync_save_failure_reason(store, "delivery payload failed: missing sequence")
            continue
        try:
            max_sequence = max(max_sequence, int(seq))
        except (TypeError, ValueError):
            _cloud_sync_save_failure_reason(store, f"delivery payload failed: invalid sequence {seq!r}")

    return {
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "deviceId": device_id,
        "workspaceId": ws_id,
        "batchId": f"batch-{time.time_ns()}",
        "inboundCursor": max_sequence or _get_current_cloud_sync_sequence(store),
        "events": events,
    }


def _cloud_sync_push_batch_to_cloud(
    store: GuardStore,
    auth_context: dict[str, Any],
    batch: list[dict[str, Any]],
) -> dict[str, Any]:
    """POST batch to cloud live-request endpoint."""
    payload = _cloud_sync_build_batch_push_payload(store, batch)
    response = _cloud_sync_retry_request(
        auth_context,
        method="POST",
        path="live-requests/batch",
        payload=payload,
    )
    return response


def _cloud_sync_attempt_401_retry(
    store: GuardStore,
    initial_auth: dict[str, Any],
    *,
    batch: list[dict[str, Any]],
    max_refresh: int = _DEFAULT_401_REFRESH_RETRY_MAX,
) -> dict[str, Any]:
    """Attempt push, then one 401 refresh + retry pass."""
    from .runner import GuardSyncAuthorizationExpiredError

    try:
        return _cloud_sync_push_batch_to_cloud(store, initial_auth, batch)
    except GuardSyncAuthorizationExpiredError:
        _LOGGER.warning("Live request cloud sync: 401 received, attempting refresh retry")
        refreshed = _cloud_sync_handle_401_refresh(store, initial_auth, max_refresh_attempts=max_refresh)
        try:
            return _cloud_sync_push_batch_to_cloud(store, refreshed, batch)
        except Exception as exc:
            _cloud_sync_save_failure_reason(store, f"Live request cloud sync: 401 refresh retry failed: {exc}")
            raise


# --- Live request cloud sync ack processing ---------------------------------


def process_cloud_sync_ack_response(
    store: GuardStore,
    ack_data: dict[str, Any],
) -> list[EventAck]:
    """Process cloud ack response — partial success with indexed failures.

    Ack per event includes {localRequestId, accepted, stale, status,
    reason?, localEventSequence}. Batch partially succeeds.
    """
    acks: list[EventAck] = []
    results = ack_data.get("results", ack_data) if isinstance(ack_data, dict) else []
    if isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                _cloud_sync_save_failure_reason(store, "delivery ack failed: malformed ack item")
                continue
            lr_id = str(item.get("localRequestId", ""))
            accepted = bool(item.get("accepted", False))
            stale = bool(item.get("stale", False))
            status = str(item.get("status", "unknown"))
            reason_value = item.get("reason")
            reason = str(reason_value) if reason_value is not None else None
            seq = item.get("localEventSequence")
            try:
                local_event_sequence = int(seq) if seq is not None else None
            except (TypeError, ValueError):
                local_event_sequence = None
                _cloud_sync_save_failure_reason(store, f"delivery ack failed: invalid sequence {seq!r}")
            ack = EventAck(
                local_request_id=lr_id,
                accepted=accepted,
                stale=stale,
                status=status,
                reason=reason,
                local_event_sequence=local_event_sequence,
            )
            acks.append(ack)

            if accepted and not stale:
                mark_outbox_synced(store, lr_id, synced_at=_now(), sequence=local_event_sequence)
            elif stale:
                _LOGGER.debug("Live request cloud sync: stale event %s seq %s", lr_id, seq)
                mark_outbox_synced(store, lr_id, synced_at=_now(), sequence=local_event_sequence)
            else:
                _cloud_sync_save_failure_reason(store, f"delivery ack failed: {reason}")

    return acks


# --- Live request cloud sync main sync --------------------------------------


def cloud_sync_sync_live_requests_once(
    store: GuardStore,
    auth_context: dict[str, Any],
    *,
    max_batch_count: int = OUTBOX_BATCH_COUNT,
) -> dict[str, Any]:
    """Sync pending live-request events to the cloud.

    Uses the outbox path with retry/401/ack. Falls back to cursor-based sync
    if no outbox entries exist.
    """
    from .runner import GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError

    state = _get_cloud_sync_sync_state(store)
    state["state"] = "polling"
    state["last_poll_at"] = _now()
    pending = dequeue_outbox_batch(store, limit=max_batch_count)

    if pending:
        # Outbox path
        try:
            response = _cloud_sync_attempt_401_retry(store, auth_context, batch=pending)
        except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
            _cloud_sync_save_failure_reason(store, "Live request cloud sync: auth expired")
            state = _get_cloud_sync_sync_state(store)
            state["state"] = "auth_expired"
            state["refresh_loop_count"] = int(state.get("refresh_loop_count", 0)) + 1
            _set_cloud_sync_sync_state(store, state)
            return {
                "synced": 0,
                "error": True,
                "state": "auth_expired",
                "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
            }
        except Exception as exc:
            _cloud_sync_save_failure_reason(store, f"Live request cloud sync: {exc}")
            state = _get_cloud_sync_sync_state(store)
            state["error_streak"] = int(state.get("error_streak", 0)) + 1
            _set_cloud_sync_sync_state(store, state)
            return {
                "synced": 0,
                "error": True,
                "reason": str(exc),
                "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
            }

        acks = process_cloud_sync_ack_response(store, response)
        synced_count = sum(1 for a in acks if a.accepted and not a.stale)
        if not acks:
            _cloud_sync_save_failure_reason(store, "Live request cloud sync: invalid empty ack response")
            state["error_streak"] = int(state.get("error_streak", 0)) + 1
            _set_cloud_sync_sync_state(store, state)
        elif synced_count > 0:
            _cloud_sync_clear_failure_state(store)
            state = _get_cloud_sync_sync_state(store)
            state["last_successful_sync_at"] = _now()
            state["refresh_loop_count"] = 0
            _set_cloud_sync_sync_state(store, state)
        return {
            "synced": synced_count,
            "batch_size": len(pending),
            "acks": [a.to_dict() for a in acks],
            "response": response,
            "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        }

    # No outbox entries — fall back to existing cursor-based sync
    # Reuse the existing sync_live_requests_once which does cursor-based
    # pagination against the approval_requests table
    return sync_live_requests_once(store, auth_context)


# --- Live request cloud sync health -----------------------------------------


def set_sync_health(
    store: GuardStore,
    source: str,
    state: str,
    *,
    last_success_at: str | None = None,
    last_attempt_at: str | None = None,
    next_retry_at: str | None = None,
    backlog_count: int = 0,
    last_error_code: str | None = None,
    auth_required: bool = False,
    action_label: str | None = None,
) -> None:
    """Persist per-source sync health snapshot."""
    if source not in SYNC_HEALTH_SOURCES:
        raise ValueError(f"Unknown sync health source: {source!r}")
    if state not in SYNC_HEALTH_STATES:
        raise ValueError(f"Invalid sync health state: {state!r}")

    store.set_sync_payload(
        f"guard_health:{source}",
        {
            "source": source,
            "state": state,
            "lastSuccessAt": last_success_at,
            "lastAttemptAt": last_attempt_at,
            "nextRetryAt": next_retry_at,
            "backlogCount": backlog_count,
            "lastErrorCode": last_error_code,
            "authRequired": auth_required,
            "actionLabel": action_label,
        },
        _now(),
    )


def get_sync_health(store: GuardStore) -> dict[str, dict[str, Any]]:
    """Return per-source sync health. Must not hide per-source stale/auth/backlog."""
    result: dict[str, dict[str, Any]] = {}
    for source in SYNC_HEALTH_SOURCES:
        data = store.get_sync_payload(f"guard_health:{source}")
        if isinstance(data, dict):
            result[source] = data
        else:
            result[source] = {"source": source, "state": "unknown"}
    return result


# --- Live request cloud sync diagnostics ------------------------------------


def cloud_sync_live_request_diagnostics(store: GuardStore) -> dict[str, Any]:
    state = _get_cloud_sync_sync_state(store)
    seq = _get_current_cloud_sync_sequence(store)
    pending = []
    for i in range(1, seq + 1):
        event_data = store.get_sync_payload(f"guard_outbox_seq:{i}")
        if isinstance(event_data, dict) and event_data.get("synced_at") is None:
            pending.append(event_data)
            if len(pending) >= OUTBOX_MAX_QUEUE_EVENTS:
                break
    pending_count = len(pending)

    events: list[dict[str, Any]] = []
    for i in range(max(1, seq - 10), seq + 1):
        event_data = store.get_sync_payload(f"guard_event:{i}")
        if isinstance(event_data, dict):
            events.append(event_data)

    health = get_sync_health(store)

    return {
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "syncState": state.get("state", "idle"),
        "sequence": state.get("cloud_sync_sequence", 0),
        "lastSuccessfulSyncAt": state.get("last_successful_sync_at"),
        "lastFailureReason": state.get("last_failure_reason"),
        "lastPollAt": state.get("last_poll_at"),
        "refreshLoopCount": state.get("refresh_loop_count", 0),
        "lastRefreshAt": state.get("last_refresh_at"),
        "retryCount": state.get("retry_count", 0),
        "errorStreak": state.get("error_streak", 0),
        "pendingOutboxCount": pending_count,
        "pendingOutboxBytes": sum(len(json.dumps(e, separators=(",", ":")).encode("utf-8")) for e in pending),
        "maxOutboxBytes": OUTBOX_MAX_QUEUE_SIZE_BYTES,
        "outboxCapacityRemaining": max(
            0,
            OUTBOX_MAX_QUEUE_SIZE_BYTES
            - sum(len(json.dumps(e, separators=(",", ":")).encode("utf-8")) for e in pending),
        ),
        "recentEvents": events[-10:],
        "syncHealth": health,
    }


# --- Live request cloud sync worker -----------------------------------------


@dataclass
class LiveRequestSyncWorker:
    """Background worker for live-request event outbox sync."""

    thread: threading.Thread
    stop_event: threading.Event


def start_cloud_sync_sync_worker(
    store: GuardStore,
    existing: LiveRequestSyncWorker | None = None,
    *,
    poll_interval: float | None = None,
    error_backoff: float | None = None,
) -> LiveRequestSyncWorker | None:
    """Start independent live-request sync worker at daemon startup.

    Runs continuously syncing the outbox to cloud regardless of whether the
    command-queue lease path is active. Offline preservation ensures local
    enforcement continues while outbox buffers.
    """
    if existing is not None and existing.thread.is_alive() and not existing.stop_event.is_set():
        return existing

    if os.environ.get("GUARD_LIVE_REQUEST_ENABLED", "1").strip().lower() in {
        "0",
        "false",
        "no",
        "off",
    }:
        return None
    stop_event = threading.Event()
    poll_interval = poll_interval or float(
        os.environ.get(
            "GUARD_LIVE_REQUEST_POLL_INTERVAL",
            str(DEFAULT_POLL_INTERVAL_SECONDS),
        )
    )
    error_backoff = error_backoff or float(
        os.environ.get(
            "GUARD_LIVE_REQUEST_ERROR_BACKOFF",
            str(DEFAULT_ERROR_BACKOFF_SECONDS),
        )
    )

    thread = threading.Thread(
        target=_cloud_sync_sync_loop,
        kwargs={
            "store": store,
            "stop_event": stop_event,
            "poll_interval": poll_interval,
            "error_backoff": error_backoff,
        },
        daemon=True,
        name="hol-guard-live-request-sync",
    )
    thread.start()
    return LiveRequestSyncWorker(thread=thread, stop_event=stop_event)


def stop_cloud_sync_sync_worker(
    worker: LiveRequestSyncWorker | None,
) -> LiveRequestSyncWorker | None:
    """Stop a live-request sync worker gracefully."""
    if worker is None:
        return None
    worker.stop_event.set()
    worker.thread.join(timeout=30.0)
    return worker if worker.thread.is_alive() else None


def _resolve_live_request_sync_auth_context(store: GuardStore) -> dict[str, Any]:
    """Resolve cloud sync auth context and repair paired storage when possible."""
    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
        _resolve_guard_sync_auth_context,
        repair_guard_cloud_connect_storage,
    )

    try:
        return _resolve_guard_sync_auth_context(store)
    except (GuardSyncAuthorizationExpiredError, GuardSyncNotConfiguredError):
        repair = repair_guard_cloud_connect_storage(store)
        if repair["existing_sign_in_valid"] or repair["repaired_storage"]:
            return _resolve_guard_sync_auth_context(store)
        raise


def _cloud_sync_sync_loop(
    store: GuardStore,
    stop_event: threading.Event,
    *,
    poll_interval: float,
    error_backoff: float,
) -> None:
    """Main loop for the independent live-request sync worker."""
    from .runner import (
        GuardSyncAuthorizationExpiredError,
        GuardSyncNotConfiguredError,
    )

    error_streak = 0
    while not stop_event.is_set():
        try:
            auth_context = _resolve_live_request_sync_auth_context(store)
            result = cloud_sync_sync_live_requests_once(store, auth_context)
            if result.get("synced", 0) > 0:
                error_streak = 0
                continue
        except GuardSyncAuthorizationExpiredError as exc:
            error_streak += 1
            _cloud_sync_save_failure_reason(store, f"Live request cloud sync: auth expired — {exc}")
        except GuardSyncNotConfiguredError as exc:
            _cloud_sync_save_failure_reason(store, f"Live request cloud sync: not configured — {exc}")
        except Exception as exc:
            error_streak += 1
            _cloud_sync_save_failure_reason(store, f"Live request cloud sync: {exc}")

        wait = _cloud_sync_retry_wait_seconds(poll_interval, error_backoff, error_streak)
        if stop_event.wait(wait):
            return
