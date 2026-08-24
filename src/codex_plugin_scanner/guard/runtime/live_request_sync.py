"""Durable, independent synchronization for local Guard approval requests."""

import logging
import threading  # noqa: F401 - retained as the worker lifecycle's testable runtime seam.
import urllib.error
from datetime import datetime, timezone

from ..store import GuardStore
from .live_request_event_projection import (
    _build_live_request_event as _build_live_request_event,
)
from .local_request_snapshots import _cloud_scrub_text
from .review_event_batch_delivery import prepare_review_event_batch, reconcile_review_event_batch
from .review_event_batch_worker import (
    DEFAULT_REVIEW_EVENT_BATCH_MAX_BYTES,
    DEFAULT_REVIEW_EVENT_BATCH_SIZE,
    bounded_batch_size,
    classify_review_event_sync_error,
    record_review_event_latency,
)
from .review_event_transport import encode_live_request_events, resolve_sync_url
from .review_event_transport import post_sync_events as _post_sync_events
from .review_event_worker_lifecycle import (
    LiveRequestSyncWorker as LiveRequestSyncWorker,
)
from .review_event_worker_lifecycle import (
    _cloud_sync_sync_loop as _cloud_sync_sync_loop,
)
from .review_event_worker_lifecycle import (
    _resolve_live_request_sync_auth_context as _resolve_live_request_sync_auth_context,
)
from .review_event_worker_lifecycle import (
    start_cloud_sync_sync_worker as start_cloud_sync_sync_worker,
)
from .review_event_worker_lifecycle import (
    stop_cloud_sync_sync_worker as stop_cloud_sync_sync_worker,
)

_encode_live_request_events = encode_live_request_events
_resolve_sync_url = resolve_sync_url

_LOGGER = logging.getLogger(__name__)

LIVE_REQUEST_SYNC_BATCH_SIZE = DEFAULT_REVIEW_EVENT_BATCH_SIZE
LIVE_REQUEST_SYNC_MAX_BATCHES = 200
LIVE_REQUEST_SYNC_PROTOCOL_VERSION = "2"
LIVE_REQUEST_SYNC_STATE_KEY = "guard_live_request_sync_state"
DEFAULT_POLL_INTERVAL_SECONDS = 0.1
DEFAULT_HEALTH_INTERVAL_SECONDS = 30.0
DEFAULT_ERROR_BACKOFF_SECONDS = 1.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redacted_error(error: BaseException) -> str:
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP Error {error.code}: {error.reason}"
    if isinstance(error, OSError):
        return type(error).__name__
    return str(error)


def _live_request_sync_state_key(store: GuardStore) -> str:
    source = getattr(store, "guard_source", "default")
    if source == "default":
        return LIVE_REQUEST_SYNC_STATE_KEY
    return f"{LIVE_REQUEST_SYNC_STATE_KEY}:{source}"


def _load_sync_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload(_live_request_sync_state_key(store))
    return dict(payload) if isinstance(payload, dict) else {}


def _save_sync_state(store: GuardStore, state: dict[str, object]) -> None:
    store.set_sync_payload(_live_request_sync_state_key(store), state, _now())


def _review_event_batch_limits(
    state: dict[str, object],
    auth_context: dict[str, object],
) -> tuple[int, int]:
    configured_size = auth_context.get("review_event_batch_size", state.get("adaptive_batch_size"))
    configured_bytes = auth_context.get("review_event_batch_max_bytes", state.get("batch_max_bytes"))
    batch_size = bounded_batch_size(configured_size, fallback=LIVE_REQUEST_SYNC_BATCH_SIZE)
    byte_cap = (
        int(configured_bytes)
        if isinstance(configured_bytes, int) and not isinstance(configured_bytes, bool)
        else DEFAULT_REVIEW_EVENT_BATCH_MAX_BYTES
    )
    return batch_size, max(1_024, min(byte_cap, DEFAULT_REVIEW_EVENT_BATCH_MAX_BYTES))


def _contiguous_acknowledgement(response: dict[str, object]) -> int | None:
    for key in ("highestContiguousAcknowledgedStreamSequence", "highestContiguousAcknowledgedSequence"):
        value = response.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def _state_int(state: dict[str, object], key: str, *, fallback: int = 0) -> int:
    value = state.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else fallback


def _post_sync_events_with_auth_refresh(
    store: GuardStore,
    auth_context: dict[str, object],
    *,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
    cursor: str | None,
    events: list[dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    """Retry one rejected request with a newly resolved authorization context."""

    try:
        response = _post_sync_events(
            auth_context,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
            cursor=cursor,
            events=events,
        )
        return response, auth_context
    except Exception as error:
        if classify_review_event_sync_error(error) != "authorization":
            raise
    refreshed = _resolve_auth_context_for_retry(store)
    response = _post_sync_events(
        refreshed,
        workspace_id=workspace_id,
        machine_id=machine_id,
        machine_installation_id=machine_installation_id,
        cursor=cursor,
        events=events,
    )
    return response, refreshed


def _is_terminally_superseded_result(item: dict[str, object]) -> bool:
    """Return whether Cloud already owns a newer authoritative request state.

    ``decision_queued`` means a Cloud decision was durably queued for delivery;
    subsequent local refresh/resolution events cannot replace it. The eventual
    ``decision_applied`` acknowledgement travels as a separate outbox event.
    """
    if item.get("code") == "stale_sequence":
        return True
    error = item.get("error")
    if error in {"decision_queued", "stale_regression_rejected", "stale_sequence"}:
        return True
    return isinstance(error, str) and error.startswith("stale event sequence ")


def _retry_result_message(items: list[dict[str, object]]) -> str:
    details: list[str] = []
    for item in items:
        code = item.get("code")
        error = item.get("error")
        detail = ": ".join(
            _cloud_scrub_text(value) for value in (code, error) if isinstance(value, str) and value.strip()
        )
        if detail and detail not in details:
            details.append(detail)
    message = f"{len(items)} live request events require retry."
    if details:
        return f"{message} Cloud reported: {'; '.join(details[:3])}."
    return message


def _is_permanently_rejected_result(item: dict[str, object]) -> bool:
    code = item.get("code")
    return isinstance(code, str) and code in {
        "invalid_event_schema",
        "invalid_payload",
        "invalid_binding",
        "permanent_rejection",
    }


def sync_live_requests_once(
    store: GuardStore,
    auth_context: dict[str, object],
) -> dict[str, object]:
    """Drain the durable local approval outbox into the Cloud projection."""
    machine_id = str(auth_context.get("machine_id") or "")
    workspace_id = str(auth_context.get("workspace_id") or "")
    machine_installation_id = str(auth_context.get("machine_installation_id") or "")
    oauth_subject_hash = str(auth_context.get("oauth_subject_hash") or "")
    oauth_source = str(auth_context.get("oauth_source") or "")
    supplied_binding = {
        "oauth_source": oauth_source,
        "oauth_subject_hash": oauth_subject_hash,
        "workspace_id": workspace_id,
        "machine_id": machine_id,
        "machine_installation_id": machine_installation_id,
    }

    if not all(supplied_binding.values()) or supplied_binding != store.get_live_request_oauth_binding():
        raise RuntimeError(
            "Guard live request sync requires a matching source, OAuth subject, machine, workspace, "
            "and installation binding."
        )
    delivery_binding = {
        "oauth_subject_hash": oauth_subject_hash,
        "workspace_id": workspace_id,
        "machine_id": machine_id,
        "machine_installation_id": machine_installation_id,
    }
    store.claim_unowned_live_request_outbox(**delivery_binding)

    state = _load_sync_state(store)
    batch_size, batch_max_bytes = _review_event_batch_limits(state, auth_context)
    state.update(
        {
            "state": "syncing",
            "last_sync_attempt_at": _now(),
            "last_error": None,
            "last_error_category": None,
            "adaptive_batch_size": batch_size,
            "batch_max_bytes": batch_max_bytes,
        }
    )
    _save_sync_state(store, state)

    total_accepted = 0
    total_rejected = 0
    all_errors: list[str] = []
    batches = 0

    try:
        attempted_authenticated_round_trip = False
        while batches < LIVE_REQUEST_SYNC_MAX_BATCHES:
            outbox_rows = store.list_ready_live_request_outbox(
                now=_now(),
                limit=batch_size,
                **delivery_binding,
                newest_first=False,
            )
            if not outbox_rows:
                if not attempted_authenticated_round_trip:
                    _, auth_context = _post_sync_events_with_auth_refresh(
                        store,
                        auth_context,
                        workspace_id=workspace_id,
                        machine_id=machine_id,
                        machine_installation_id=machine_installation_id,
                        cursor=None,
                        events=[],
                    )
                    attempted_authenticated_round_trip = True
                break

            batch = prepare_review_event_batch(
                store=store,
                rows=outbox_rows,
                delivery_binding=delivery_binding,
                maximum_events=batch_size,
                maximum_bytes=batch_max_bytes,
            )
            events = batch.events
            sequences = batch.sequences
            if not events:
                break

            state["last_attempted_sequence"] = max(sequences)
            state["last_batch_bytes"] = batch.byte_size
            state["in_flight_sequences"] = sequences
            record_review_event_latency(state, events, metric="enqueue_to_send", now=_now())
            _save_sync_state(store, state)

            try:
                response, auth_context = _post_sync_events_with_auth_refresh(
                    store,
                    auth_context,
                    workspace_id=workspace_id,
                    machine_id=machine_id,
                    machine_installation_id=machine_installation_id,
                    cursor=None,
                    events=events,
                )
                attempted_authenticated_round_trip = True
            except Exception as error:
                category = classify_review_event_sync_error(error)
                state["last_error_category"] = category
                store.retry_live_request_outbox(
                    sequences,
                    now=_now(),
                    error=_redacted_error(error),
                    **delivery_binding,
                )
                raise

            server_batch_size = response.get("maxBatchSize", response.get("maxEventCount"))
            if server_batch_size is not None:
                batch_size = bounded_batch_size(server_batch_size, fallback=batch_size)
                state["adaptive_batch_size"] = batch_size
            contiguous_ack = _contiguous_acknowledgement(response)

            reconciliation = reconcile_review_event_batch(
                store=store,
                response=response,
                events=events,
                sequences=sequences,
                delivery_binding=delivery_binding,
                now=_now(),
                contiguous_ack=contiguous_ack,
                is_terminal=_is_terminally_superseded_result,
                is_permanent=_is_permanently_rejected_result,
                retry_message=_retry_result_message,
            )
            total_accepted += reconciliation.accepted
            total_rejected += reconciliation.rejected
            all_errors.extend(reconciliation.errors)
            if reconciliation.error_category is not None:
                state["last_error_category"] = reconciliation.error_category
            if reconciliation.acknowledged_sequences:
                state["last_acknowledged_sequence"] = max(
                    _state_int(state, "last_acknowledged_sequence"),
                    max(reconciliation.acknowledged_sequences),
                )
            acknowledged = set(reconciliation.acknowledged_sequences)
            record_review_event_latency(
                state,
                [event for sequence, event in zip(sequences, events, strict=True) if sequence in acknowledged],
                metric="enqueue_to_ack",
                now=_now(),
            )
            batches += 1
            if not reconciliation.continue_sync:
                break

        completed_at = _now()
        outbox_status = store.live_request_outbox_status(
            now=completed_at,
            **delivery_binding,
        )
        state.update(
            {
                "state": "idle",
                "last_sync_at": completed_at,
                "last_success_at": completed_at,
                "synced_count": total_accepted,
                "rejected_count": total_rejected,
                "last_error": all_errors[0] if all_errors else None,
                "outbox_depth": outbox_status["depth"],
                "outbox_oldest_changed_at": outbox_status["oldest_changed_at"],
                "error_streak": 0,
                "in_flight_sequences": [],
            }
        )
        if attempted_authenticated_round_trip:
            state["last_authenticated_round_trip_at"] = completed_at
        _save_sync_state(store, state)

        outbox_depth = outbox_status["depth"]
        if not isinstance(outbox_depth, int):
            raise RuntimeError("Live-request outbox depth is invalid.")
        _LOGGER.info(
            "Guard live request sync complete: accepted=%d rejected=%d batches=%d outbox_depth=%d",
            total_accepted,
            total_rejected,
            batches,
            outbox_depth,
        )
        return {
            "synced": total_accepted,
            "rejected": total_rejected,
            "errors": all_errors[:5],
            "cursor": None,
            "batches": batches,
            "outbox": outbox_status,
        }
    except urllib.error.HTTPError as error:
        error_message = f"HTTP {error.code}: {error.reason}"
        state.update(
            {
                "state": "error",
                "last_error": error_message,
                "last_error_at": _now(),
            }
        )
        _save_sync_state(store, state)
        _LOGGER.warning("Guard live request sync failed: %s", error_message)
        raise
    except Exception as error:
        error_message = _redacted_error(error)
        state.update(
            {
                "state": "error",
                "last_error": error_message,
                "last_error_at": _now(),
            }
        )
        _save_sync_state(store, state)
        _LOGGER.warning("Guard live request sync failed: %s", error_message)
        raise


def live_request_sync_status(store: GuardStore) -> dict[str, object]:
    """Return live request outbox and delivery health."""
    state = _load_sync_state(store)
    profile = store.get_cloud_sync_profile()
    workspace_id = profile.get("workspace_id") if isinstance(profile, dict) else None
    binding = store.get_live_request_oauth_binding()
    if binding is not None:
        outbox = store.live_request_outbox_status(
            now=_now(),
            oauth_subject_hash=binding["oauth_subject_hash"],
            workspace_id=binding["workspace_id"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        )
    else:
        outbox = store.live_request_outbox_status(
            now=_now(),
            workspace_id=workspace_id,
        )
    return {
        "state": state.get("state") or "not_configured",
        "last_sync_at": state.get("last_sync_at"),
        "last_success_at": state.get("last_success_at"),
        "last_authenticated_round_trip_at": state.get("last_authenticated_round_trip_at"),
        "last_attempted_sequence": state.get("last_attempted_sequence"),
        "last_acknowledged_sequence": state.get("last_acknowledged_sequence"),
        "last_error": state.get("last_error"),
        "last_error_category": state.get("last_error_category"),
        "worker_heartbeat_at": state.get("worker_heartbeat_at"),
        "watchdog_restart_count": state.get("watchdog_restart_count", 0),
        "adaptive_batch_size": state.get("adaptive_batch_size", LIVE_REQUEST_SYNC_BATCH_SIZE),
        "batch_max_bytes": state.get("batch_max_bytes", DEFAULT_REVIEW_EVENT_BATCH_MAX_BYTES),
        "dead_letter_depth": (
            len(
                store.list_live_request_outbox_dead_letters(
                    oauth_subject_hash=binding["oauth_subject_hash"],
                    workspace_id=binding["workspace_id"],
                    machine_id=binding["machine_id"],
                    machine_installation_id=binding["machine_installation_id"],
                    limit=1_000,
                )
            )
            if binding is not None
            else 0
        ),
        "synced_count": state.get("synced_count", 0),
        "rejected_count": state.get("rejected_count", 0),
        "enqueue_to_send_latency_ms": state.get("enqueue_to_send_average_ms"),
        "enqueue_to_ack_latency_ms": state.get("enqueue_to_ack_average_ms"),
        "outbox": outbox,
        "oauth_source": store.guard_source,
        "protocol_version": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
        "protocolVersion": LIVE_REQUEST_SYNC_PROTOCOL_VERSION,
    }


def _resolve_auth_context_for_retry(store: GuardStore) -> dict[str, object]:
    from .review_event_worker_lifecycle import _resolve_live_request_sync_auth_context

    return _resolve_live_request_sync_auth_context(store, force_refresh=True)
