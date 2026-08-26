"""Durable, independent synchronization for local Guard approval requests."""

import json
import logging
import urllib.error
from datetime import datetime, timezone

from ..review_contracts import (
    GuardReviewContractError,
    guard_review_oauth_metadata,
)
from ..store import GuardStore
from .cloud_review_batching import (
    CloudReviewBatchLimits,
    CloudReviewEventTooLargeError,
    next_review_batch_limits,
    persisted_review_batch_limits,
    select_review_event_batch,
)
from .cloud_review_event_delivery import (
    CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
    post_review_events,
)
from .cloud_review_event_projection import build_cloud_review_event, project_cloud_review_event
from .cloud_review_sync_auth import resolve_cloud_review_sync_auth_context as _resolve_cloud_review_sync_auth_context
from .local_request_snapshots import (
    _cloud_scrub_text,
    _resolve_cloud_receipt_redaction_level,
)
from .oauth_request_retry import request_after_oauth_refresh

_LOGGER = logging.getLogger(__name__)

CLOUD_REVIEW_SYNC_MAX_BATCHES = 200
CLOUD_REVIEW_SYNC_STATE_KEY = "guard_cloud_review_sync_state"

__all__ = [
    "CloudReviewSyncWorker",
    "build_cloud_review_event",
    "cloud_review_sync_status",
    "start_cloud_sync_sync_worker",
    "stop_cloud_sync_sync_worker",
    "sync_cloud_review_events_once",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redacted_error(error: BaseException) -> str:
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP Error {error.code}: {error.reason}"
    if isinstance(error, OSError):
        return type(error).__name__
    return str(error)


def _cloud_review_sync_state_key(store: GuardStore) -> str:
    source = store.guard_source
    if source == "default":
        return CLOUD_REVIEW_SYNC_STATE_KEY
    return f"{CLOUD_REVIEW_SYNC_STATE_KEY}:{source}"


def _load_sync_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload(_cloud_review_sync_state_key(store))
    return dict(payload) if isinstance(payload, dict) else {}


def _save_sync_state(store: GuardStore, state: dict[str, object]) -> None:
    store.set_sync_payload(_cloud_review_sync_state_key(store), state, _now())


def _batch_binding_key(binding: dict[str, str]) -> str:
    return json.dumps(
        [binding[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")],
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _prepare_sync_batch_state(
    store: GuardStore,
    delivery_binding: dict[str, str],
) -> tuple[dict[str, object], str, CloudReviewBatchLimits]:
    state = _load_sync_state(store)
    binding_key = _batch_binding_key(delivery_binding)
    limits = persisted_review_batch_limits(state, binding_key)
    state.update({"state": "syncing", "last_sync_attempt_at": _now(), "last_error": None})
    _save_sync_state(store, state)
    return state, binding_key, limits


def _persist_sync_batch_limits(
    store: GuardStore,
    state: dict[str, object],
    binding_key: str,
    limits: CloudReviewBatchLimits,
) -> None:
    state.update(
        {
            "batch_binding_key": binding_key,
            "batch_events": limits.events,
            "batch_max_bytes": limits.bytes,
            "batch_event_cap": limits.event_cap,
        }
    )
    _save_sync_state(store, state)


def _select_or_quarantine_sync_batch(
    store: GuardStore,
    events: list[dict[str, object]],
    sequences: list[int],
    limits: CloudReviewBatchLimits,
    delivery_binding: dict[str, str],
) -> tuple[list[dict[str, object]], list[int], int, list[str]]:
    try:
        selected = select_review_event_batch(events, limits)
    except CloudReviewEventTooLargeError as error:
        message = _redacted_error(error)
        store.quarantine_review_event(
            sequences[0],
            reason="event_exceeds_upload_limit",
            error=message,
            **delivery_binding,
        )
        return [], [], 1, [message]
    return selected, sequences[: len(selected)], 0, []


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
    message = f"{len(items)} Cloud Review events require retry."
    if details:
        return f"{message} Cloud reported: {'; '.join(details[:3])}."
    return message


def _post_events_with_oauth_refresh(
    store: GuardStore,
    auth_context: dict[str, object],
    events: list[dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    return request_after_oauth_refresh(
        auth_context,
        request=lambda current: post_review_events(current, events=events),
        refresh=lambda: _resolve_cloud_review_sync_auth_context(store, force_refresh=True),
        logger=_LOGGER,
        operation="Cloud Review event upload",
    )


def sync_cloud_review_events_once(
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

    if not all(supplied_binding.values()) or supplied_binding != store.get_review_event_oauth_binding():
        raise RuntimeError(
            "Cloud Review sync requires a matching source, OAuth subject, machine, workspace, and installation binding."
        )
    delivery_binding = {
        "oauth_subject_hash": oauth_subject_hash,
        "workspace_id": workspace_id,
        "machine_id": machine_id,
        "machine_installation_id": machine_installation_id,
    }
    store.refresh_review_event_outbox_binding_for_identity(**delivery_binding)

    state, batch_binding_key, batch_limits = _prepare_sync_batch_state(store, delivery_binding)

    total_accepted = total_rejected = 0
    all_errors: list[str] = []
    batches = 0

    try:
        while batches < CLOUD_REVIEW_SYNC_MAX_BATCHES:
            newest_first = batches % 10 != 9
            outbox_rows = store.list_ready_review_events(
                now=_now(),
                limit=batch_limits.events,
                **delivery_binding,
                newest_first=newest_first,
            )
            if not outbox_rows:
                break

            events: list[dict[str, object]] = []
            sequences: list[int] = []
            redaction_level = _resolve_cloud_receipt_redaction_level(store)
            try:
                oauth = guard_review_oauth_metadata(store)
            except GuardReviewContractError:
                oauth = None
            for outbox_row in outbox_rows:
                projected = project_cloud_review_event(
                    store,
                    outbox_row=outbox_row,
                    delivery_binding=delivery_binding,
                    redaction_level=redaction_level,
                    oauth=oauth,
                )
                if projected is None:
                    continue
                sequence, event = projected
                sequences.append(sequence)
                events.append(event)
            events, sequences, local_rejected, local_errors = _select_or_quarantine_sync_batch(
                store,
                events,
                sequences,
                batch_limits,
                delivery_binding,
            )
            total_rejected += local_rejected
            all_errors.extend(local_errors)
            batches += local_rejected
            if not events:
                continue
            try:
                response, auth_context = _post_events_with_oauth_refresh(store, auth_context, events)
            except Exception as error:
                store.retry_review_events(
                    sequences,
                    now=_now(),
                    error=_redacted_error(error),
                    **delivery_binding,
                )
                raise

            accepted_value = response.get("accepted")
            rejected_value = response.get("rejected")
            accepted = int(accepted_value) if isinstance(accepted_value, (int, float)) else 0
            rejected = int(rejected_value) if isinstance(rejected_value, (int, float)) else 0
            total_accepted += accepted
            total_rejected += rejected
            batches += 1
            batch_limits = next_review_batch_limits(batch_limits, response)
            _persist_sync_batch_limits(store, state, batch_binding_key, batch_limits)

            errors = response.get("errors")
            if isinstance(errors, list):
                all_errors.extend(str(error) for error in errors[:5])
            per_event_results = response.get("perEventResults")
            if isinstance(per_event_results, list) and len(per_event_results) == len(events):
                acknowledged_sequences: list[int] = []
                retry_sequences: list[int] = []
                retry_results: list[dict[str, object]] = []
                valid_results = True
                for index, item in enumerate(per_event_results):
                    if (
                        not isinstance(item, dict)
                        or item.get("index") != index
                        or not isinstance(item.get("accepted"), bool)
                    ):
                        valid_results = False
                        break
                    if item["accepted"] or _is_terminally_superseded_result(item):
                        acknowledged_sequences.append(sequences[index])
                    else:
                        retry_sequences.append(sequences[index])
                        retry_results.append(item)
                if (
                    valid_results
                    and sum(bool(item["accepted"]) for item in per_event_results) == accepted
                    and len(per_event_results) - accepted == rejected
                ):
                    store.acknowledge_review_events(acknowledged_sequences, **delivery_binding)
                    if retry_sequences:
                        message = _retry_result_message(retry_results)
                        all_errors.append(message)
                        store.retry_review_events(
                            retry_sequences,
                            now=_now(),
                            error=message,
                            **delivery_binding,
                        )
                    continue

            accounted = accepted + rejected
            if accounted != len(events):
                message = "Cloud Review sync acknowledgement count did not match the batch."
                all_errors.append(message)
                store.retry_review_events(
                    sequences,
                    now=_now(),
                    error=message,
                    **delivery_binding,
                )
                break
            if rejected:
                message = f"{rejected} Cloud Review events were rejected."
                all_errors.append(message)
                store.retry_review_events(
                    sequences,
                    now=_now(),
                    error=message,
                    **delivery_binding,
                )
                break
            store.acknowledge_review_events(sequences, **delivery_binding)

        completed_at = _now()
        outbox_status = store.review_event_outbox_status(
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
            }
        )
        _save_sync_state(store, state)

        outbox_depth = outbox_status["depth"]
        if not isinstance(outbox_depth, int):
            raise RuntimeError("Cloud Review event outbox depth is invalid.")
        _LOGGER.info(
            "Cloud Review sync complete: accepted=%d rejected=%d batches=%d outbox_depth=%d",
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
            "next_attempt_at": outbox_status.get("next_attempt_at"),
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
        _LOGGER.warning("Cloud Review sync failed: %s", error_message)
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
        _LOGGER.warning("Cloud Review sync failed: %s", error_message)
        raise


def cloud_review_sync_status(store: GuardStore) -> dict[str, object]:
    """Return Cloud Review outbox and delivery health."""
    state = _load_sync_state(store)
    profile = store.get_cloud_sync_profile()
    workspace_id = profile.get("workspace_id") if isinstance(profile, dict) else None
    binding = store.get_review_event_oauth_binding()
    if binding is not None:
        outbox = store.review_event_outbox_status(
            now=_now(),
            oauth_subject_hash=binding["oauth_subject_hash"],
            workspace_id=binding["workspace_id"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        )
    else:
        outbox = store.review_event_outbox_status(
            now=_now(),
            workspace_id=workspace_id,
        )
    return {
        "state": state.get("state") or "not_configured",
        "last_sync_at": state.get("last_sync_at"),
        "last_success_at": state.get("last_success_at"),
        "last_error": state.get("last_error"),
        "synced_count": state.get("synced_count", 0),
        "rejected_count": state.get("rejected_count", 0),
        "outbox": outbox,
        "oauth_source": store.guard_source,
        "protocol_version": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
        "protocolVersion": CLOUD_REVIEW_EVENT_PROTOCOL_VERSION,
    }


from .cloud_review_sync_worker import (  # noqa: E402
    CloudReviewSyncWorker,
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)
