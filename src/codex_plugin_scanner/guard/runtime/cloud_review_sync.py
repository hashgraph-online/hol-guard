"""Durable, independent synchronization for local Guard approval requests."""

import json
import logging
import urllib.error
from datetime import datetime, timezone
from typing import Any, cast

from ..config import VALID_RECEIPT_REDACTION_LEVELS, load_guard_config
from ..review_contracts import GuardReviewContractError, guard_review_oauth_metadata
from ..store import GuardStore
from ..synced_policy import validated_synced_policy_bundle
from .cloud_request_native import cloud_error_text
from .cloud_review_batching import (
    CloudReviewBatchLimits,
    CloudReviewEventTooLargeError,
    next_review_batch_limits,
    persisted_review_batch_limits,
    review_batch_answer,
    select_review_event_batch,
)
from .cloud_review_event_delivery import CloudReviewEventProtocolError, post_review_events
from .cloud_review_event_projection import build_cloud_review_event, project_cloud_review_event
from .cloud_review_retry_recovery import (
    forget_rejection_counts,
    retry_result_message,
    settle_rejected_review_events,
)
from .cloud_review_sync_auth import resolve_cloud_review_sync_auth_context as _resolve_cloud_review_sync_auth_context
from .native_workspace_review_context import NativeWorkspaceReviewContextProbeState
from .native_workspace_review_replay import (
    _PROBE_STATE_ATTRIBUTE,
    _mark_accepted_replay_contexts,
    _prepare_native_replay_commit_states,
)
from .oauth_request_retry import request_after_oauth_refresh

_LOGGER = logging.getLogger(__name__)

CLOUD_REVIEW_SYNC_MAX_BATCHES = 200
CLOUD_REVIEW_SYNC_STATE_KEY = "guard_cloud_review_sync_state"

__all__ = [
    "CloudReviewSyncWorker",
    "build_cloud_review_event",
    "start_cloud_sync_sync_worker",
    "stop_cloud_sync_sync_worker",
    "sync_cloud_review_events_once",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_cloud_receipt_redaction_level(store: GuardStore) -> str:
    policy_bundle = validated_synced_policy_bundle(store)
    if policy_bundle is not None:
        level = policy_bundle.get("receiptRedactionLevel")
        if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS:
            return level
    try:
        config = load_guard_config(store.guard_home)
        if config.receipt_redaction_level in VALID_RECEIPT_REDACTION_LEVELS:
            return config.receipt_redaction_level
    except (OSError, ValueError):
        pass
    return "full"


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
    try:
        limits = persisted_review_batch_limits(state, binding_key)
    except CloudReviewEventProtocolError:
        # The first batch hits the same refusal inside the run, which records it.
        limits = CloudReviewBatchLimits()
    state.update({"state": "syncing", "last_sync_attempt_at": _now(), "last_error": None, "last_error_code": None})
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


def _sync_result(
    *,
    accepted: int,
    rejected: int,
    errors: list[str],
    batches: int,
    outbox: dict[str, object],
    stalled: bool = False,
    retry_after_ms: int = 0,
) -> dict[str, object]:
    return {
        "synced": accepted,
        "rejected": rejected,
        "errors": errors[:5],
        "cursor": None,
        "batches": batches,
        "outbox": outbox,
        "next_attempt_at": outbox.get("next_attempt_at"),
        "stalled": stalled,
        "retry_after_ms": retry_after_ms,
    }


def _complete_sync_state(
    store: GuardStore,
    state: dict[str, object],
    delivery_binding: dict[str, str],
    *,
    accepted: int,
    delivered: int,
    rejected: int,
    errors: list[str],
) -> tuple[str, dict[str, object]]:
    completed_at = _now()
    outbox_status = store.review_event_outbox_status(now=completed_at, **delivery_binding)
    pending_error = errors[0] if errors else outbox_status.get("last_error")
    if accepted > 0 or outbox_status["depth"] == 0:
        state["last_success_at"] = completed_at
    if delivered > 0:
        state.update({"last_delivery_at": completed_at, "last_delivery_binding": delivery_binding})
    state.update(
        {
            "state": "error" if pending_error and outbox_status["depth"] else "idle",
            "last_sync_at": completed_at,
            "synced_count": accepted,
            "rejected_count": rejected,
            "last_error": pending_error,
            "outbox_depth": outbox_status["depth"],
            "outbox_oldest_changed_at": outbox_status["oldest_changed_at"],
        }
    )
    _save_sync_state(store, state)
    return completed_at, outbox_status


def _settle_review_batch(
    response: dict[str, object],
    events: list[dict[str, object]],
    sequences: list[int],
) -> dict[str, object]:
    """Read Cloud's answer to one batch in the native ``cloud_review_batch`` kind."""
    answer = review_batch_answer(
        {
            "op": "settle",
            "response": response,
            "sequences": sequences,
            "snapshot_keys": [[event.get("localRequestId"), event.get("localEventSequence")] for event in events],
        }
    )
    if answer.get("plan") not in {"per_event", "count_mismatch", "rejected", "acknowledge"}:
        raise CloudReviewEventProtocolError("HOL Guard native runtime returned a malformed Review batch settlement.")
    return answer


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


def _retry_review_events(store: GuardStore, sequences: list[int], *, error: str, binding: dict[str, str]) -> None:
    store.retry_review_events(sequences, now=_now(), error=cloud_error_text(error), **binding)


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

    total_accepted = total_rejected = total_delivered = batches = 0
    all_errors: list[str] = []
    # A batch that Cloud answered without accepting, acknowledging, or
    # dead-lettering anything ends the run so the worker can back off the whole
    # queue instead of sending the next due batch straight away.
    stalled_batch = False
    retry_after_ms = 0
    native_context_probe_state = getattr(store, _PROBE_STATE_ATTRIBUTE, None)
    setattr(store, _PROBE_STATE_ATTRIBUTE, None)
    if not isinstance(native_context_probe_state, NativeWorkspaceReviewContextProbeState):
        native_context_probe_state = NativeWorkspaceReviewContextProbeState()

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
            projection_options: dict[str, Any] = {
                "delivery_binding": delivery_binding,
                "redaction_level": redaction_level,
                "oauth": oauth,
                "native_context_probe_state": native_context_probe_state,
            }
            for outbox_row in outbox_rows:
                projected = project_cloud_review_event(store, outbox_row=outbox_row, **projection_options)
                if projected is None:
                    continue
                sequences.append(projected[0])
                events.append(projected[1])
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
            if not _prepare_native_replay_commit_states(store, events, supplied_binding):
                message = "Native workspace review replay commitment state requires retry."
                all_errors.append(message)
                _retry_review_events(store, sequences, error=message, binding=delivery_binding)
                continue
            try:
                response, auth_context = _post_events_with_oauth_refresh(store, auth_context, events)
            except Exception as error:
                _retry_review_events(store, sequences, error=_redacted_error(error), binding=delivery_binding)
                raise

            settled = _settle_review_batch(response, events, sequences)
            accepted, rejected = cast("int", settled["accepted"]), cast("int", settled["rejected"])
            total_accepted += accepted
            total_rejected += rejected
            total_delivered += cast("int", settled["delivered"])
            batches += 1
            retry_after_ms = max(retry_after_ms, cast("int", settled["retry_after_ms"]))
            batch_limits = next_review_batch_limits(batch_limits, response)
            _persist_sync_batch_limits(store, state, batch_binding_key, batch_limits)

            errors = response.get("errors")
            if isinstance(errors, list):
                all_errors.extend(str(error) for error in errors[:5])
            plan = settled["plan"]
            if plan == "per_event":
                acknowledged_sequences = cast("list[int]", settled["acknowledged"])
                marker_ready = _mark_accepted_replay_contexts(
                    store, events, cast("list[dict[str, object]]", response["perEventResults"]), supplied_binding
                )
                if not marker_ready:
                    message = "Native workspace review replay marker persistence requires retry."
                    all_errors.append(message)
                    _retry_review_events(store, sequences, error=message, binding=delivery_binding)
                    continue
                store.acknowledge_review_events(acknowledged_sequences, **delivery_binding)
                retry_sequences, retry_results, progressed = settle_rejected_review_events(
                    store,
                    sequences=cast("list[int]", settled["retry"]),
                    results=cast("list[dict[str, object]]", settled["retry_results"]),
                    events=dict(zip(sequences, events, strict=True)),
                    acknowledged=acknowledged_sequences,
                    acknowledged_through=response.get("acknowledgedThrough"),
                    binding=delivery_binding,
                )
                stalled_batch = not progressed
                if retry_sequences:
                    message = retry_result_message(retry_results)
                    all_errors.append(message)
                    store.retry_review_events(
                        retry_sequences,
                        now=_now(),
                        error=message,
                        **delivery_binding,
                    )
                snapshot_repairs = cast("dict[str, int]", settled["snapshot_repairs"])
                if snapshot_repairs and store.requeue_pending_review_events(
                    changed_at=_now(), require_binding=True, snapshot_repair_sequences=snapshot_repairs
                ):
                    stalled_batch = False
                if stalled_batch:
                    break
                continue
            if plan != "acknowledge":
                message = (
                    "Cloud Review sync acknowledgement count did not match the batch."
                    if plan == "count_mismatch"
                    else f"{rejected} Cloud Review events were rejected."
                )
                all_errors.append(message)
                _retry_review_events(store, sequences, error=message, binding=delivery_binding)
                stalled_batch = True
                break
            store.acknowledge_review_events(sequences, **delivery_binding)
            forget_rejection_counts(store, sequences)

        _, outbox_status = _complete_sync_state(
            store,
            state,
            delivery_binding,
            accepted=total_accepted,
            delivered=total_delivered,
            rejected=total_rejected,
            errors=all_errors,
        )

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
        return _sync_result(
            accepted=total_accepted,
            rejected=total_rejected,
            errors=all_errors,
            batches=batches,
            outbox=outbox_status,
            stalled=stalled_batch,
            retry_after_ms=retry_after_ms if stalled_batch else 0,
        )
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


from .cloud_review_sync_worker import (  # noqa: E402
    CloudReviewSyncWorker,
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)
