"""Durable, independent synchronization for local Guard approval requests."""

import json
import logging
import urllib.error
from datetime import datetime, timezone
from typing import Any

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
    select_review_event_batch,
)
from .cloud_review_event_delivery import post_review_events
from .cloud_review_event_projection import build_cloud_review_event, project_cloud_review_event
from .cloud_review_retry_recovery import (
    dead_letter_exhausted_review_events,
    recover_rejected_review_events,
    retry_result_message,
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
    limits = persisted_review_batch_limits(state, binding_key)
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


def _is_terminally_superseded_result(item: dict[str, object]) -> bool:
    """Ignore refreshes superseded by an authoritative Cloud decision.

    Decision application acknowledgements travel as separate outbox events.
    """
    if item.get("code") == "stale_sequence":
        return True
    error = item.get("error")
    if error in {"decision_queued", "stale_regression_rejected", "stale_sequence"}:
        return True
    return isinstance(error, str) and error.startswith("stale event sequence ")


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
    made_progress = stalled_batch = False
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

            accepted_value, rejected_value = response.get("accepted"), response.get("rejected")
            accepted = int(accepted_value) if isinstance(accepted_value, (int, float)) else 0
            rejected = int(rejected_value) if isinstance(rejected_value, (int, float)) else 0
            total_accepted += accepted
            total_rejected += rejected
            delivered = response.get("delivered")
            if isinstance(delivered, int) and not isinstance(delivered, bool) and 0 <= delivered <= accepted:
                total_delivered += delivered
            batches += 1
            retry_after_hint = response.get("retryAfterMs")
            if type(retry_after_hint) is int and retry_after_hint > 0:
                retry_after_ms = max(retry_after_ms, retry_after_hint)
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
                snapshot_repairs: dict[str, int] = {}
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
                        if item.get("code") == "review_event_snapshot_required":
                            request_id = events[index].get("localRequestId")
                            request_sequence = events[index].get("localEventSequence")
                            if isinstance(request_id, str) and type(request_sequence) is int:
                                snapshot_repairs[request_id] = max(
                                    snapshot_repairs.get(request_id, 0), request_sequence
                                )
                if (
                    valid_results
                    and sum(bool(item["accepted"]) for item in per_event_results) == accepted
                    and len(per_event_results) - accepted == rejected
                ):
                    marker_ready = _mark_accepted_replay_contexts(store, events, per_event_results, supplied_binding)
                    if not marker_ready:
                        message = "Native workspace review replay marker persistence requires retry."
                        all_errors.append(message)
                        _retry_review_events(store, sequences, error=message, binding=delivery_binding)
                        continue
                    store.acknowledge_review_events(acknowledged_sequences, **delivery_binding)
                    rejected_before_recovery = len(retry_sequences)
                    retry_sequences, retry_results = recover_rejected_review_events(
                        store,
                        sequences=retry_sequences,
                        results=retry_results,
                        events=dict(zip(sequences, events, strict=True)),
                        binding=delivery_binding,
                        acknowledged_through=response.get("acknowledgedThrough"),
                    )
                    resolved_locally = rejected_before_recovery - len(retry_sequences)
                    still_retryable, dead_lettered = dead_letter_exhausted_review_events(
                        store,
                        sequences=retry_sequences,
                        acknowledged=acknowledged_sequences,
                        binding=delivery_binding,
                    )
                    retryable = set(still_retryable)
                    retry_results = [
                        result
                        for sequence, result in zip(retry_sequences, retry_results, strict=True)
                        if sequence in retryable
                    ]
                    retry_sequences = still_retryable
                    if acknowledged_sequences or resolved_locally or dead_lettered:
                        made_progress = True
                    else:
                        stalled_batch = True
                    if retry_sequences:
                        message = retry_result_message(retry_results)
                        all_errors.append(message)
                        store.retry_review_events(
                            retry_sequences,
                            now=_now(),
                            error=message,
                            **delivery_binding,
                        )
                    if snapshot_repairs and store.requeue_pending_review_events(
                        changed_at=_now(), require_binding=True, snapshot_repair_sequences=snapshot_repairs
                    ):
                        made_progress, stalled_batch = True, False
                    if stalled_batch:
                        break
                    continue

            accounted = accepted + rejected
            if accounted != len(events):
                message = "Cloud Review sync acknowledgement count did not match the batch."
                all_errors.append(message)
                _retry_review_events(store, sequences, error=message, binding=delivery_binding)
                stalled_batch = True
                break
            if rejected:
                message = f"{rejected} Cloud Review events were rejected."
                all_errors.append(message)
                _retry_review_events(store, sequences, error=message, binding=delivery_binding)
                stalled_batch = True
                break
            store.acknowledge_review_events(sequences, **delivery_binding)

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
            stalled=stalled_batch and not made_progress,
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
