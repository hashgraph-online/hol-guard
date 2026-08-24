"""Preparation and reconciliation of one durable Review event delivery batch."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass

from ..review_contracts import GuardReviewContractError, guard_review_oauth_metadata
from ..store import GuardStore
from .live_request_event_projection import project_live_request_outbox_row
from .local_request_snapshots import _resolve_cloud_receipt_redaction_level
from .review_event_batch_worker import ReviewEventBatch, take_bounded_batch


@dataclass(frozen=True)
class ReviewEventBatchReconciliation:
    """Acknowledgement effects of one Cloud response."""

    accepted: int
    rejected: int
    errors: list[str]
    continue_sync: bool
    acknowledged_sequences: list[int]
    error_category: str | None = None


def prepare_review_event_batch(
    *,
    store: GuardStore,
    rows: list[dict[str, object]],
    delivery_binding: dict[str, str],
    maximum_events: int,
    maximum_bytes: int,
) -> ReviewEventBatch:
    """Decode, validate, and size a sendable ordered Review event prefix."""

    candidates: list[tuple[int, dict[str, object]]] = []
    redaction_level = _resolve_cloud_receipt_redaction_level(store)
    oauth = None
    with suppress(GuardReviewContractError):
        oauth = guard_review_oauth_metadata(store)
    for row in rows:
        projected = project_live_request_outbox_row(
            store,
            outbox_row=row,
            delivery_binding=delivery_binding,
            redaction_level=redaction_level,
            oauth=oauth,
        )
        if projected is None:
            break
        sequence, event = projected
        candidates.append((sequence, event))
    batch, oversized = take_bounded_batch(candidates, maximum_events=maximum_events, maximum_bytes=maximum_bytes)
    for sequence in oversized:
        store.dead_letter_live_request_outbox_event(
            sequence,
            reason="batch_byte_limit_exceeded",
            error="Review event exceeds the configured delivery byte limit.",
            oauth_subject_hash=delivery_binding["oauth_subject_hash"],
            workspace_id=delivery_binding["workspace_id"],
            machine_id=delivery_binding["machine_id"],
            machine_installation_id=delivery_binding["machine_installation_id"],
        )
    return batch


def reconcile_review_event_batch(
    *,
    store: GuardStore,
    response: dict[str, object],
    events: list[dict[str, object]],
    sequences: list[int],
    delivery_binding: dict[str, str],
    now: str,
    contiguous_ack: int | None,
    is_terminal: Callable[[dict[str, object]], bool],
    is_permanent: Callable[[dict[str, object]], bool],
    retry_message: Callable[[list[dict[str, object]]], str],
) -> ReviewEventBatchReconciliation:
    """Apply only contiguous acknowledgement and durable retry/dead-letter effects."""

    if not sequences or contiguous_ack is None or contiguous_ack < 0 or contiguous_ack > max(sequences):
        message = "Cloud live request sync omitted a valid contiguous acknowledgement."
        store.retry_live_request_outbox(sequences, now=now, error=message, **delivery_binding)
        return ReviewEventBatchReconciliation(0, 0, [message], False, [], "schema")

    accepted = _response_count(response.get("accepted"))
    rejected = _response_count(response.get("rejected"))
    errors = _response_errors(response)
    per_event = response.get("perEventResults")
    if isinstance(per_event, list) and len(per_event) == len(events):
        result = _reconcile_per_event_results(
            store=store,
            results=per_event,
            sequences=sequences,
            accepted=accepted,
            rejected=rejected,
            delivery_binding=delivery_binding,
            now=now,
            contiguous_ack=contiguous_ack,
            is_terminal=is_terminal,
            is_permanent=is_permanent,
            retry_message=retry_message,
        )
        if result is not None:
            retry_errors, acknowledged = result
            return ReviewEventBatchReconciliation(
                accepted,
                rejected,
                [*errors, *retry_errors],
                not retry_errors,
                acknowledged,
                _response_error_category(items=per_event),
            )
    if accepted + rejected != len(events):
        message = "Cloud live request sync acknowledgement count did not match the batch."
        store.retry_live_request_outbox(sequences, now=now, error=message, **delivery_binding)
        return ReviewEventBatchReconciliation(accepted, rejected, [*errors, message], False, [], "schema")
    if rejected:
        message = f"{rejected} live request events were rejected."
        store.retry_live_request_outbox(sequences, now=now, error=message, **delivery_binding)
        return ReviewEventBatchReconciliation(
            accepted,
            rejected,
            [*errors, message],
            False,
            [],
            _response_error_category(items=per_event),
        )
    acknowledged = [sequence for sequence in sequences if sequence <= contiguous_ack]
    store.acknowledge_live_request_outbox(acknowledged, **delivery_binding)
    unacknowledged = [sequence for sequence in sequences if sequence > contiguous_ack]
    if unacknowledged:
        message = "Cloud did not contiguously acknowledge every accepted live request event."
        store.retry_live_request_outbox(unacknowledged, now=now, error=message, **delivery_binding)
        return ReviewEventBatchReconciliation(accepted, rejected, [*errors, message], False, acknowledged, "server")
    return ReviewEventBatchReconciliation(accepted, rejected, errors, True, acknowledged)


def _response_error_category(*, items: object) -> str | None:
    if not isinstance(items, list):
        return None
    codes = {
        str(item.get("code")).lower()
        for item in items
        if isinstance(item, dict) and isinstance(item.get("code"), str) and item.get("code")
    }
    if any("binding" in code or "identity" in code for code in codes):
        return "binding"
    if any("schema" in code or "payload" in code for code in codes):
        return "schema"
    return "server" if codes else None


def _response_count(value: object) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def _response_errors(response: Mapping[str, object]) -> list[str]:
    errors = response.get("errors")
    return [str(error) for error in errors[:5]] if isinstance(errors, list) else []


def _reconcile_per_event_results(
    *,
    store: GuardStore,
    results: list[object],
    sequences: list[int],
    accepted: int,
    rejected: int,
    delivery_binding: dict[str, str],
    now: str,
    contiguous_ack: int,
    is_terminal: Callable[[dict[str, object]], bool],
    is_permanent: Callable[[dict[str, object]], bool],
    retry_message: Callable[[list[dict[str, object]]], str],
) -> tuple[list[str], list[int]] | None:
    valid = all(
        isinstance(item, dict) and item.get("index") == index and isinstance(item.get("accepted"), bool)
        for index, item in enumerate(results)
    )
    items = [item for item in results if isinstance(item, dict)]
    if not valid or sum(bool(item["accepted"]) for item in items) != accepted or len(items) - accepted != rejected:
        return None
    acknowledged: list[int] = []
    retries: list[int] = []
    retry_items: list[dict[str, object]] = []
    for sequence, item in zip(sequences, items, strict=True):
        if item["accepted"] or is_terminal(item):
            if sequence <= contiguous_ack:
                acknowledged.append(sequence)
            else:
                retries.append(sequence)
                retry_items.append(item)
        elif is_permanent(item):
            store.dead_letter_live_request_outbox_event(
                sequence,
                reason=str(item.get("code") or "permanent_rejection"),
                error=retry_message([item]),
                retain_outbox_event=sequence > contiguous_ack,
                oauth_subject_hash=delivery_binding["oauth_subject_hash"],
                workspace_id=delivery_binding["workspace_id"],
                machine_id=delivery_binding["machine_id"],
                machine_installation_id=delivery_binding["machine_installation_id"],
            )
        else:
            retries.append(sequence)
            retry_items.append(item)
    store.acknowledge_live_request_outbox(acknowledged, **delivery_binding)
    if not retries:
        return [], acknowledged
    message = retry_message(retry_items)
    store.retry_live_request_outbox(retries, now=now, error=message, **delivery_binding)
    return [message], acknowledged
