"""Repair a rejected retry identity without changing approval authority."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping

from .continuation_snapshot import validated_continuation_snapshot
from .review_correlation import cloud_review_correlation_id
from .store_review_event_acknowledgment import acknowledge_review_events
from .store_review_event_outbox_binding import load_review_oauth_binding, normalized_delivery_binding
from .store_review_event_outbox_writes import append_request_snapshot_event

_BINDING_FIELDS = ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")


def repair_rejected_review_correlation(
    connection: sqlite3.Connection,
    *,
    source: str,
    event_sequence: int,
    binding: Mapping[str, str],
    changed_at: str,
) -> int:
    """Restore only the deterministic identity explicitly requested by Cloud."""
    _ = connection.execute("begin immediate")
    current_binding = load_review_oauth_binding(connection, source)
    if current_binding is None or any(current_binding.get(key) != binding.get(key) for key in _BINDING_FIELDS):
        return 0
    event = connection.execute(
        "select * from guard_review_outbox_events where stream_sequence = ? and oauth_source = ?",
        (event_sequence, source),
    ).fetchone()
    if event is None or any(event[key] != binding.get(key) for key in _BINDING_FIELDS):
        return 0
    if event["binding_status"] != "ready" or event["acknowledged_at"] is not None:
        return 0
    request_id = str(event["local_request_id"])
    request = connection.execute(
        """select continuation_snapshot_json from approval_requests
        where request_id = ? and oauth_source = ? and status = 'pending'""",
        (request_id, source),
    ).fetchone()
    established = connection.execute(
        "select * from guard_review_outbox_request_sequences where local_request_id = ?",
        (request_id,),
    ).fetchone()
    if request is None or established is None or established["oauth_source"] != source:
        return 0
    if any(established[key] != binding.get(key) for key in _BINDING_FIELDS):
        return 0
    try:
        snapshot = validated_continuation_snapshot(json.loads(request[0]))
    except (TypeError, ValueError):
        return 0
    if snapshot is None or snapshot["capability"] not in {"retry-only", "unsupported"}:
        return 0
    correlation_id = cloud_review_correlation_id(request_id)
    if snapshot["correlationId"] == correlation_id:
        return 0
    snapshot["correlationId"] = correlation_id
    _ = connection.execute(
        "update approval_requests set continuation_snapshot_json = ? where request_id = ? and oauth_source = ?",
        (json.dumps(snapshot, sort_keys=True, separators=(",", ":")), request_id, source),
    )
    appended = append_request_snapshot_event(
        connection,
        request_id=request_id,
        source=source,
        event_type="review.request.snapshot_requeued",
        occurred_at=changed_at,
    )
    if appended == 0:
        raise sqlite3.IntegrityError("Retry identity repair did not append its replacement event")
    _ = acknowledge_review_events(
        connection,
        source=source,
        sequences=[event_sequence],
        binding=normalized_delivery_binding(
            oauth_subject_hash=binding["oauth_subject_hash"],
            workspace_id=binding["workspace_id"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        ),
        acknowledged_at=changed_at,
    )
    return appended
