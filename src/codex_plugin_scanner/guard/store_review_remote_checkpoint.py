"""Settle remotely durable Review events without rewriting immutable payloads."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from typing import TYPE_CHECKING

from .runtime.cloud_review_event_delivery import CloudReviewEventProtocolError
from .store_review_event_acknowledgment import acknowledge_review_events
from .store_review_event_outbox_binding import load_review_oauth_binding, normalized_delivery_binding

if TYPE_CHECKING:
    from .store import GuardStore


def apply_review_remote_checkpoint(store: GuardStore, *, acknowledged_through: object, binding: dict[str, str]) -> int:
    """Validate identity, allocation bounds, and monotonicity in one transaction.

    A rejected replay can refer to an event that was accepted before a response
    was lost. The durable remote checkpoint settles that earlier acceptance;
    it does not count the current rejected payload as a new delivery.
    """
    if type(acknowledged_through) is not int or acknowledged_through < 0:
        raise CloudReviewEventProtocolError("Cloud Review returned an invalid durable checkpoint.")
    normalized = normalized_delivery_binding(**binding)
    source = store.guard_source
    identity = (source, *normalized)
    key_digest = sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
    state_key = f"guard_review_remote_checkpoint:{key_digest}"
    now = datetime.now(timezone.utc).isoformat()
    with store._connect() as connection:
        connection.execute("begin immediate")
        if load_review_oauth_binding(connection, source) != {"oauth_source": source, **binding}:
            raise CloudReviewEventProtocolError("Cloud Review checkpoint identity changed during delivery.")
        prior_row = connection.execute(
            "select payload_json from sync_state where state_key = ?", (state_key,)
        ).fetchone()
        prior = 0
        if prior_row is not None:
            try:
                payload = json.loads(str(prior_row["payload_json"]))
                prior = payload["acknowledgedThrough"]
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise CloudReviewEventProtocolError("Stored Cloud Review checkpoint is invalid.") from error
            if type(prior) is not int or prior < 0:
                raise CloudReviewEventProtocolError("Stored Cloud Review checkpoint is invalid.")
        highest = connection.execute(
            """
            select max(sequence) as sequence from (
              select max(stream_sequence) as sequence from guard_review_outbox_events
              where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
                and machine_id = ? and machine_installation_id = ?
              union all
              select acknowledged_stream_sequence as sequence from guard_review_outbox_cursors
              where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
                and machine_id = ? and machine_installation_id = ?
            )
            """,
            (*identity, *identity),
        ).fetchone()
        maximum = int(highest["sequence"] or 0) if highest is not None else 0
        if acknowledged_through < prior or acknowledged_through > maximum:
            raise CloudReviewEventProtocolError("Cloud Review durable checkpoint is outside the known stream bounds.")
        rows = connection.execute(
            """
            select stream_sequence from guard_review_outbox_events
            where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
              and machine_id = ? and machine_installation_id = ?
              and binding_status = 'ready' and stream_sequence <= ?
            order by stream_sequence
            """,
            (*identity, acknowledged_through),
        ).fetchall()
        acknowledge_review_events(
            connection,
            source=source,
            sequences=[int(row["stream_sequence"]) for row in rows],
            binding=normalized,
            acknowledged_at=now,
        )
        connection.execute(
            """
            insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)
            on conflict(state_key) do update set payload_json = excluded.payload_json, updated_at = excluded.updated_at
            """,
            (state_key, json.dumps({"acknowledgedThrough": acknowledged_through}), now),
        )
    return acknowledged_through
