"""Transactional writes for the local Review event outbox."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from uuid import uuid4

from .review_event_integrity import review_event_payload_digest
from .store_review_event_outbox_binding import load_review_oauth_binding
from .store_review_event_outbox_schema import REVIEW_EVENT_SCHEMA_VERSION, review_event_payload_json

# pyright: reportAny=false, reportUnusedCallResult=false

_REQUEST_SNAPSHOT_JSON_FIELDS = (
    "action_envelope_json",
    "browser_intent_json",
    "continuation_snapshot_json",
    "changed_fields_json",
    "decision_v2_json",
    "risk_signals_json",
    "scanner_evidence_json",
)


def _binding_for_append(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    source: str,
) -> tuple[Mapping[str, str | None], str, str | None]:
    current = load_review_oauth_binding(connection, source)
    prior = connection.execute(
        """
        select oauth_subject_hash, workspace_id, machine_id, machine_installation_id
        from guard_review_outbox_request_sequences
        where local_request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if prior is None:
        values = current or {
            "oauth_subject_hash": None,
            "workspace_id": None,
            "machine_id": None,
            "machine_installation_id": None,
        }
        return (
            values,
            "ready" if current is not None else "quarantined",
            (None if current is not None else "identity_incomplete"),
        )
    prior_values = {
        key: prior[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    prior_complete = all(isinstance(value, str) and value.strip() for value in prior_values.values())
    if not prior_complete:
        return prior_values, "quarantined", "identity_incomplete"
    if current is None or (
        prior_values["oauth_subject_hash"] != current["oauth_subject_hash"]
        or prior_values["workspace_id"] != current["workspace_id"]
    ):
        return prior_values, "quarantined", "identity_changed_requires_confirmation"
    return current, "ready", None


def append_request_snapshot_event(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    source: str,
    event_type: str,
    occurred_at: str,
    continuation_result: Mapping[str, object] | None = None,
    native_application_result: Mapping[str, object] | None = None,
    request_snapshot: Mapping[str, object] | None = None,
    native_replay: bool = False,
) -> int:
    """Append a request snapshot without replacing any unacknowledged event."""

    if request_snapshot is None:
        request_row = connection.execute(
            "select * from approval_requests where request_id = ?",
            (request_id,),
        ).fetchone()
        if request_row is None:
            return 0
        request = dict(request_row)
    else:
        request = dict(request_snapshot)
        if request.get("request_id") != request_id:
            return 0
        for field in _REQUEST_SNAPSHOT_JSON_FIELDS:
            value = request.get(field)
            if isinstance(value, (dict, list)):
                request[field] = json.dumps(value, sort_keys=True, separators=(",", ":"))
    values, binding_status, quarantine_reason = _binding_for_append(
        connection,
        request_id=request_id,
        source=source,
    )
    payload = review_event_payload_json(
        dict(request),
        event_type=event_type,
        occurred_at=occurred_at,
        continuation_result=continuation_result,
        native_replay=native_replay,
        native_application_result=native_application_result,
    )
    connection.execute(
        """
        insert into guard_review_outbox_request_sequences (
          local_request_id, last_sequence, updated_at, oauth_source,
          oauth_subject_hash, workspace_id, machine_id, machine_installation_id
        ) values (?, 1, ?, ?, ?, ?, ?, ?)
        on conflict(local_request_id) do update set
          last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
          updated_at = excluded.updated_at,
          oauth_source = coalesce(guard_review_outbox_request_sequences.oauth_source, excluded.oauth_source),
          oauth_subject_hash = coalesce(
            guard_review_outbox_request_sequences.oauth_subject_hash,
            excluded.oauth_subject_hash
          ),
          workspace_id = coalesce(guard_review_outbox_request_sequences.workspace_id, excluded.workspace_id),
          machine_id = coalesce(guard_review_outbox_request_sequences.machine_id, excluded.machine_id),
          machine_installation_id = coalesce(
            guard_review_outbox_request_sequences.machine_installation_id,
            excluded.machine_installation_id
          )
        """,
        (
            request_id,
            occurred_at,
            source,
            values["oauth_subject_hash"],
            values["workspace_id"],
            values["machine_id"],
            values["machine_installation_id"],
        ),
    )
    row = connection.execute(
        "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("Review event request sequence allocation failed.")
    request_sequence = int(row["last_sequence"])
    cursor = connection.execute(
        """
        insert into guard_review_outbox_events (
          event_id, local_request_id, request_sequence, event_type, event_schema_version,
          payload_json, payload_hash, occurred_at, oauth_source, oauth_subject_hash,
          workspace_id, machine_id, machine_installation_id, binding_status, quarantine_reason
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            uuid4().hex,
            request_id,
            request_sequence,
            event_type,
            REVIEW_EVENT_SCHEMA_VERSION,
            payload,
            review_event_payload_digest(
                payload,
                oauth_source=source,
                oauth_subject_hash=values["oauth_subject_hash"],
                workspace_id=values["workspace_id"],
                machine_id=values["machine_id"],
                machine_installation_id=values["machine_installation_id"],
            ),
            occurred_at,
            source,
            values["oauth_subject_hash"],
            values["workspace_id"],
            values["machine_id"],
            values["machine_installation_id"],
            binding_status,
            quarantine_reason,
        ),
    )
    return max(0, int(cursor.rowcount or 0))
