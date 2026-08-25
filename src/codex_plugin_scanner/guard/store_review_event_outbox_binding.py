"""OAuth identity binding for local Review outbox events."""

from __future__ import annotations

import json
import sqlite3
from hashlib import sha256
from typing import cast

from .review_event_integrity import review_event_payload_digest

# pyright: reportAny=false, reportUnusedCallResult=false


def review_event_oauth_subject_hash(grant_id: str | None) -> str | None:
    """Return a non-reversible account binding for an OAuth grant subject."""

    normalized = grant_id.strip() if isinstance(grant_id, str) else ""
    return sha256(normalized.encode("utf-8")).hexdigest() if normalized else None


def _oauth_binding_state_key(source: str) -> str:
    return "oauth_local_credentials" if source == "default" else f"oauth_local_credentials:{source}"


def load_review_oauth_binding(connection: sqlite3.Connection, source: str) -> dict[str, str] | None:
    row = connection.execute(
        "select payload_json from sync_state where state_key = ?",
        (_oauth_binding_state_key(source),),
    ).fetchone()
    if row is None:
        return None
    try:
        parsed = cast(object, json.loads(str(row["payload_json"])))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    raw_payload = cast(dict[object, object], parsed)
    if any(not isinstance(key, str) for key in raw_payload):
        return None
    payload = cast(dict[str, object], raw_payload)
    grant_id = payload.get("grant_id")
    subject_hash = review_event_oauth_subject_hash(grant_id if isinstance(grant_id, str) else None)
    workspace_id = payload.get("workspace_id")
    machine_id = payload.get("machine_id")
    device = connection.execute(
        "select installation_id from guard_devices where device_key = 'local-device'"
    ).fetchone()
    installation_id = device["installation_id"] if device is not None else None
    values = (subject_hash, workspace_id, machine_id, installation_id)
    if not all(isinstance(value, str) and value.strip() for value in values):
        return None
    return {
        "oauth_source": source,
        "oauth_subject_hash": str(subject_hash),
        "workspace_id": str(workspace_id).strip(),
        "machine_id": str(machine_id).strip(),
        "machine_installation_id": str(installation_id).strip(),
    }


def bind_review_events_for_request(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    oauth_source: str,
) -> bool:
    """Bind newly written events inside the approval write transaction."""

    binding = load_review_oauth_binding(connection, oauth_source)
    if binding is None:
        return False
    candidate = connection.execute(
        """
        select stream_sequence, payload_json from guard_review_outbox_events
        where local_request_id = ?
          and request_sequence = 1
          and oauth_source = ?
          and binding_status = 'quarantined'
          and oauth_subject_hash is null
          and workspace_id is null
          and machine_id is null
          and machine_installation_id is null
          and not exists (
            select 1 from guard_review_outbox_events as later
            where later.local_request_id = guard_review_outbox_events.local_request_id
              and later.request_sequence > 1
          )
        """,
        (request_id, oauth_source),
    ).fetchone()
    if candidate is None:
        return False
    payload_hash = review_event_payload_digest(
        str(candidate["payload_json"]),
        oauth_source=oauth_source,
        oauth_subject_hash=binding["oauth_subject_hash"],
        workspace_id=binding["workspace_id"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    connection.execute(
        """
        update guard_review_outbox_events
        set payload_hash = ?, oauth_subject_hash = ?, workspace_id = ?, machine_id = ?,
            machine_installation_id = ?, binding_status = 'ready', quarantine_reason = null
        where stream_sequence = ?
        """,
        (
            payload_hash,
            binding["oauth_subject_hash"],
            binding["workspace_id"],
            binding["machine_id"],
            binding["machine_installation_id"],
            candidate["stream_sequence"],
        ),
    )
    connection.execute(
        """
        update guard_review_outbox_request_sequences
        set oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?,
            machine_id = ?, machine_installation_id = ?
        where local_request_id = ?
        """,
        (
            oauth_source,
            binding["oauth_subject_hash"],
            binding["workspace_id"],
            binding["machine_id"],
            binding["machine_installation_id"],
            request_id,
        ),
    )
    return True


def normalized_delivery_binding(
    *,
    oauth_subject_hash: str,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
) -> tuple[str, str, str, str]:
    values = (
        oauth_subject_hash.strip(),
        workspace_id.strip(),
        machine_id.strip(),
        machine_installation_id.strip(),
    )
    if not all(values):
        raise ValueError("complete Cloud Review OAuth binding is required")
    return values


def refresh_same_subject_binding(connection: sqlite3.Connection, source: str) -> int:
    """Refresh machine metadata only when subject and workspace are unchanged."""

    binding = load_review_oauth_binding(connection, source)
    if binding is None:
        return 0
    candidates = connection.execute(
        """
        select stream_sequence, payload_json from guard_review_outbox_events
        where oauth_source = ?
          and oauth_subject_hash = ?
          and workspace_id = ?
          and binding_status = 'ready'
          and (machine_id is not ? or machine_installation_id is not ?)
        """,
        (
            source,
            binding["oauth_subject_hash"],
            binding["workspace_id"],
            binding["machine_id"],
            binding["machine_installation_id"],
        ),
    ).fetchall()
    for candidate in candidates:
        payload_hash = review_event_payload_digest(
            str(candidate["payload_json"]),
            oauth_source=source,
            oauth_subject_hash=binding["oauth_subject_hash"],
            workspace_id=binding["workspace_id"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        )
        connection.execute(
            """
            update guard_review_outbox_events
            set payload_hash = ?, machine_id = ?, machine_installation_id = ?,
                binding_status = 'ready', quarantine_reason = null
            where stream_sequence = ?
            """,
            (
                payload_hash,
                binding["machine_id"],
                binding["machine_installation_id"],
                candidate["stream_sequence"],
            ),
        )
    refreshed = len(candidates)
    connection.execute(
        """
        update guard_review_outbox_request_sequences
        set machine_id = ?, machine_installation_id = ?
        where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
        """,
        (
            binding["machine_id"],
            binding["machine_installation_id"],
            source,
            binding["oauth_subject_hash"],
            binding["workspace_id"],
        ),
    )
    quarantined = connection.execute(
        """
        update guard_review_outbox_events
        set binding_status = 'quarantined', quarantine_reason = 'identity_changed_requires_confirmation'
        where oauth_source = ? and binding_status = 'ready'
          and (oauth_subject_hash is not ? or workspace_id is not ?)
        """,
        (source, binding["oauth_subject_hash"], binding["workspace_id"]),
    )
    return refreshed + max(0, int(quarantined.rowcount or 0))


def explicitly_reassign_quarantined_events(
    connection: sqlite3.Connection,
    *,
    source: str,
    approved_source: str,
    approved_workspace_id: str,
) -> int:
    """Adopt quarantined events only after a caller confirms the target binding."""

    if approved_source.strip() != source:
        raise ValueError("approved source does not match the active Guard connection source")
    binding = load_review_oauth_binding(connection, source)
    if binding is None:
        raise ValueError("active OAuth source does not have a complete Review event binding")
    if approved_workspace_id.strip() != binding["workspace_id"]:
        raise ValueError("approved workspace does not match the active OAuth workspace")
    candidates = connection.execute(
        """
        select stream_sequence, payload_json from guard_review_outbox_events
        where binding_status = 'quarantined'
          and quarantine_reason in (
            'identity_incomplete',
            'identity_changed_requires_confirmation'
          )
          and (
            oauth_source = ?
            or (oauth_source is null and (workspace_id is null or workspace_id = ?))
          )
        """,
        (
            source,
            approved_workspace_id.strip(),
        ),
    ).fetchall()
    for candidate in candidates:
        payload_hash = review_event_payload_digest(
            str(candidate["payload_json"]),
            oauth_source=source,
            oauth_subject_hash=binding["oauth_subject_hash"],
            workspace_id=binding["workspace_id"],
            machine_id=binding["machine_id"],
            machine_installation_id=binding["machine_installation_id"],
        )
        connection.execute(
            """
            update guard_review_outbox_events
            set payload_hash = ?, oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?,
                machine_id = ?, machine_installation_id = ?,
                binding_status = 'ready', quarantine_reason = null
            where stream_sequence = ?
            """,
            (
                payload_hash,
                source,
                binding["oauth_subject_hash"],
                binding["workspace_id"],
                binding["machine_id"],
                binding["machine_installation_id"],
                candidate["stream_sequence"],
            ),
        )
    connection.execute(
        """
        update guard_review_outbox_request_sequences
        set oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?, machine_id = ?,
            machine_installation_id = ?
        where local_request_id in (
          select local_request_id from guard_review_outbox_events
          where oauth_source = ? and workspace_id = ?
        )
        """,
        (
            source,
            binding["oauth_subject_hash"],
            binding["workspace_id"],
            binding["machine_id"],
            binding["machine_installation_id"],
            source,
            binding["workspace_id"],
        ),
    )
    connection.execute(
        """
        update approval_requests
        set oauth_source = ?
        where oauth_source is null
          and request_id in (
            select local_request_id from guard_review_outbox_events
            where oauth_source = ? and workspace_id = ?
          )
        """,
        (source, source, binding["workspace_id"]),
    )
    return len(candidates)
