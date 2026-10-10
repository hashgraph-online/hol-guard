"""OAuth identity binding for local Review outbox events."""

from __future__ import annotations

import json
import sqlite3
from hashlib import sha256
from typing import cast

from .review_event_integrity import review_event_payload_digest
from .sqlite_errors import sqlite_error_is_busy_locked, sqlite_error_is_fatal, sqlite_error_is_io

# pyright: reportAny=false, reportUnusedCallResult=false


def review_event_oauth_subject_hash(grant_id: str | None) -> str | None:
    """Return a non-reversible account binding for an OAuth grant subject."""

    normalized = grant_id.strip() if isinstance(grant_id, str) else ""
    return sha256(normalized.encode("utf-8")).hexdigest() if normalized else None


def _oauth_binding_state_key(source: str) -> str:
    return "oauth_local_credentials" if source == "default" else f"oauth_local_credentials:{source}"


# SQLite primary code. Named sqlite3 exports are not available on Python 3.10.
_SQLITE_SCHEMA = 17


def _review_binding_schema_unavailable(error: sqlite3.OperationalError) -> bool:
    """A missing binding table is no Cloud identity, not a failed local pause."""

    if sqlite_error_is_busy_locked(error) or sqlite_error_is_fatal(error) or sqlite_error_is_io(error):
        return False
    code = getattr(error, "sqlite_errorcode", None)
    if isinstance(code, int) and not isinstance(code, bool) and (code & 0xFF) == _SQLITE_SCHEMA:
        return False
    message = str(error).lower()
    return message.startswith("no such table:") or message.startswith("no such column:")


def _query_review_binding_row(
    connection: sqlite3.Connection,
    sql: str,
    params: tuple[str, ...],
) -> sqlite3.Row | None:
    try:
        return connection.execute(sql, params).fetchone()
    except sqlite3.OperationalError as error:
        code = getattr(error, "sqlite_errorcode", None)
        schema_changed = isinstance(code, int) and not isinstance(code, bool) and (code & 0xFF) == _SQLITE_SCHEMA
        if not schema_changed and str(error).lower() != "database schema has changed":
            raise
        # Another connection can publish schema while this pause is being saved.
        # SQLite requires the statement to be prepared again; one retry is enough.
        return connection.execute(sql, params).fetchone()


def load_review_oauth_binding(connection: sqlite3.Connection, source: str) -> dict[str, str] | None:
    try:
        row = _query_review_binding_row(
            connection,
            "select payload_json from sync_state where state_key = ?",
            (_oauth_binding_state_key(source),),
        )
    except sqlite3.OperationalError as error:
        if _review_binding_schema_unavailable(error):
            return None
        raise
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
    try:
        device = _query_review_binding_row(
            connection,
            "select installation_id from guard_devices where device_key = ?",
            ("local-device",),
        )
    except sqlite3.OperationalError as error:
        if _review_binding_schema_unavailable(error):
            return None
        raise
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
