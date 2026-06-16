"""Legacy Guard connect-state readers for migration compatibility."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone

CONNECT_STATE_VERSION = "guard-connect-state.v1"
CONNECT_STATE_STATUS_VALUES = {"waiting", "connected", "retry_required", "expired"}
CONNECT_STATE_MILESTONE_VALUES = {
    "waiting_for_browser",
    "first_sync_pending",
    "first_sync_succeeded",
    "first_sync_failed",
    "sync_not_available",
    "expired",
}


def connect_request_schema_statement() -> str:
    return """
        create table if not exists guard_connect_requests (
          request_id text primary key,
          sync_url text not null,
          allowed_origin text not null,
          pairing_secret_hash text not null,
          status text not null,
          created_at text not null,
          expires_at text not null,
          completed_at text
        )
        """


def connect_state_schema_statement() -> str:
    return """
        create table if not exists guard_connect_states (
          request_id text primary key,
          sync_url text not null,
          allowed_origin text not null,
          status text not null,
          milestone text not null,
          reason text,
          created_at text not null,
          updated_at text not null,
          expires_at text not null,
          completed_at text,
          proof_json text not null default '{}'
        )
        """


def load_connect_state(
    connection: sqlite3.Connection,
    request_id: str,
    *,
    now: str | None = None,
) -> dict[str, object] | None:
    row = connection.execute(
        """
        select request_id, sync_url, allowed_origin, status, milestone, reason,
               created_at, updated_at, expires_at, completed_at, proof_json
        from guard_connect_states
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    payload = _build_connect_state_payload(row)
    if now is not None and payload["status"] == "waiting" and payload["milestone"] == "waiting_for_browser":
        expires_at = _parse_timestamp(str(payload["expires_at"]))
        if expires_at <= _parse_timestamp(now):
            connection.execute(
                """
                update guard_connect_states
                set status = 'expired',
                    milestone = 'expired',
                    reason = 'request_expired',
                    updated_at = ?
                where request_id = ?
                """,
                (now, request_id),
            )
            connection.execute(
                """
                update guard_connect_requests
                set status = 'expired'
                where request_id = ? and status = 'pending'
                """,
                (request_id,),
            )
            row = connection.execute(
                """
                select request_id, sync_url, allowed_origin, status, milestone, reason,
                       created_at, updated_at, expires_at, completed_at, proof_json
                from guard_connect_states
                where request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if row is None:
                return None
            payload = _build_connect_state_payload(row)
    return payload


def get_latest_connect_state(
    connection: sqlite3.Connection,
    *,
    now: str | None = None,
) -> dict[str, object] | None:
    row = connection.execute(
        """
        select request_id
        from guard_connect_states
        order by updated_at desc
        limit 1
        """
    ).fetchone()
    if row is None:
        return None
    return load_connect_state(connection, str(row["request_id"]), now=now)


def mark_connect_result(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    status: str,
    milestone: str,
    updated_at: str,
    reason: str | None = None,
    sync_payload: dict[str, object] | None = None,
) -> dict[str, object]:
    if status not in CONNECT_STATE_STATUS_VALUES:
        raise ValueError("invalid_connect_state_status")
    if milestone not in CONNECT_STATE_MILESTONE_VALUES:
        raise ValueError("invalid_connect_state_milestone")
    state = load_connect_state(connection, request_id, now=updated_at)
    if state is None:
        raise ValueError("connect_state_not_found")
    proof = _coerce_proof(state.get("proof"))
    if sync_payload is not None:
        if "synced_at" in sync_payload:
            proof["first_synced_at"] = sync_payload.get("synced_at")
        if "receipts_stored" in sync_payload:
            proof["receipts_stored"] = _coerce_non_negative_int(sync_payload.get("receipts_stored"))
        if "inventory_tracked" in sync_payload or "inventory" in sync_payload:
            proof["inventory_items"] = _coerce_non_negative_int(
                sync_payload.get("inventory_tracked", sync_payload.get("inventory"))
            )
        if "runtime_session_id" in sync_payload:
            proof["runtime_session_id"] = sync_payload.get("runtime_session_id")
        if "runtime_session_synced_at" in sync_payload:
            proof["runtime_session_synced_at"] = sync_payload.get("runtime_session_synced_at")
    connection.execute(
        """
        update guard_connect_states
        set status = ?,
            milestone = ?,
            reason = ?,
            updated_at = ?,
            proof_json = ?
        where request_id = ?
        """,
        (
            status,
            milestone,
            reason,
            updated_at,
            json.dumps(proof),
            request_id,
        ),
    )
    return load_connect_state(connection, request_id, now=updated_at) or {}


def build_connect_state_response(
    payload: Mapping[str, object],
    *,
    poll_after_ms: int | None = None,
) -> dict[str, object]:
    response: dict[str, object] = dict(payload)
    response["version"] = CONNECT_STATE_VERSION
    response["poll_after_ms"] = poll_after_ms if poll_after_ms is not None else _resolve_poll_after_ms(response)
    response["proof"] = _coerce_proof(response.get("proof"))
    return response


def _coerce_non_negative_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str) and value.strip():
        try:
            return max(0, int(value.strip()))
        except ValueError:
            return 0
    return 0


def _build_connect_state_payload(row: sqlite3.Row) -> dict[str, object]:
    payload = {
        "request_id": str(row["request_id"]),
        "sync_url": str(row["sync_url"]),
        "allowed_origin": str(row["allowed_origin"]),
        "status": str(row["status"]),
        "milestone": str(row["milestone"]),
        "reason": str(row["reason"]) if row["reason"] is not None else None,
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "expires_at": str(row["expires_at"]),
        "completed_at": str(row["completed_at"]) if row["completed_at"] is not None else None,
        "proof": _coerce_proof(row["proof_json"]),
    }
    return build_connect_state_response(payload)


def _coerce_proof(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return dict(parsed)
    return {}


def _resolve_poll_after_ms(payload: dict[str, object]) -> int:
    if str(payload.get("status")) == "waiting":
        return 1500
    return 0


def _parse_timestamp(value: str) -> datetime:
    normalized_value = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized_value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
