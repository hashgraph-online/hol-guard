"""One-time browser pairing persistence helpers for Guard connect."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

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


def create_connect_request(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    sync_url: str,
    allowed_origin: str,
    pairing_secret_hash: str,
    created_at: str,
    expires_at: str,
) -> None:
    connection.execute(
        """
        insert into guard_connect_requests (
          request_id,
          sync_url,
          allowed_origin,
          pairing_secret_hash,
          status,
          created_at,
          expires_at,
          completed_at
        )
        values (?, ?, ?, ?, 'pending', ?, ?, null)
        """,
        (
            request_id,
            sync_url,
            allowed_origin,
            pairing_secret_hash,
            created_at,
            expires_at,
        ),
    )


def get_connect_request(
    connection: sqlite3.Connection,
    request_id: str,
) -> dict[str, object] | None:
    row = connection.execute(
        """
        select request_id, sync_url, allowed_origin, status, created_at, expires_at, completed_at
        from guard_connect_requests
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "request_id": str(row["request_id"]),
        "sync_url": str(row["sync_url"]),
        "allowed_origin": str(row["allowed_origin"]),
        "status": str(row["status"]),
        "created_at": str(row["created_at"]),
        "expires_at": str(row["expires_at"]),
        "completed_at": str(row["completed_at"]) if row["completed_at"] is not None else None,
    }


def create_connect_state(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    sync_url: str,
    allowed_origin: str,
    created_at: str,
    expires_at: str,
    updated_at: str,
) -> dict[str, object]:
    proof = {
        "pairing_completed_at": None,
        "first_synced_at": None,
        "receipts_stored": 0,
        "inventory_items": 0,
        "runtime_session_id": None,
        "runtime_session_synced_at": None,
    }
    connection.execute(
        """
        insert into guard_connect_states (
          request_id,
          sync_url,
          allowed_origin,
          status,
          milestone,
          reason,
          created_at,
          updated_at,
          expires_at,
          completed_at,
          proof_json
        )
        values (?, ?, ?, 'waiting', 'waiting_for_browser', 'waiting_for_browser', ?, ?, ?, null, ?)
        """,
        (
            request_id,
            sync_url,
            allowed_origin,
            created_at,
            updated_at,
            expires_at,
            json.dumps(proof),
        ),
    )
    return load_connect_state(connection, request_id, now=updated_at) or {}


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


def mark_connect_pairing_completed(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    completed_at: str,
) -> dict[str, object]:
    state = load_connect_state(connection, request_id, now=completed_at)
    if state is None:
        raise ValueError("connect_state_not_found")
    proof = _coerce_proof(state.get("proof"))
    proof["pairing_completed_at"] = completed_at
    connection.execute(
        """
        update guard_connect_states
        set status = 'connected',
            milestone = 'first_sync_pending',
            reason = 'waiting_for_first_sync',
            updated_at = ?,
            completed_at = ?,
            proof_json = ?
        where request_id = ?
        """,
        (completed_at, completed_at, json.dumps(proof), request_id),
    )
    return load_connect_state(connection, request_id, now=completed_at) or {}


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
        proof["first_synced_at"] = sync_payload.get("synced_at")
        proof["receipts_stored"] = _coerce_non_negative_int(sync_payload.get("receipts_stored"))
        proof["inventory_items"] = _coerce_non_negative_int(
            sync_payload.get("inventory_tracked", sync_payload.get("inventory"))
        )
        proof["runtime_session_id"] = sync_payload.get("runtime_session_id")
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


get_connect_state = load_connect_state


def verify_connect_request_access(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    pairing_secret: str,
) -> dict[str, object] | None:
    row = connection.execute(
        """
        select request_id, allowed_origin, pairing_secret_hash
        from guard_connect_requests
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    if not secrets.compare_digest(str(row["pairing_secret_hash"]), _hash_secret(pairing_secret)):
        return None
    return {
        "request_id": str(row["request_id"]),
        "allowed_origin": str(row["allowed_origin"]),
    }


def complete_connect_request(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    pairing_secret: str,
    completed_at: str,
) -> dict[str, object]:
    row = connection.execute(
        """
        select request_id, sync_url, allowed_origin, pairing_secret_hash, status, created_at, expires_at, completed_at
        from guard_connect_requests
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        raise ValueError("connect_request_not_found")
    if str(row["status"]) != "pending":
        raise ValueError("connect_request_not_pending")
    expires_at = _parse_timestamp(str(row["expires_at"]))
    if expires_at <= _parse_timestamp(completed_at):
        connection.execute(
            """
            update guard_connect_requests
            set status = 'expired'
            where request_id = ?
            """,
            (request_id,),
        )
        raise ValueError("connect_request_expired")
    if not secrets.compare_digest(str(row["pairing_secret_hash"]), _hash_secret(pairing_secret)):
        raise ValueError("connect_request_invalid_secret")
    connection.execute(
        """
        update guard_connect_requests
        set status = 'completed',
            completed_at = ?
        where request_id = ?
        """,
        (completed_at, request_id),
    )
    return {
        "request_id": str(row["request_id"]),
        "sync_url": str(row["sync_url"]),
        "allowed_origin": str(row["allowed_origin"]),
        "status": "completed",
        "created_at": str(row["created_at"]),
        "expires_at": str(row["expires_at"]),
        "completed_at": completed_at,
    }


def build_connect_request(
    *,
    request_id: str,
    sync_url: str,
    allowed_origin: str,
    now: str,
    lifetime_seconds: int = 300,
) -> tuple[dict[str, object], str]:
    pairing_secret = secrets.token_urlsafe(24)
    expires_at = (_parse_timestamp(now) + timedelta(seconds=max(30, lifetime_seconds))).isoformat()
    payload = {
        "request_id": request_id,
        "sync_url": sync_url,
        "allowed_origin": allowed_origin,
        "status": "pending",
        "created_at": now,
        "expires_at": expires_at,
    }
    return payload, pairing_secret


def hash_pairing_secret(pairing_secret: str) -> str:
    return _hash_secret(pairing_secret)


def build_connect_state_response(
    payload: dict[str, object],
    *,
    poll_after_ms: int | None = None,
) -> dict[str, object]:
    response = dict(payload)
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


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
