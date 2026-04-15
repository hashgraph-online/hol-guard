"""One-time browser pairing persistence helpers for Guard connect."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone


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


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
