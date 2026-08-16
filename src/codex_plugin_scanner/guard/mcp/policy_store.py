"""Pending MCP policy creation request persistence.

Stores private, digest-bound policy creation requests in Guard-owned SQLite.
Raw idempotency keys and approval credentials are never persisted.  Status
transitions use ``BEGIN IMMEDIATE`` compare-and-set.  Terminal payloads are
purged after 24 hours; terminal metadata after seven days.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Literal, Protocol

from .policy_errors import PolicyToolError
from .policy_schemas import PolicyImportMode, generate_request_id, hash_idempotency_key

PolicyRequestStatus = Literal["pending", "applied", "declined", "expired", "failed"]
_VALID_REQUEST_STATUSES = frozenset({"pending", "applied", "declined", "expired", "failed"})


class _PolicyRequestStoreConnection(Protocol):
    """Minimal connection-bound protocol for MCP policy request persistence.

    Structural only — avoids a type-level import cycle back to GuardStore,
    whose ``store_connection_schema`` mixin imports ``ensure_mcp_policy_request_schema``
    from this module at runtime.
    """

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


class _PolicyImportResult(Protocol):
    """Structural protocol for the apply_fn return value."""

    @property
    def inserted(self) -> int: ...

    @property
    def replaced(self) -> int: ...


_PENDING_TTL_SECONDS = 600  # 10 minutes
_TERMINAL_PAYLOAD_TTL_SECONDS = 86400  # 24 hours
_TERMINAL_METADATA_TTL_SECONDS = 604800  # 7 days

_MCP_POLICY_REQUEST_SCHEMA = """
create table if not exists mcp_policy_requests (
    request_id text primary key,
    idempotency_key_hash text not null unique,
    status text not null default 'pending',
    policy_document_id text not null,
    policy_document_digest text not null,
    expected_current_digest text,
    expected_policy_generation integer,
    mode text not null,
    canonical_policy_yaml text not null,
    plan_json text not null,
    created_at text not null,
    expires_at text not null,
    resolved_at text,
    result_json text,
    failure_code text
)
"""

_MCP_POLICY_REQUEST_INDEXES = (
    "create index if not exists idx_mcp_policy_requests_status on mcp_policy_requests (status)",
    "create index if not exists idx_mcp_policy_requests_expires on mcp_policy_requests (expires_at)",
    "create index if not exists idx_mcp_policy_requests_idempotency on mcp_policy_requests (idempotency_key_hash)",
)


def ensure_mcp_policy_request_schema(connection: sqlite3.Connection) -> None:
    connection.execute(_MCP_POLICY_REQUEST_SCHEMA)
    for statement in _MCP_POLICY_REQUEST_INDEXES:
        connection.execute(statement)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True, slots=True)
class PendingPolicyRequest:
    request_id: str
    idempotency_key_hash: str
    status: PolicyRequestStatus
    policy_document_id: str
    policy_document_digest: str
    expected_current_digest: str | None
    expected_policy_generation: int | None
    mode: PolicyImportMode
    canonical_policy_yaml: str
    plan_json: str
    created_at: str
    expires_at: str
    resolved_at: str | None
    result_json: str | None
    failure_code: str | None

    @property
    def is_terminal(self) -> bool:
        return self.status in {"applied", "declined", "expired", "failed"}

    @property
    def is_expired(self) -> bool:
        if self.status != "pending":
            return False
        return _now() > _parse_iso(self.expires_at)


def _coerce_status(value: object) -> PolicyRequestStatus:
    if isinstance(value, str) and value in _VALID_REQUEST_STATUSES:
        if value == "pending":
            return "pending"
        if value == "applied":
            return "applied"
        if value == "declined":
            return "declined"
        if value == "expired":
            return "expired"
        return "failed"
    raise PolicyToolError("policy_write_failed", f"Unexpected request status: {value!r}")


def _coerce_mode(value: object) -> PolicyImportMode:
    if isinstance(value, str):
        if value == "merge":
            return "merge"
        if value == "replace":
            return "replace"
    raise PolicyToolError("policy_write_failed", f"Unexpected request mode: {value!r}")


def _row_to_request(row: sqlite3.Row | Mapping[str, object]) -> PendingPolicyRequest:
    return PendingPolicyRequest(
        request_id=str(row["request_id"]),
        idempotency_key_hash=str(row["idempotency_key_hash"]),
        status=_coerce_status(row["status"]),
        policy_document_id=str(row["policy_document_id"]),
        policy_document_digest=str(row["policy_document_digest"]),
        expected_current_digest=str(row["expected_current_digest"]) if row["expected_current_digest"] else None,
        expected_policy_generation=(
            int(str(row["expected_policy_generation"])) if row["expected_policy_generation"] is not None else None
        ),
        mode=_coerce_mode(row["mode"]),
        canonical_policy_yaml=str(row["canonical_policy_yaml"]),
        plan_json=str(row["plan_json"]),
        created_at=str(row["created_at"]),
        expires_at=str(row["expires_at"]),
        resolved_at=str(row["resolved_at"]) if row["resolved_at"] else None,
        result_json=str(row["result_json"]) if row["result_json"] else None,
        failure_code=str(row["failure_code"]) if row["failure_code"] else None,
    )


@dataclass(frozen=True, slots=True)
class StageRequestInput:
    policy_document_id: str
    policy_document_digest: str
    expected_current_digest: str | None
    expected_policy_generation: int | None
    mode: PolicyImportMode
    canonical_policy_yaml: str
    plan_json: str
    idempotency_key: str


@dataclass(frozen=True, slots=True)
class StageRequestResult:
    request_id: str
    status: PolicyRequestStatus
    created_at: str
    expires_at: str
    is_replay: bool


@dataclass(frozen=True, slots=True)
class ApplyRequestResult:
    request_id: str
    status: PolicyRequestStatus
    resolved_at: str
    inserted: int
    replaced: int


class MCPolicyRequestRepository:
    """Repository for pending MCP policy creation requests.

    Wraps GuardStore's SQLite connection.  Never persists raw idempotency keys
    or approval credentials.
    """

    def __init__(self, store: _PolicyRequestStoreConnection) -> None:
        self._store = store

    def stage_request(self, request_input: StageRequestInput) -> StageRequestResult:
        key_hash = hash_idempotency_key(request_input.idempotency_key)
        now = _now()
        now_iso = now.isoformat().replace("+00:00", "Z")
        expires_dt = now + timedelta(seconds=_PENDING_TTL_SECONDS)
        expires_iso = expires_dt.isoformat().replace("+00:00", "Z")
        request_id = generate_request_id()

        with self._store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "select request_id, status, policy_document_digest, mode, expected_current_digest, "
                    "canonical_policy_yaml, created_at, expires_at from mcp_policy_requests "
                    "where idempotency_key_hash = ?",
                    (key_hash,),
                ).fetchone()
                if existing is not None:
                    existing_digest = str(existing["policy_document_digest"])
                    existing_mode = str(existing["mode"])
                    existing_baseline = (
                        str(existing["expected_current_digest"]) if existing["expected_current_digest"] else None
                    )
                    existing_yaml = str(existing["canonical_policy_yaml"])
                    if (
                        existing_digest == request_input.policy_document_digest
                        and existing_mode == request_input.mode
                        and existing_baseline == request_input.expected_current_digest
                        and existing_yaml == request_input.canonical_policy_yaml
                    ):
                        return StageRequestResult(
                            request_id=str(existing["request_id"]),
                            status=_coerce_status(existing["status"]),
                            created_at=str(existing["created_at"]),
                            expires_at=str(existing["expires_at"]),
                            is_replay=True,
                        )
                    raise PolicyToolError(
                        "idempotency_conflict",
                        "idempotencyKey was already used for a different request.",
                    )

                connection.execute(
                    """
                    insert into mcp_policy_requests (
                        request_id, idempotency_key_hash, status,
                        policy_document_id, policy_document_digest,
                        expected_current_digest, expected_policy_generation,
                        mode, canonical_policy_yaml, plan_json,
                        created_at, expires_at, resolved_at, result_json, failure_code
                    ) values (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, null, null, null)
                    """,
                    (
                        request_id,
                        key_hash,
                        request_input.policy_document_id,
                        request_input.policy_document_digest,
                        request_input.expected_current_digest,
                        request_input.expected_policy_generation,
                        request_input.mode,
                        request_input.canonical_policy_yaml,
                        request_input.plan_json,
                        now_iso,
                        expires_iso,
                    ),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

        return StageRequestResult(
            request_id=request_id,
            status="pending",
            created_at=now_iso,
            expires_at=expires_iso,
            is_replay=False,
        )

    def get_request(self, request_id: str) -> PendingPolicyRequest | None:
        with self._store._connect() as connection:
            row = connection.execute(
                "select * from mcp_policy_requests where request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        request = _row_to_request(row)
        if request.is_expired:
            self._expire_request(request_id)
            return replace(request, status="expired")
        return request

    def _expire_request(self, request_id: str) -> None:
        with self._store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "update mcp_policy_requests set status = 'expired', resolved_at = ? "
                    "where request_id = ? and status = 'pending'",
                    (_now_iso(), request_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def list_pending_requests(self) -> list[PendingPolicyRequest]:
        with self._store._connect() as connection:
            rows = connection.execute(
                "select * from mcp_policy_requests where status = 'pending' order by created_at desc"
            ).fetchall()
        return [_row_to_request(row) for row in rows]

    def apply_request(
        self,
        request_id: str,
        *,
        apply_fn: Callable[[PendingPolicyRequest, sqlite3.Connection], _PolicyImportResult],
    ) -> ApplyRequestResult:
        """Atomically transition pending -> applied and run the import.

        ``apply_fn`` receives the stored ``PendingPolicyRequest`` and the
        active SQLite ``connection`` (already in ``BEGIN IMMEDIATE``).  It
        must return a ``PolicyDocumentImportResult``-like object with
        ``inserted`` and ``replaced`` integer fields.  The entire operation
        runs inside one shared transaction — policy row writes and the
        status transition commit or roll back together.
        """
        with self._store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                # Authoritative in-transaction fetch + validation. The
                # pre-transaction checks in apply_pending_policy_request
                # are a TOCTOU fast-path; these run under BEGIN IMMEDIATE.
                row = connection.execute(
                    "select * from mcp_policy_requests where request_id = ?",
                    (request_id,),
                ).fetchone()
                if row is None:
                    raise PolicyToolError("policy_request_not_found", "Policy request not found.")
                request = _row_to_request(row)
                if request.status == "applied":
                    raise PolicyToolError("approval_already_resolved", "Request is already applied.")
                if request.status in {"declined", "expired", "failed"}:
                    raise PolicyToolError("approval_already_resolved", f"Request is {request.status}.")
                if request.status != "pending":
                    raise PolicyToolError("policy_write_conflict", f"Unexpected request status: {request.status}.")

                if request.is_expired:
                    connection.execute(
                        "update mcp_policy_requests set status = 'expired', resolved_at = ? "
                        "where request_id = ? and status = 'pending'",
                        (_now_iso(), request_id),
                    )
                    connection.commit()
                    raise PolicyToolError("approval_expired", "Policy request has expired.")
                result = apply_fn(request, connection)
                resolved_at = _now_iso()
                result_json = json.dumps(
                    {"inserted": int(result.inserted), "replaced": int(result.replaced)},
                    separators=(",", ":"),
                    sort_keys=True,
                )
                cursor = connection.execute(
                    "update mcp_policy_requests set status = 'applied', resolved_at = ?, result_json = ? "
                    "where request_id = ? and status = 'pending'",
                    (resolved_at, result_json, request_id),
                )
                if cursor.rowcount == 0:
                    raise PolicyToolError("policy_write_conflict", "Request was modified concurrently.")

                connection.commit()
                return ApplyRequestResult(
                    request_id=request_id,
                    status="applied",
                    resolved_at=resolved_at,
                    inserted=int(result.inserted),
                    replaced=int(result.replaced),
                )
            except PolicyToolError:
                if connection.in_transaction:
                    connection.rollback()
                raise
            except Exception:
                # Rollback the shared transaction FIRST so partial policy
                # rows are discarded.  Then use a SEPARATE connection to
                # mark the request as failed — never commit partial rows.
                if connection.in_transaction:
                    connection.rollback()
                try:
                    with self._store._connect() as failure_conn:
                        failure_conn.execute("BEGIN IMMEDIATE")
                        failure_conn.execute(
                            "update mcp_policy_requests set status = 'failed', "
                            "resolved_at = ?, failure_code = 'policy_write_failed' "
                            "where request_id = ? and status = 'pending'",
                            (_now_iso(), request_id),
                        )
                        failure_conn.commit()
                except Exception:
                    pass
                raise

    def decline_request(self, request_id: str) -> PendingPolicyRequest:
        with self._store._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    "update mcp_policy_requests set status = 'declined', resolved_at = ? "
                    "where request_id = ? and status = 'pending'",
                    (_now_iso(), request_id),
                )
                if cursor.rowcount == 0:
                    row = connection.execute(
                        "select status from mcp_policy_requests where request_id = ?",
                        (request_id,),
                    ).fetchone()
                    if row is None:
                        raise PolicyToolError("policy_request_not_found", "Policy request not found.")
                    raise PolicyToolError(
                        "approval_already_resolved",
                        f"Request is {row['status']}.",
                    )

                connection.commit()
            except Exception:
                connection.rollback()
                raise
        result = self.get_request(request_id)
        if result is None:
            raise PolicyToolError("policy_request_not_found", "Policy request not found.")
        return result

    def purge_expired_and_old(self) -> int:
        """Purge terminal payloads after 24h and terminal metadata after 7d."""
        now = _now()
        payload_cutoff = (now - timedelta(seconds=_TERMINAL_PAYLOAD_TTL_SECONDS)).isoformat().replace("+00:00", "Z")
        metadata_cutoff = (now - timedelta(seconds=_TERMINAL_METADATA_TTL_SECONDS)).isoformat().replace("+00:00", "Z")
        purged = 0
        with self._store._connect() as connection:
            cursor = connection.execute(
                "delete from mcp_policy_requests where status in ('applied','declined','expired','failed') "
                "and resolved_at < ?",
                (metadata_cutoff,),
            )
            purged += cursor.rowcount if cursor.rowcount is not None else 0
            cursor = connection.execute(
                "update mcp_policy_requests set canonical_policy_yaml = '', plan_json = '' "
                "where status in ('applied','declined','expired','failed') "
                "and resolved_at < ? and canonical_policy_yaml != ''",
                (payload_cutoff,),
            )
            connection.commit()
        return purged


__all__ = [
    "ApplyRequestResult",
    "MCPolicyRequestRepository",
    "PendingPolicyRequest",
    "StageRequestInput",
    "StageRequestResult",
    "ensure_mcp_policy_request_schema",
]
