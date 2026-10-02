"""Request-bound persistence access for purpose-separated exact Cloud grants."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import Protocol, cast

from .store_approvals import get_approval_request as load_approval_request
from .store_base import _canonical_utc_timestamp, _workspace_policy_key
from .store_event_receipts import (
    StoreEventReceiptsMixin,
    _local_once_approval_payload,
    _verify_local_once_approval,
)
from .store_local_once_authority import EXACT_CLOUD_AUTHORITY_KIND


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...


class StoreExactCloudLocalOnceMixin:
    def peek_exact_cloud_local_once_approval(
        self: _ConnectionOwner,
        *,
        request_id: str,
        now: str,
    ) -> dict[str, object] | None:
        key, key_id = self._policy_integrity_secret_material(create=False)
        if key is None or key_id is None:
            return None
        with self._connect() as connection:
            request = load_approval_request(connection, request_id)
            if not isinstance(request, Mapping):
                return None
            bindings = _request_bindings(request)
            if bindings is None:
                return None
            row = _exact_row_locked(connection, bindings=bindings, now=now)
            return _verified_decision(
                row,
                key=key,
                key_id=key_id,
                authority_revision=_authority_revision(connection),
            )


def claim_exact_cloud_local_once_approval_locked(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    expected_decision: Mapping[str, object],
    now: str,
    integrity_key: bytes,
    integrity_key_id: str,
) -> dict[str, object] | None:
    request = load_approval_request(connection, request_id)
    if not isinstance(request, Mapping):
        return None
    bindings = _request_bindings(request)
    if bindings is None:
        return None
    row = _exact_row_locked(connection, bindings=bindings, now=now)
    decision = _verified_decision(
        row,
        key=integrity_key,
        key_id=integrity_key_id,
        authority_revision=_authority_revision(connection),
    )
    if decision is None:
        return None
    return StoreEventReceiptsMixin._claim_local_once_approval_by_id_locked(
        connection,
        approval_id=str(decision["approval_id"]),
        now=now,
        expected_decision=expected_decision,
        integrity_key=integrity_key,
        integrity_key_id=integrity_key_id,
        authority_kind=EXACT_CLOUD_AUTHORITY_KIND,
    )


def _request_bindings(request: Mapping[str, object]) -> tuple[object, ...] | None:
    if request.get("status") != "resolved" or request.get("resolution_action") != "allow":
        return None
    if request.get("resolution_scope") != "artifact":
        return None
    if request.get("policy_action") not in {"review", "require-reapproval"}:
        return None
    request_id = _text(request.get("request_id"))
    harness = _text(request.get("harness"))
    artifact_id = _text(request.get("artifact_id"))
    artifact_hash = _text(request.get("artifact_hash"))
    if request_id is None or harness is None or artifact_id is None or artifact_hash is None:
        return None
    workspace = _text(request.get("workspace"))
    publisher = _text(request.get("publisher"))
    return (
        request_id,
        harness,
        artifact_id,
        artifact_hash,
        _workspace_policy_key(workspace),
        publisher,
    )


def _exact_row_locked(
    connection: sqlite3.Connection,
    *,
    bindings: tuple[object, ...],
    now: str,
) -> sqlite3.Row | None:
    request_id, harness, artifact_id, artifact_hash, workspace, publisher = bindings
    clauses = [
        "authority_kind = ?",
        "request_id = ?",
        "harness = ?",
        "artifact_id = ?",
        "artifact_hash = ?",
        "claimed_at is null",
        "julianday(expires_at) > julianday(?)",
    ]
    params: list[object] = [
        EXACT_CLOUD_AUTHORITY_KIND,
        request_id,
        harness,
        artifact_id,
        artifact_hash,
        _canonical_utc_timestamp(now),
    ]
    if workspace is None:
        clauses.append("workspace is null")
    else:
        clauses.append("workspace = ?")
        params.append(workspace)
    if publisher is None:
        clauses.append("publisher is null")
    else:
        clauses.append("publisher = ?")
        params.append(publisher)
    return connection.execute(
        f"""
        select approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
               created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
               integrity_key_id, signed_at, authority_kind
        from guard_local_once_approvals
        where {" and ".join(clauses)}
        order by created_at desc, approval_id desc
        limit 1
        """,
        tuple(params),
    ).fetchone()


def _verified_decision(
    row: sqlite3.Row | None,
    *,
    key: bytes,
    key_id: str,
    authority_revision: int,
) -> dict[str, object] | None:
    if row is None:
        return None
    row_mapping = cast(Mapping[str, object], cast(object, row))
    if _verify_local_once_approval(row_mapping, key=key, key_id=key_id).status != "valid":
        return None
    decision = _local_once_approval_payload(row_mapping)
    decision["_approval_authority_revision"] = authority_revision
    return decision


def _authority_revision(connection: sqlite3.Connection) -> int:
    row = connection.execute("select revision from guard_approval_authority_revision where singleton = 1").fetchone()
    return int(row["revision"]) if row is not None else -1


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


__all__ = ["StoreExactCloudLocalOnceMixin", "claim_exact_cloud_local_once_approval_locked"]
