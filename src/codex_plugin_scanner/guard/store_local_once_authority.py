"""Transactional persistence for exact local one-shot authority."""

from __future__ import annotations

import sqlite3
from uuid import uuid4

from .local_authority_integrity import sign_local_authority_payload
from .store_base import _canonical_utc_timestamp, _timestamp_has_expired, _workspace_policy_key

LOCAL_ONCE_INTEGRITY_PURPOSE = "guard-local-once-approval"


def persist_local_once_approval(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
    workspace: str | None,
    publisher: str | None,
    action: str,
    created_at: str,
    expires_at: str,
    integrity_key: bytes,
    integrity_key_id: str,
) -> str | None:
    """Insert exact one-shot authority inside the caller's transaction."""

    if not artifact_id or not artifact_hash:
        return None
    canonical_created_at = _canonical_utc_timestamp(created_at)
    canonical_expires_at = _canonical_utc_timestamp(expires_at)
    if _timestamp_has_expired(canonical_expires_at, now=canonical_created_at):
        raise ValueError("local approval expiry must be after its creation time")
    approval_id = uuid4().hex
    workspace_key = _workspace_policy_key(workspace)
    signing_row: dict[str, object] = {
        "approval_id": approval_id,
        "request_id": request_id,
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "workspace": workspace_key,
        "publisher": publisher,
        "action": action,
        "created_at": canonical_created_at,
        "expires_at": canonical_expires_at,
        "claimed_at": None,
    }
    integrity = sign_local_authority_payload(
        signing_row,
        key=integrity_key,
        key_id=integrity_key_id,
        purpose=LOCAL_ONCE_INTEGRITY_PURPOSE,
        signed_at=canonical_created_at,
    )
    connection.execute(
        """
        insert into guard_local_once_approvals (
          approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
          created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
          integrity_key_id, signed_at
        )
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, ?, ?, ?, ?, ?)
        """,
        (
            approval_id,
            request_id,
            harness,
            artifact_id,
            artifact_hash,
            workspace_key,
            publisher,
            action,
            canonical_created_at,
            canonical_expires_at,
            integrity["integrity_version"],
            integrity["payload_hash"],
            integrity["payload_mac"],
            integrity["integrity_key_id"],
            integrity["signed_at"],
        ),
    )
    return approval_id
