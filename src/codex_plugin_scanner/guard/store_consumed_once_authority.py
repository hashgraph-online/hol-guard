"""Verify retained one-shot consumption without trusting continuation metadata."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager

from .store_base import _parse_utc_timestamp, _workspace_policy_key
from .store_event_receipts import _local_once_approval_payload, _verify_local_once_approval


def read_consumed_once_authority(
    connect: Callable[[], AbstractContextManager[sqlite3.Connection]],
    secret_material: Callable[..., tuple[bytes | None, str | None]],
    *,
    request_id: str,
    harness: str,
    artifact_id: str | None,
    artifact_hash: str | None,
    workspace: str | None,
    publisher: str | None,
    now: str,
) -> dict[str, object] | None:
    """Return one exact, unexpired, MAC-verified consumed record, read-only.

    This proves a prior grant was consumed. The caller still owns fresh policy,
    original waiter identity, deadline, and terminal-operation checks. Null
    workspace/publisher values are exact identities, never wildcard authority.
    """
    if not request_id or not harness or not artifact_id or not artifact_hash:
        return None
    try:
        observed_at = _parse_utc_timestamp(now)
    except (TypeError, ValueError):
        return None
    integrity_key, integrity_key_id = secret_material(create=False)
    if integrity_key is None or integrity_key_id is None:
        return None
    with connect() as connection:
        row = connection.execute(
            """
            select approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
                   created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
                   integrity_key_id, signed_at
            from guard_local_once_approvals
            where request_id = ? and harness = ? and artifact_id = ? and artifact_hash = ?
              and workspace is ? and publisher is ? and action = 'allow' and claimed_at is not null
            order by created_at desc, approval_id desc
            limit 1
            """,
            (request_id, harness, artifact_id, artifact_hash, _workspace_policy_key(workspace), publisher),
        ).fetchone()
    if row is None or _verify_local_once_approval(row, key=integrity_key, key_id=integrity_key_id).status != "valid":
        return None
    # Python comparisons retain microsecond boundaries; SQLite julianday rounds
    # more coarsely and could otherwise admit a claim just after the caller's now.
    try:
        if (
            _parse_utc_timestamp(row["claimed_at"]) > observed_at
            or _parse_utc_timestamp(row["expires_at"]) <= observed_at
        ):
            return None
    except (TypeError, ValueError):
        return None
    return _local_once_approval_payload(row)
