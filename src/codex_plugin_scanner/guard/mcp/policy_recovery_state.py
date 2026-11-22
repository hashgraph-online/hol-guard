"""Durable denial metadata for policy requests imported through recovery.

This never authorizes a source or provider action. Native source/approval owners
remain authoritative; the existing SQL transaction records only non-replay state.
"""

import json

from ..store_sync_payload_snapshot import SyncPayloadRowUnreadableError
from .policy_errors import PolicyToolError


def request_recovery_recorded(store, request_id):
    """Whether recovery already recorded ``request_id``, read by the native store.

    A row that is not JSON still counts as recorded, so a damaged marker keeps
    refusing a second recovery. The check inside the apply transaction stays on
    that transaction's connection and remains the authoritative one.
    """
    key = _key(request_id)
    try:
        rows = store.sync_payload_snapshot(key)
    except SyncPayloadRowUnreadableError:
        return True
    return rows[key] is not None


def request_recovery_recorded_on_connection(connection, request_id):
    return (
        connection.execute("select 1 from sync_state where state_key = ?", (_key(request_id),)).fetchone() is not None
    )


def stage_request_recovery(connection, request_id, digest, now):
    row = connection.execute(
        "select policy_document_digest, mode, status from mcp_policy_requests where request_id = ?", (request_id,)
    ).fetchone()
    if row is None or row[0] != digest or row[1] != "replace" or row[2] == "declined":
        raise PolicyToolError("candidate_digest_mismatch", "The stored request changed. Refresh before recovery.")
    connection.execute(
        "insert into sync_state (state_key,payload_json,updated_at) values (?,?,?) "
        "on conflict(state_key) do update set payload_json=excluded.payload_json,updated_at=excluded.updated_at",
        (_key(request_id), json.dumps({"source_digest": digest, "request_recovered": True}), now),
    )


def _key(request_id):
    return "business_policy_request_recovered_v1/" + request_id
