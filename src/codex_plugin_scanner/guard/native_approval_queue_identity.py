"""Resident bridge for the ``approval_queue_identity`` op.

Rust owns the queue identity of an approval request: the normalized identity
key, the action identity and the queue group id that decide which pending
approvals are duplicates. This module only narrows requests to the fields the
identity reads, binds the reply by ``request_id`` plus ``request_sha256`` and
decodes it. A missing, malformed or mismatched reply raises; nothing is ever
recomputed in Python.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NamedTuple
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

APPROVAL_QUEUE_IDENTITY_FEATURE = "approval-queue-identity-v1"
_REQUEST_SCHEMA = "guard-approval-queue-identity-request.v1"
_RESULT_SCHEMA = "guard-approval-queue-identity-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
UNAVAILABLE = "native_approval_queue_identity_unavailable"


class ApprovalQueueIdentityUnavailableError(ValueError):
    """The resident could not identify the request; nothing was recomputed."""

    def __init__(self) -> None:
        super().__init__(UNAVAILABLE)


class QueueIdentity(NamedTuple):
    identity_key: str
    action_identity: str
    queue_group_id: str


def connection_guard_home(connection: sqlite3.Connection) -> Path | None:
    """The Guard home of the store a connection is open on, when it is file-backed."""

    try:
        row = connection.execute("pragma database_list").fetchone()
    except sqlite3.Error:
        return None
    database = row[2] if row is not None and len(row) > 2 else None
    return Path(str(database)).parent if isinstance(database, str) and database else None


def _json_value(value: object) -> object:
    """Narrow a stored value to JSON: string keys only, unknown objects as text."""

    if isinstance(value, Mapping):
        return {key: _json_value(item) for key, item in value.items() if isinstance(key, str)}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def queue_identity_item(
    *,
    launch_target: str | None,
    harness: str,
    workspace: str | None,
    artifact_id: str,
    envelope: Mapping[str, object] | None,
    browser_intent: Mapping[str, object] | None,
    action_identity: str | None = None,
    queue_group_id: str | None = None,
) -> dict[str, object]:
    """Narrow one approval request to the wire form."""

    return {
        "launch_target": launch_target,
        "harness": harness,
        "workspace": workspace,
        "artifact_id": artifact_id,
        "envelope": _json_value(envelope) if envelope is not None else None,
        "browser_intent": _json_value(browser_intent) if browser_intent is not None else None,
        "action_identity": action_identity,
        "queue_group_id": queue_group_id,
    }


def _verifier_key_present(guard_home: Path) -> bool:
    from .native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME, NATIVE_RUNTIME_STATE_DIRECTORY

    return (guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME).is_file()


def native_approval_queue_identities(
    items: Sequence[Mapping[str, object]],
    *,
    guard_home: Path,
    provision: bool = True,
) -> list[QueueIdentity]:
    """Identify approval requests in the resident; raise when it cannot.

    ``provision=False`` never creates the home's verifier key, for callers that
    already run inside a store's own initialization.
    """

    # The resident refuses to serve a home without its verifier key. The check
    # is memoized per home, so it costs one stat after the first call.
    if not (ensure_resident_prerequisite(Path(guard_home)) if provision else _verifier_key_present(Path(guard_home))):
        raise ApprovalQueueIdentityUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"approval-queue-identity-{uuid4().hex}",
        "items": [dict(item) for item in items],
    }
    try:
        response = _resident_request(
            operation="approval_queue_identity",
            request=wire,
            guard_home=guard_home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=APPROVAL_QUEUE_IDENTITY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError):
        raise ApprovalQueueIdentityUnavailableError from None
    payload = _payload(response, wire, Path(guard_home))
    reply = payload.get("items") if payload is not None else None
    if not isinstance(reply, list) or len(reply) != len(items):
        raise ApprovalQueueIdentityUnavailableError
    identities: list[QueueIdentity] = []
    for entry in reply:
        if not isinstance(entry, dict):
            raise ApprovalQueueIdentityUnavailableError
        identity_key = entry.get("identity_key")
        action_identity = entry.get("action_identity")
        queue_group_id = entry.get("queue_group_id")
        # identity_key may be empty; the action and queue ids must be present.
        if not isinstance(identity_key, str):
            raise ApprovalQueueIdentityUnavailableError
        if not isinstance(action_identity, str) or not action_identity:
            raise ApprovalQueueIdentityUnavailableError
        if not isinstance(queue_group_id, str) or not queue_group_id:
            raise ApprovalQueueIdentityUnavailableError
        identities.append(QueueIdentity(identity_key, action_identity, queue_group_id))
    return identities
