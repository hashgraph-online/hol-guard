"""OAuth identity binding for local Review outbox events."""

from __future__ import annotations

import json
import sqlite3
from hashlib import sha256
from typing import cast

# pyright: reportAny=false, reportUnusedCallResult=false


def review_event_oauth_subject_hash(grant_id: str | None) -> str | None:
    """Return a non-reversible account binding for an OAuth grant subject."""

    normalized = grant_id.strip() if isinstance(grant_id, str) else ""
    return sha256(normalized.encode("utf-8")).hexdigest() if normalized else None


def _oauth_binding_state_key(source: str) -> str:
    return "oauth_local_credentials" if source == "default" else f"oauth_local_credentials:{source}"


def load_review_oauth_binding(connection: sqlite3.Connection, source: str) -> dict[str, str] | None:
    row = connection.execute(
        "select payload_json from sync_state where state_key = ?",
        (_oauth_binding_state_key(source),),
    ).fetchone()
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
    device = connection.execute(
        "select installation_id from guard_devices where device_key = 'local-device'"
    ).fetchone()
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
