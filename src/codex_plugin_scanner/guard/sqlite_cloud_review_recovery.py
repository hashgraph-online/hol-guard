"""Recover coherent Cloud Review state from the just-quarantined database."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import cast

from .review_event_wake import review_event_wake_signal
from .sqlite_deadline_connection import connect_sqlite_with_deadline
from .store_native_workspace_review import (
    NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX,
    _receipt_payload,
)

# pyright: reportAny=false

# Consent must never be recovered without its revocation and replay records.
# These are current-state reads, not restoration from an older backup.
_STATE_KEYS = (
    "oauth_local_credentials",
    "guard_exact_cloud_review_capability",
    "guard_exact_cloud_review_revocation",
    "guard_review_verification_keyring",
    "guard_cloud_review_settings_recovery",
)
_STATE_PLACEHOLDERS = ", ".join("?" for _ in _STATE_KEYS)
_TABLES = (
    "guard_devices",
    "guard_connect_states",
    "guard_exact_cloud_review_receipts",
    "approval_requests",
    "guard_review_outbox_events",
    "guard_review_outbox_cursors",
    "guard_review_outbox_request_sequences",
)
# Only additive presentation columns may be absent in an older request table.
# Identity, decisions, revocations and replay records must remain complete.
_OPTIONAL_REQUEST_COLUMNS = frozenset(
    {
        "artifact_label",
        "source_label",
        "trigger_summary",
        "why_now",
        "launch_summary",
        "risk_headline",
        "desktop_notified_at",
        "guard_version",
        "first_seen_guard_version",
        "last_seen_guard_version",
        "dedupe_count",
        "last_seen_at",
    }
)
_NATIVE_RECEIPT_MAX_REQUEST_ID_LENGTH = 128


def salvage_cloud_review_state(*, source: Path, destination: Path) -> bool:
    """Restore all required state or nothing, while the store recovery gate is held.

    Normal OAuth, DPoP, capability-signature, revocation and request-binding
    checks still apply after recovery. No consent is created or renewed here.
    """

    if source.is_symlink() or destination.is_symlink() or not destination.is_file():
        return False
    source_uri = f"{source.resolve().as_uri()}?mode=ro"
    try:
        with (
            closing(connect_sqlite_with_deadline(source_uri, uri=True, timeout_seconds=1.0)) as src,
            closing(connect_sqlite_with_deadline(destination, timeout_seconds=1.0)) as dst,
            dst,
        ):
            _ = src.execute("begin")
            _ = dst.execute("begin immediate")
            if not _destination_is_empty(dst):
                return False
            states = src.execute(
                "select state_key, payload_json, updated_at from sync_state "
                + f"where state_key in ({_STATE_PLACEHOLDERS})",
                _STATE_KEYS,
            ).fetchall()
            if not any(row[0] == "oauth_local_credentials" for row in states):
                return False
            states.extend(_validated_native_receipt_states(src))
            device = src.execute(
                "select installation_id from guard_devices where device_key = 'local-device'"
            ).fetchone()
            if device is None or not isinstance(device[0], str) or not device[0]:
                return False
            _ = dst.executemany("insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)", states)
            for table in _TABLES:
                _copy_complete_table(src, dst, table)
        review_event_wake_signal(destination).notify()
        return True
    except sqlite3.Error:
        return False


def _validated_native_receipt_states(src: sqlite3.Connection) -> list[tuple[object, object, object]]:
    """Select only native receipts bound to their resolved local request.

    Recovery must not manufacture a receipt for a missing or corrupt row. Such
    rows are omitted so the native redelivery path remains fail-closed.
    """

    rows = src.execute(
        "select state_key, payload_json, updated_at from sync_state where state_key like ?",
        (NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX + "%",),
    ).fetchall()
    recovered: list[tuple[object, object, object]] = []
    for state_key, payload_json, updated_at in rows:
        if not isinstance(state_key, str) or not state_key.startswith(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX):
            continue
        request_id = state_key[len(NATIVE_WORKSPACE_REVIEW_RECEIPT_STATE_PREFIX) :]
        if not _native_receipt_request_id_is_safe(request_id):
            continue
        request = src.execute(
            "select status, resolution_action, resolution_scope from approval_requests where request_id = ?",
            (request_id,),
        ).fetchone()
        if request is None or request[0] != "resolved" or request[1] not in {"allow", "block"}:
            continue
        resolution_action = request[1]
        if not isinstance(resolution_action, str) or request[2] != "artifact":
            continue
        try:
            receipt = json.loads(payload_json)
            if not isinstance(receipt, dict):
                continue
            canonical_receipt = _receipt_payload(cast(dict[str, object], receipt), request_id, resolution_action)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        recovered.append((state_key, canonical_receipt, updated_at))
    return recovered


def _native_receipt_request_id_is_safe(request_id: str) -> bool:
    return (
        bool(request_id)
        and len(request_id) <= _NATIVE_RECEIPT_MAX_REQUEST_ID_LENGTH
        and all(char.isascii() and (char.isalnum() or char in "-_.:") for char in request_id)
    )


def _destination_is_empty(connection: sqlite3.Connection) -> bool:
    if connection.execute(
        f"select 1 from sync_state where state_key in ({_STATE_PLACEHOLDERS}) limit 1", _STATE_KEYS
    ).fetchone():
        return False
    for table in _TABLES:
        if table == "guard_devices":
            continue  # Schema initialization creates a replacement installation ID.
        if connection.execute(f'select 1 from "{table}" limit 1').fetchone():
            return False
    return True


def _copy_complete_table(src: sqlite3.Connection, dst: sqlite3.Connection, table: str) -> None:
    if table not in _TABLES:
        raise ValueError("Unsupported Cloud Review recovery table")
    destination_columns = list(dst.execute(f'pragma table_info("{table}")'))
    columns = [str(row[1]) for row in destination_columns]
    source_columns = {str(row[1]) for row in src.execute(f'pragma table_info("{table}")')}
    missing = set(columns) - source_columns
    compatible = {
        str(row[1])
        for row in destination_columns
        if table == "approval_requests"
        and row[1] in _OPTIONAL_REQUEST_COLUMNS
        and (not row[3] or row[4] is not None)
        and not row[5]
    }
    if not columns or not missing.issubset(compatible):
        raise sqlite3.DatabaseError("Incomplete Cloud Review recovery schema")
    columns = [column for column in columns if column in source_columns]
    quoted = ", ".join('"' + column.replace('"', '""') + '"' for column in columns)
    placeholders = ", ".join("?" for _ in columns)
    cursor = src.execute(f'select {quoted} from "{table}"')
    # Restoring approval_requests fires outbox triggers. The subsequent complete
    # outbox copies replace those generated rows with the original identities.
    _ = dst.execute(f'delete from "{table}"')
    _ = dst.executemany(f'insert into "{table}" ({quoted}) values ({placeholders})', cursor)
