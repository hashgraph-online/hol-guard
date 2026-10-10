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


def _recovery_state_keys() -> tuple[str, ...]:
    """Current security rows copied with consent. Replay tombstones are mandatory."""

    from .runtime.command_capability import COMMAND_REPLAY_STATE_KEY

    if COMMAND_REPLAY_STATE_KEY in _STATE_KEYS:
        return _STATE_KEYS
    return (*_STATE_KEYS, COMMAND_REPLAY_STATE_KEY)


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
            state_keys = _recovery_state_keys()
            states = src.execute(
                "select state_key, payload_json, updated_at from sync_state where state_key in ("
                + ", ".join("?" for _ in state_keys)
                + ")",
                state_keys,
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
    state_keys = _recovery_state_keys()
    if connection.execute(
        "select 1 from sync_state where state_key in (" + ", ".join("?" for _ in state_keys) + ") limit 1",
        state_keys,
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


RECOVERY_HEALTH_STATE_KEY = "guard_cloud_review_recovery_health"
PARTIAL_CLOUD_RECOVERY_DETAIL = "Local protection is working. Restore this device's Cloud connection to sync reviews."
INCOMPLETE_CLOUD_RECOVERY_DETAIL = (
    "Cloud Review recovery did not finish. Sign in on this device before reviews can sync."
)


def cloud_review_recovery_health(*, cloud_review: bool, local_cli: bool) -> dict[str, object]:
    """Describe one recovery layer without paths, SQL, or credentials."""

    if cloud_review:
        reason = "cloud_review_restored"
        repair = "none"
        summary = ""
    elif local_cli:
        reason = "cloud_review_salvage_failed"
        repair = "authenticated_current_binding"
        summary = PARTIAL_CLOUD_RECOVERY_DETAIL
    else:
        reason = "recovery_incomplete"
        repair = "authenticated_current_binding"
        summary = INCOMPLETE_CLOUD_RECOVERY_DETAIL
    return {
        "cloudReview": cloud_review,
        "localCli": local_cli,
        "reason": reason,
        "repair": repair,
        "summary": summary,
    }


def persist_cloud_review_recovery_health(
    store: object,
    *,
    cloud_review: bool,
    local_cli: bool,
    now: str,
) -> None:
    """Remember the recovery result on the new store. This does not create consent."""

    setter = getattr(store, "set_sync_payload", None)
    if setter is None:
        return
    setter(
        RECOVERY_HEALTH_STATE_KEY,
        cloud_review_recovery_health(cloud_review=cloud_review, local_cli=local_cli),
        now,
    )


def read_cloud_review_recovery_health(store: object) -> dict[str, object] | None:
    getter = getattr(store, "get_sync_payload", None)
    if getter is None:
        return None
    payload = getter(RECOVERY_HEALTH_STATE_KEY)
    if not isinstance(payload, dict):
        return None
    cloud_review = payload.get("cloudReview")
    local_cli = payload.get("localCli")
    if not isinstance(cloud_review, bool) or not isinstance(local_cli, bool):
        return None
    expected = cloud_review_recovery_health(cloud_review=cloud_review, local_cli=local_cli)
    if payload.get("reason") != expected["reason"] or payload.get("repair") != expected["repair"]:
        return None
    return expected


REPAIR_ATTEMPT_STATE_KEY = "guard_cloud_review_recovery_repair"
_INSTALLATION_CLAIM_FIELDS = ("installation_id", "machine_installation_id")


def read_cloud_review_recovery_repair(store: object) -> dict[str, object]:
    """Return the recorded repair, if any. This does not write consent, authority, or repair state."""

    health = read_cloud_review_recovery_health(store)
    if health is None or health.get("repair") != "authenticated_current_binding":
        return {"status": "not_required", "reason": "no_pending_repair"}
    if health.get("reason") != "cloud_review_salvage_failed":
        return {"status": "recovery_incomplete", "reason": "local_recovery_incomplete"}
    getter = getattr(store, "get_sync_payload", None)
    binding_getter = getattr(store, "get_review_event_oauth_binding", None)
    if getter is None or binding_getter is None:
        return {"status": "authentication_required", "reason": "oauth_binding_missing"}
    payload = getter("oauth_local_credentials")
    binding = binding_getter()
    if not isinstance(payload, dict) or not isinstance(binding, dict):
        return {"status": "authentication_required", "reason": "oauth_binding_missing"}
    installation_id = str(binding.get("machine_installation_id") or "").strip()
    workspace_id = str(binding.get("workspace_id") or "").strip()
    if not installation_id or not workspace_id:
        return {"status": "authentication_required", "reason": "oauth_binding_missing"}
    for field in _INSTALLATION_CLAIM_FIELDS:
        claimed = payload.get(field)
        if isinstance(claimed, str) and claimed.strip() and claimed.strip() != installation_id:
            return {"status": "binding_mismatch", "reason": "installation_disagrees"}
    existing = _matching_completed_repair(getter(REPAIR_ATTEMPT_STATE_KEY), workspace_id, installation_id)
    if existing is not None:
        return existing
    return {"status": "authentication_required", "reason": "current_binding_unconfirmed"}


def complete_authenticated_current_binding_repair(store: object, *, now: str) -> dict[str, object]:
    """Confirm one live sign-in belongs to this device.

    The confirmation does not create Review consent or native authority, copy
    credentials, or delete tombstones, replay counters, or revocation records.
    A confirmation that already matches this device is not written again.
    """

    health = read_cloud_review_recovery_health(store)
    if health is None or health.get("repair") != "authenticated_current_binding":
        return {"status": "not_required", "reason": "no_pending_repair"}
    if health.get("reason") != "cloud_review_salvage_failed":
        return {"status": "recovery_incomplete", "reason": "local_recovery_incomplete"}
    getter = getattr(store, "get_sync_payload", None)
    binding_getter = getattr(store, "get_review_event_oauth_binding", None)
    setter = getattr(store, "set_sync_payload", None)
    if getter is None or binding_getter is None or setter is None:
        return {"status": "authentication_required", "reason": "oauth_binding_missing"}
    payload = getter("oauth_local_credentials")
    binding = binding_getter()
    if not isinstance(payload, dict) or not isinstance(binding, dict):
        return {"status": "authentication_required", "reason": "oauth_binding_missing"}
    installation_id = str(binding.get("machine_installation_id") or "").strip()
    workspace_id = str(binding.get("workspace_id") or "").strip()
    if not installation_id or not workspace_id:
        return {"status": "authentication_required", "reason": "oauth_binding_missing"}
    for field in _INSTALLATION_CLAIM_FIELDS:
        claimed = payload.get(field)
        if isinstance(claimed, str) and claimed.strip() and claimed.strip() != installation_id:
            return {"status": "binding_mismatch", "reason": "installation_disagrees"}
    existing = _matching_completed_repair(getter(REPAIR_ATTEMPT_STATE_KEY), workspace_id, installation_id)
    if existing is not None:
        return existing
    setter(
        REPAIR_ATTEMPT_STATE_KEY,
        {
            "installationId": installation_id,
            "reason": "current_binding_confirmed",
            "status": "completed",
            "workspaceId": workspace_id,
        },
        now,
    )
    return {"status": "completed", "reason": "current_binding_confirmed"}


def note_authenticated_cloud_review_round_trip(store: object, *, now: str) -> None:
    """Replace a salvage warning after Cloud accepts a review batch.

    This does not read stored sign-in metadata, create consent, or change
    tombstones, replay counters, or revocation records.
    """

    health = read_cloud_review_recovery_health(store)
    if health is None or health.get("repair") != "authenticated_current_binding":
        return
    local_cli = health.get("localCli")
    if not isinstance(local_cli, bool):
        return
    persist_cloud_review_recovery_health(store, cloud_review=True, local_cli=local_cli, now=now)


def _matching_completed_repair(
    payload: object,
    workspace_id: str,
    installation_id: str,
) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    if payload.get("status") != "completed" or payload.get("reason") != "current_binding_confirmed":
        return None
    if payload.get("workspaceId") != workspace_id or payload.get("installationId") != installation_id:
        return None
    return {"status": "completed", "reason": "current_binding_confirmed"}
