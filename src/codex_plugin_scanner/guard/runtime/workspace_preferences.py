"""Authenticated optional-upload preferences, separate from signed policy authority."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from ..config import load_guard_config
from ..synced_policy import validated_synced_policy_bundle

if TYPE_CHECKING:
    from ..store import GuardStore

CONTRACT = "guard.workspace-preferences.v1"
_MAX_REVISION = (1 << 53) - 1
_LEVELS = {"none": 0, "partial": 1, "full": 2}
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\Z")


@dataclass(frozen=True)
class WorkspacePreferences:
    workspace_id: str
    revision: int
    updated_at: str
    sync_enabled: bool
    telemetry_enabled: bool
    redaction_level: str

    def to_wire(self) -> dict[str, object]:
        return {
            "contractVersion": CONTRACT,
            "workspaceId": self.workspace_id,
            "revision": self.revision,
            "updatedAt": self.updated_at,
            "preferences": {
                "syncEnabled": self.sync_enabled,
                "telemetryEnabled": self.telemetry_enabled,
                "receiptRedactionLevel": self.redaction_level,
            },
        }

    def semantic_identity(self) -> tuple[str, int, bool, bool, str]:
        return (self.workspace_id, self.revision, self.sync_enabled, self.telemetry_enabled, self.redaction_level)


def parse_workspace_preferences(value: object, *, workspace_id: str) -> WorkspacePreferences:
    if not isinstance(value, dict) or set(value) != {
        "contractVersion",
        "workspaceId",
        "revision",
        "updatedAt",
        "preferences",
    }:
        raise ValueError("workspace_preferences_invalid")
    if value["contractVersion"] != CONTRACT or value["workspaceId"] != workspace_id:
        raise ValueError("workspace_preferences_scope_invalid")
    if str(UUID(workspace_id)) != workspace_id:
        raise ValueError("workspace_preferences_scope_invalid")
    revision = value["revision"]
    if type(revision) is not int or not 0 <= revision <= _MAX_REVISION:
        raise ValueError("workspace_preferences_revision_invalid")
    updated_at = value["updatedAt"]
    if not isinstance(updated_at, str) or not _TIMESTAMP.fullmatch(updated_at):
        raise ValueError("workspace_preferences_timestamp_invalid")
    datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    preferences = value["preferences"]
    if not isinstance(preferences, dict) or set(preferences) != {
        "syncEnabled",
        "telemetryEnabled",
        "receiptRedactionLevel",
    }:
        raise ValueError("workspace_preferences_invalid")
    sync, telemetry, redaction = (
        preferences["syncEnabled"],
        preferences["telemetryEnabled"],
        preferences["receiptRedactionLevel"],
    )
    if type(sync) is not bool or type(telemetry) is not bool:
        raise ValueError("workspace_preferences_invalid")
    if not isinstance(redaction, str) or redaction not in _LEVELS:
        raise ValueError("workspace_preferences_invalid")
    return WorkspacePreferences(workspace_id, revision, updated_at, sync, telemetry, redaction)


def _state_key(workspace_id: str) -> str:
    return "workspace_preferences:" + workspace_id


def read_workspace_preferences(store: GuardStore) -> WorkspacePreferences | None:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    value = store.get_sync_payload(_state_key(workspace_id))
    return None if value is None else parse_workspace_preferences(value, workspace_id=workspace_id)


def preference_sync_context(store: GuardStore) -> dict[str, object]:
    context: dict[str, object] = {"workspacePreferencesContract": CONTRACT}
    try:
        current = read_workspace_preferences(store)
    except (ValueError, TypeError):
        return context
    if current is not None:
        context["workspacePreferenceRevision"] = current.revision
    return context


def accept_workspace_preferences(store: GuardStore, value: object, *, workspace_id: str) -> WorkspacePreferences:
    candidate = parse_workspace_preferences(value, workspace_id=workspace_id)
    with store._connect() as connection:
        connection.execute("begin immediate")
        if store._cloud_workspace_id_from_connection(connection) != workspace_id:
            raise ValueError("workspace_preferences_scope_changed")
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?", (_state_key(workspace_id),)
        ).fetchone()
        if row is not None:
            previous = parse_workspace_preferences(json.loads(str(row["payload_json"])), workspace_id=workspace_id)
            if candidate.revision < previous.revision:
                raise ValueError("workspace_preferences_stale")
            if (
                candidate.revision == previous.revision
                and candidate.semantic_identity() != previous.semantic_identity()
            ):
                raise ValueError("workspace_preferences_conflict")
        connection.execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) "
            "on conflict(state_key) do update set payload_json=excluded.payload_json, updated_at=excluded.updated_at",
            (_state_key(workspace_id), json.dumps(candidate.to_wire(), sort_keys=True), candidate.updated_at),
        )
    return candidate


def _legacy_state_key(workspace_id: str) -> str:
    return "workspace_preferences_legacy:" + workspace_id


def _accept_legacy_response(store: GuardStore, workspace_id: str | None) -> bool:
    if workspace_id is None:
        return False
    with store._connect() as connection:
        connection.execute("begin immediate")
        if store._cloud_workspace_id_from_connection(connection) != workspace_id:
            return False
        current = connection.execute(
            "select 1 from sync_state where state_key = ?", (_state_key(workspace_id),)
        ).fetchone()
        if current is not None:
            return False
        connection.execute(
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) "
            "on conflict(state_key) do update set payload_json=excluded.payload_json, updated_at=excluded.updated_at",
            (
                _legacy_state_key(workspace_id),
                json.dumps({"workspaceId": workspace_id, "legacyReceiptSync": True}),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return True


def _has_legacy_negotiation(store: GuardStore) -> bool:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return False
    return store.get_sync_payload(_legacy_state_key(workspace_id)) == {
        "workspaceId": workspace_id,
        "legacyReceiptSync": True,
    }


def receipt_upload_accepted(
    store: GuardStore, payload: dict[str, object], *, workspace_id: str | None, sent_revision: object
) -> bool:
    """Only an exact current preference acknowledgement permits cursor progress."""
    try:
        if store.get_cloud_workspace_id() != workspace_id:
            return False
        current = read_workspace_preferences(store)
        if "workspacePreferences" not in payload and "receiptSyncAccepted" not in payload:
            synced_at, count = payload.get("syncedAt"), payload.get("receiptsStored")
            if (
                not isinstance(synced_at, str)
                or not _TIMESTAMP.fullmatch(synced_at)
                or type(count) is not int
                or not 0 <= count <= _MAX_REVISION
            ):
                return False
            datetime.fromisoformat(synced_at.replace("Z", "+00:00"))
            return current is None and _accept_legacy_response(store, workspace_id)
        if workspace_id is None:
            return False
        candidate = accept_workspace_preferences(store, payload.get("workspacePreferences"), workspace_id=workspace_id)
        return (
            payload.get("receiptSyncAccepted") is True
            and type(sent_revision) is int
            and candidate.revision == sent_revision
            and candidate.sync_enabled
        )
    except (ValueError, TypeError):
        return False


def optional_upload_allowed(store: GuardStore, *, telemetry: bool = False) -> bool:
    """Saved remote permission can restrict, but cannot grant, local consent."""
    try:
        config = load_guard_config(store.guard_home)
        if not config.sync or (telemetry and not config.telemetry):
            return False
        current = read_workspace_preferences(store)
        return (
            _has_legacy_negotiation(store)
            if current is None
            else current.sync_enabled and (not telemetry or current.telemetry_enabled)
        )
    except (OSError, ValueError, TypeError):
        return False


def effective_receipt_redaction_level(store: GuardStore) -> str:
    try:
        local = load_guard_config(store.guard_home).receipt_redaction_level
        if local not in _LEVELS:
            return "full"
        levels = [local]
        signed = validated_synced_policy_bundle(store)
        if signed is not None:
            level = signed.get("receiptRedactionLevel")
            if isinstance(level, str) and level in _LEVELS:
                levels.append(level)
        current = read_workspace_preferences(store)
        if current is not None:
            levels.append(current.redaction_level)
        return max(levels, key=_LEVELS.__getitem__)
    except (OSError, ValueError, TypeError):
        return "full"
