"""Source-bound optional-upload negotiation, independent of signed policy authority."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast
from uuid import UUID

from .oauth_connection_authority import OAuthConnectionSnapshot, read_connection_authority

if TYPE_CHECKING:
    from .store import GuardStore

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
    value = _plain_json(value)
    if type(workspace_id) is not str:
        raise ValueError("workspace_preferences_scope_invalid")
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


_LEDGER_PREFIX = "workspace_preference_authority:"
_MARKER_PREFIX = "workspace_preference_adopted:"
_BINDING_FIELDS = ("issuer", "client_id", "grant_id", "device_id", "machine_id", "workspace_id", "runtime_id")


def reject_private_preference_key(state_key: str) -> None:
    if type(state_key) is not str:
        raise ValueError("State keys must be plain strings.")
    if state_key.startswith((_LEDGER_PREFIX, _MARKER_PREFIX)):
        raise ValueError("Preference authority requires its dedicated mutation boundary.")


def _plain_json(value: object) -> object:
    # Consume each caller-owned container once; validation and persistence use only the copy.
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) is dict:
        copied: dict[str, object] = {}
        for key, item in cast(dict[object, object], value).copy().items():
            if type(key) is not str:
                raise ValueError("Preference fields must be plain strings.")
            copied[key] = _plain_json(item)
        return copied
    if type(value) is list:
        return [_plain_json(item) for item in cast(list[object], value).copy()]
    raise ValueError("Invalid preference JSON value.")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate preference field.")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("Non-JSON preference value.")


def _read(connection: sqlite3.Connection, key: str) -> tuple[bool, object]:
    row = connection.execute("select payload_json from sync_state where state_key = ?", (key,)).fetchone()
    if row is None:
        return False, None
    try:
        return True, json.loads(str(row[0]), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, TypeError, RecursionError):
        return True, None


def _write(connection: sqlite3.Connection, key: str, value: object, now: str) -> None:
    connection.execute(
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) "
        "on conflict(state_key) do update set payload_json=excluded.payload_json, updated_at=excluded.updated_at",
        (key, json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), now),
    )


def _domain(source: OAuthConnectionSnapshot) -> tuple[str, str]:
    credentials = source.credentials()
    issuer, workspace = credentials.get("issuer"), credentials.get("workspace_id")
    if type(issuer) is not str or not issuer or type(workspace) is not str or str(UUID(workspace)) != workspace:
        raise ValueError("workspace_preferences_scope_invalid")
    canonical = json.dumps([1, source.credential_key, issuer, workspace], separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), workspace


def _check_source(connection: sqlite3.Connection, source: OAuthConnectionSnapshot) -> None:
    authority = read_connection_authority(connection, source.credential_key)
    present, metadata = _read(connection, source.credential_key)
    expected = source.credentials()
    if (
        authority.state != "ready"
        or authority.epoch != source.epoch
        or not present
        or not isinstance(metadata, dict)
        or any(metadata.get(key) != expected.get(key) for key in _BINDING_FIELDS)
    ):
        raise ValueError("workspace_preferences_source_changed")


@dataclass(frozen=True, slots=True, repr=False)
class WorkspacePreferenceState:
    connection: OAuthConnectionSnapshot
    domain: str
    workspace_id: str
    mode: str
    preferences: WorkspacePreferences | None
    confirmed_epoch: str | None
    legacy_allowed: bool

    @property
    def confirmed(self) -> bool:
        return self.confirmed_epoch == self.connection.epoch and self.mode in {"legacy", "negotiated"}

    def sync_context(self) -> dict[str, object]:
        result: dict[str, object] = {"workspacePreferencesContract": CONTRACT}
        if self.preferences is not None:
            result["workspacePreferenceRevision"] = self.preferences.revision
        return result


def _ledger(connection: sqlite3.Connection, source: OAuthConnectionSnapshot, now: str) -> WorkspacePreferenceState:
    domain, workspace = _domain(source)
    present, payload = _read(connection, _LEDGER_PREFIX + domain)
    adopted, marker = _read(connection, _MARKER_PREFIX + domain)
    if not present and not adopted:
        # Old workspace-only records do not establish issuer/source provenance.
        unscoped = any(
            _read(connection, prefix + workspace)[0]
            for prefix in ("workspace_preferences:", "workspace_preferences_legacy:")
        )
        payload = {"version": 1, "mode": "unnegotiated", "wire": None, "epoch": None, "legacyAllowed": not unscoped}
        _write(connection, _LEDGER_PREFIX + domain, payload, now)
        _write(connection, _MARKER_PREFIX + domain, {"version": 1}, now)
    elif (
        not present
        or not adopted
        or type(marker) is not dict
        or marker != {"version": 1}
        or type(marker.get("version")) is not int
    ):
        raise ValueError("workspace_preferences_authority_invalid")
    if (
        type(payload) is not dict
        or set(payload) != {"version", "mode", "wire", "epoch", "legacyAllowed"}
        or type(payload.get("version")) is not int
        or payload["version"] != 1
        or payload.get("mode") not in ("unnegotiated", "legacy", "negotiated")
        or type(payload.get("legacyAllowed")) is not bool
    ):
        raise ValueError("workspace_preferences_authority_invalid")
    mode, epoch = payload["mode"], payload["epoch"]
    if epoch is not None and (type(epoch) is not str or not re.fullmatch("[0-9a-f]{32}", epoch)):
        raise ValueError("workspace_preferences_authority_invalid")
    wire = payload["wire"]
    current = parse_workspace_preferences(wire, workspace_id=workspace) if mode == "negotiated" else None
    if (
        (mode != "negotiated" and wire is not None)
        or (mode == "unnegotiated" and epoch is not None)
        or (mode != "unnegotiated" and epoch is None)
        or (mode == "legacy" and payload["legacyAllowed"] is not True)
    ):
        raise ValueError("workspace_preferences_authority_invalid")
    return WorkspacePreferenceState(
        source,
        domain,
        workspace,
        cast(str, mode),
        current,
        cast(str | None, epoch),
        cast(bool, payload["legacyAllowed"]),
    )


def _current_source(store: GuardStore, required: OAuthConnectionSnapshot | None) -> OAuthConnectionSnapshot:
    current = store._capture_oauth_connection_unlocked()
    if current is None or (required is not None and not required.same_authority(current)):
        raise ValueError("workspace_preferences_source_changed")
    return current


def capture_workspace_preference_state(
    store: GuardStore, *, required_connection: OAuthConnectionSnapshot | None = None
) -> WorkspacePreferenceState:
    with store.hold_oauth_credential_lock():
        current = _current_source(store, required_connection)
        with store._connect() as connection:
            connection.execute("begin immediate")
            _check_source(connection, current)
            return _ledger(connection, current, datetime.now(timezone.utc).isoformat())


@dataclass(frozen=True, slots=True, repr=False)
class PreferenceResponseAcceptance:
    state: WorkspacePreferenceState
    receipt_accepted: bool


def _valid_legacy_response(payload: dict[str, object]) -> bool:
    timestamp, count = payload.get("syncedAt"), payload.get("receiptsStored")
    if (
        type(timestamp) is not str
        or not _TIMESTAMP.fullmatch(timestamp)
        or type(count) is not int
        or not 0 <= count <= _MAX_REVISION
    ):
        return False
    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return True


def _accept_workspace_preference_response_on_connection(
    connection: sqlite3.Connection,
    request_state: WorkspacePreferenceState,
    response: dict[str, object],
    *,
    current: OAuthConnectionSnapshot,
    sent_revision: object,
    now: str,
) -> PreferenceResponseAcceptance:
    _check_source(connection, current)
    state = _ledger(connection, current, now)
    if state.domain != request_state.domain:
        raise ValueError("workspace_preferences_scope_changed")
    legacy = "workspacePreferences" not in response and "receiptSyncAccepted" not in response
    if legacy:
        if state.mode == "negotiated" or not state.legacy_allowed or not _valid_legacy_response(response):
            raise ValueError("workspace_preferences_legacy_invalid")
        candidate = None
        mode = "legacy"
        accepted = True
    else:
        candidate = parse_workspace_preferences(response.get("workspacePreferences"), workspace_id=state.workspace_id)
        previous = state.preferences
        if previous is not None:
            if candidate.revision < previous.revision:
                raise ValueError("workspace_preferences_stale")
            if (
                candidate.revision == previous.revision
                and candidate.semantic_identity() != previous.semantic_identity()
            ):
                raise ValueError("workspace_preferences_conflict")
        mode = "negotiated"
        accepted = (
            response.get("receiptSyncAccepted") is True
            and type(sent_revision) is int
            and sent_revision == candidate.revision
            and candidate.sync_enabled
        )
    _write(
        connection,
        _LEDGER_PREFIX + state.domain,
        {
            "version": 1,
            "mode": mode,
            "wire": None if candidate is None else candidate.to_wire(),
            "epoch": current.epoch,
            "legacyAllowed": state.legacy_allowed,
        },
        now,
    )
    updated = WorkspacePreferenceState(
        current, state.domain, state.workspace_id, mode, candidate, current.epoch, state.legacy_allowed
    )
    return PreferenceResponseAcceptance(updated, accepted)


def accept_workspace_preference_response(
    store: GuardStore,
    request_state: WorkspacePreferenceState,
    payload: object,
    *,
    sent_revision: object,
) -> PreferenceResponseAcceptance:
    copied = _plain_json(payload)
    if type(copied) is not dict:
        raise ValueError("workspace_preferences_invalid")
    response = cast(dict[str, object], copied)
    with store.hold_oauth_credential_lock():
        current = _current_source(store, request_state.connection)
        now = datetime.now(timezone.utc).isoformat()
        with store._connect() as connection:
            connection.execute("begin immediate")
            return _accept_workspace_preference_response_on_connection(
                connection,
                request_state,
                response,
                current=current,
                sent_revision=sent_revision,
                now=now,
            )
