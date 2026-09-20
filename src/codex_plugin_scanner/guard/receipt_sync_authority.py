"""Atomic, source-bound receipt acknowledgement and exact progress replacement."""

from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from . import workspace_preference_authority as preference_authority
from .config import load_guard_config
from .oauth_connection_authority import OAuthConnectionSnapshot
from .runtime.receipt_redaction import compose_receipt_redaction_level
from .synced_policy import validated_synced_policy_bundle
from .workspace_preference_authority import WorkspacePreferences, WorkspacePreferenceState

if TYPE_CHECKING:
    from .store import GuardStore

_CURSOR = "receipt_sync_cursor"
_BACKFILL = "cloud_receipt_command_detail_backfill_v2"
_REDACTION = "cloud_receipt_redaction_level"
_RELAXATION = "cloud_receipt_redaction_relaxed_resync_v1"
_KEYS = (_CURSOR, _BACKFILL, _REDACTION, _RELAXATION)
_LEVELS = {"none": 0, "partial": 1, "full": 2}
_MAX_ROWID = (1 << 63) - 1
_MARKER_FIELDS = {"level", "updated_at", "days", "limit", "receipts", "queried", "before_rowid", "complete"}


def _integer(value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("receipt_progress_integer_invalid")


def _level(value: object) -> None:
    if type(value) is not str or value not in _LEVELS:
        raise ValueError("receipt_progress_redaction_invalid")


def _timestamp(value: object) -> None:
    if type(value) is not str or not preference_authority._TIMESTAMP.fullmatch(value):
        raise ValueError("receipt_progress_timestamp_invalid")
    datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptStateRow:
    """Exact SQLite values, including malformed storage; absence is a separate None."""

    payload_json: str | bytes | int | float | None
    updated_at: str | bytes | int | float | None

    def __post_init__(self) -> None:
        for value in (self.payload_json, self.updated_at):
            if value is not None and type(value) not in (str, bytes, int, float):
                raise ValueError("receipt_progress_storage_invalid")
            if type(value) is float and not math.isfinite(value):
                raise ValueError("receipt_progress_storage_invalid")

    def payload(self) -> dict[str, object] | list[object] | None:
        """Decode a fresh legacy payload without exposing a mutable captured value."""
        if type(self.payload_json) is not str:
            return None
        try:
            value = json.loads(
                self.payload_json,
                object_pairs_hook=preference_authority._unique_object,
                parse_constant=preference_authority._invalid_constant,
            )
            return cast(dict[str, object] | list[object], value) if type(value) in (dict, list) else None
        except (ValueError, TypeError, RecursionError):
            return None


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptProgressRows:
    cursor: ReceiptStateRow | None
    backfill: ReceiptStateRow | None
    redaction: ReceiptStateRow | None
    relaxation: ReceiptStateRow | None

    def __post_init__(self) -> None:
        for row in (self.cursor, self.backfill, self.redaction, self.relaxation):
            if row is not None and type(row) is not ReceiptStateRow:
                raise ValueError("receipt_progress_storage_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptSyncCapture:
    preference_state: WorkspacePreferenceState
    rows: ReceiptProgressRows

    def __post_init__(self) -> None:
        state = self.preference_state
        if type(state) is not WorkspacePreferenceState or type(self.rows) is not ReceiptProgressRows:
            raise ValueError("receipt_progress_capture_invalid")
        if type(state.connection) is not OAuthConnectionSnapshot:
            raise ValueError("receipt_progress_capture_invalid")
        if state.preferences is not None and type(state.preferences) is not WorkspacePreferences:
            raise ValueError("receipt_progress_capture_invalid")
        for value in (
            state.domain,
            state.workspace_id,
            state.mode,
            state.connection.credential_key,
            state.connection.epoch,
            state.connection.store_scope,
            state.connection._credentials_json,
        ):
            if type(value) is not str:
                raise ValueError("receipt_progress_capture_invalid")
        if state.mode not in {"unnegotiated", "legacy", "negotiated"} or type(state.legacy_allowed) is not bool:
            raise ValueError("receipt_progress_capture_invalid")
        if state.confirmed_epoch is not None and type(state.confirmed_epoch) is not str:
            raise ValueError("receipt_progress_capture_invalid")
        if state.preferences is not None:
            preference_authority.parse_workspace_preferences(
                state.preferences.to_wire(), workspace_id=state.workspace_id
            )


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptBackfillMarker:
    level: str
    updated_at: str
    days: int
    limit: int
    receipts: int
    queried: int
    before_rowid: int | None
    complete: bool

    def __post_init__(self) -> None:
        _level(self.level)
        _timestamp(self.updated_at)
        _integer(self.days, 1, 30)
        _integer(self.limit, 1, 200)
        _integer(self.queried, 0, self.limit)
        _integer(self.receipts, 0, self.queried)
        if self.before_rowid is not None:
            _integer(self.before_rowid, 1, _MAX_ROWID)
        if type(self.complete) is not bool or (self.complete and self.queried >= self.limit):
            raise ValueError("receipt_progress_marker_invalid")

    @classmethod
    def from_payload(cls, value: object) -> ReceiptBackfillMarker:
        copied = preference_authority._plain_json(value)
        if type(copied) is not dict or set(copied) != _MARKER_FIELDS:
            raise ValueError("receipt_progress_marker_invalid")
        fields = cast(dict[str, object], copied)
        return cls(
            cast(str, fields["level"]),
            cast(str, fields["updated_at"]),
            cast(int, fields["days"]),
            cast(int, fields["limit"]),
            cast(int, fields["receipts"]),
            cast(int, fields["queried"]),
            cast(int | None, fields["before_rowid"]),
            cast(bool, fields["complete"]),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "level": self.level,
            "updated_at": self.updated_at,
            "days": self.days,
            "limit": self.limit,
            "receipts": self.receipts,
            "queried": self.queried,
            "before_rowid": self.before_rowid,
            "complete": self.complete,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptProgressCandidate:
    cursor_rowid: int | None
    backfill: ReceiptBackfillMarker | None
    synced_at: str

    def __post_init__(self) -> None:
        _timestamp(self.synced_at)
        if self.cursor_rowid is not None:
            _integer(self.cursor_rowid, 1, _MAX_ROWID)
        if self.backfill is not None and (
            type(self.backfill) is not ReceiptBackfillMarker or self.backfill.updated_at != self.synced_at
        ):
            raise ValueError("receipt_progress_candidate_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptSyncAttempt:
    capture: ReceiptSyncCapture
    sent_revision: int | None
    optional_allowed: bool
    redaction_level: str
    rows_sent: int
    authorized_empty_exhaustion: bool = False

    def __post_init__(self) -> None:
        if type(self.capture) is not ReceiptSyncCapture:
            raise ValueError("receipt_progress_capture_invalid")
        if self.sent_revision is not None:
            _integer(self.sent_revision, 0, (1 << 53) - 1)
        if type(self.optional_allowed) is not bool or type(self.authorized_empty_exhaustion) is not bool:
            raise ValueError("receipt_progress_permission_invalid")
        _level(self.redaction_level)
        _integer(self.rows_sent, 0, (1 << 53) - 1)
        if self.authorized_empty_exhaustion and (self.rows_sent != 0 or not self.optional_allowed):
            raise ValueError("receipt_progress_empty_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class ReceiptSyncCompletion:
    preference_accepted: bool
    receipt_acknowledged: bool
    progress_committed: bool
    capture: ReceiptSyncCapture


def _rows(connection: sqlite3.Connection) -> ReceiptProgressRows:
    found = {
        row[0]: ReceiptStateRow(row[1], row[2])
        for row in connection.execute(
            "select state_key, payload_json, updated_at from sync_state where state_key in (?, ?, ?, ?)", _KEYS
        )
    }
    return ReceiptProgressRows(*(found.get(key) for key in _KEYS))


def capture_receipt_sync_state(
    store: GuardStore, *, required_connection: OAuthConnectionSnapshot | None = None
) -> ReceiptSyncCapture:
    """Capture source, consent and the exact rows which will drive selection."""
    with store.hold_oauth_credential_lock():
        return _capture_receipt_sync_state_with_credential_lock(store, required_connection=required_connection)


def _capture_receipt_sync_state_with_credential_lock(
    store: GuardStore, *, required_connection: OAuthConnectionSnapshot | None = None
) -> ReceiptSyncCapture:
    """Read source and rows while the caller holds the credential lock."""
    current = preference_authority._current_source(store, required_connection)
    with store._connect() as connection:
        connection.execute("begin immediate")
        preference_authority._check_source(connection, current)
        state = preference_authority._ledger(connection, current, datetime.now(timezone.utc).isoformat())
        return ReceiptSyncCapture(state, _rows(connection))


def _valid_rows(rows: ReceiptProgressRows) -> bool:
    try:
        for key, row in zip(_KEYS, (rows.cursor, rows.backfill, rows.redaction, rows.relaxation), strict=True):
            if row is None:
                continue
            _timestamp(row.updated_at)
            value = row.payload()
            if type(value) is not dict:
                return False
            if key == _CURSOR:
                if not set(value) <= {"last_rowid", "synced_at", "reason", "receipt_redaction_level"}:
                    return False
                cursor = value.get("last_rowid")
                if type(cursor) is str and cursor.strip().isdigit():
                    cursor = int(cursor.strip())
                _integer(cursor, -_MAX_ROWID, _MAX_ROWID)
                if "synced_at" in value:
                    _timestamp(value["synced_at"])
                if "reason" in value and value["reason"] not in {
                    "cloud_receipt_redaction_level_relaxed",
                    "cloud_receipt_redaction_level_relaxed_existing",
                }:
                    return False
                if "receipt_redaction_level" in value:
                    _level(value["receipt_redaction_level"])
            elif key == _BACKFILL:
                before = value.get("before_rowid")
                if type(before) is str and before.strip().isdigit():
                    value["before_rowid"] = int(before.strip())
                ReceiptBackfillMarker.from_payload(value)
            else:
                if not {"level"} <= set(value) <= {"level", "updated_at"}:
                    return False
                _level(value["level"])
                if "updated_at" in value:
                    _timestamp(value["updated_at"])
        return True
    except (ValueError, TypeError, RecursionError):
        return False


def _local_permission(store: GuardStore) -> tuple[bool, str]:
    # External configuration and signed policy are sampled outside the final SQL transaction.
    try:
        config = load_guard_config(store.guard_home)
        signed = validated_synced_policy_bundle(store)
        return config.sync is True, compose_receipt_redaction_level(config, signed, None)
    except (OSError, RuntimeError, ValueError, TypeError):
        return False, "full"


def _optional_state(state: WorkspacePreferenceState) -> bool:
    return state.confirmed and (state.mode == "legacy" if state.preferences is None else state.preferences.sync_enabled)


def _can_commit(
    attempt: ReceiptSyncAttempt,
    candidate: ReceiptProgressCandidate,
    state: WorkspacePreferenceState,
    rows: ReceiptProgressRows,
    local: tuple[bool, str],
) -> bool:
    if (
        not attempt.optional_allowed
        or not local[0]
        or not _optional_state(attempt.capture.preference_state)
        or not _optional_state(state)
        or rows != attempt.capture.rows
        or not _valid_rows(rows)
    ):
        return False
    level = local[1]
    if state.preferences is not None:
        level = max((level, state.preferences.redaction_level), key=_LEVELS.__getitem__)
    if level != attempt.redaction_level:
        return False
    marker = candidate.backfill
    if marker is not None and marker.level != attempt.redaction_level:
        return False
    if attempt.rows_sent == 0:
        return (
            attempt.authorized_empty_exhaustion
            and candidate.cursor_rowid is None
            and marker is not None
            and marker.complete
            and marker.queried == marker.receipts == 0
        )
    return candidate.cursor_rowid is not None or marker is not None


def accept_receipt_sync_response(
    store: GuardStore,
    attempt: ReceiptSyncAttempt,
    payload: object,
    *,
    candidate: ReceiptProgressCandidate,
) -> ReceiptSyncCompletion:
    """Learn preferences and conditionally commit typed progress in one transaction."""
    copied = preference_authority._plain_json(payload)
    if type(copied) is not dict or type(attempt) is not ReceiptSyncAttempt:
        raise ValueError("receipt_progress_response_invalid")
    if type(candidate) is not ReceiptProgressCandidate:
        raise ValueError("receipt_progress_candidate_invalid")
    prepared = ReceiptProgressCandidate(
        candidate.cursor_rowid,
        None if candidate.backfill is None else ReceiptBackfillMarker.from_payload(candidate.backfill.to_payload()),
        candidate.synced_at,
    )
    with store.hold_oauth_credential_lock():
        local = _local_permission(store)
        current = preference_authority._current_source(store, attempt.capture.preference_state.connection)
        now = datetime.now(timezone.utc).isoformat()
        with store._connect() as connection:
            connection.execute("begin immediate")
            acceptance = preference_authority._accept_workspace_preference_response_on_connection(
                connection,
                attempt.capture.preference_state,
                cast(dict[str, object], copied),
                current=current,
                sent_revision=attempt.sent_revision,
                now=now,
            )
            rows = _rows(connection)
            committed = acceptance.receipt_accepted and _can_commit(attempt, prepared, acceptance.state, rows, local)
            if committed:
                if prepared.cursor_rowid is not None:
                    preference_authority._write(
                        connection,
                        _CURSOR,
                        {"last_rowid": prepared.cursor_rowid, "synced_at": prepared.synced_at},
                        prepared.synced_at,
                    )
                if prepared.backfill is not None:
                    preference_authority._write(
                        connection, _BACKFILL, prepared.backfill.to_payload(), prepared.synced_at
                    )
                rows = _rows(connection)
            return ReceiptSyncCompletion(
                True, acceptance.receipt_accepted, committed, ReceiptSyncCapture(acceptance.state, rows)
            )
