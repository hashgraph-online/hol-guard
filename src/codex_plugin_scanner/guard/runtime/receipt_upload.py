"""Prepare optional receipt content from the authority of each actual attempt."""

from __future__ import annotations

import json
import sqlite3
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, cast

from ..config import load_guard_config
from ..oauth_connection_authority import OAuthConnectionSnapshot
from ..receipt_sync_authority import (
    ReceiptProgressCandidate,
    ReceiptSyncAttempt,
    ReceiptSyncCapture,
    ReceiptSyncCompletion,
    _capture_receipt_sync_state_with_credential_lock,
    accept_receipt_sync_response,
    capture_receipt_sync_state,
)
from ..synced_policy import validated_synced_policy_bundle
from ..workspace_preference_authority import CONTRACT, WorkspacePreferenceState, _plain_json
from .receipt_redaction import compose_receipt_redaction_level

if TYPE_CHECKING:
    from ..store import GuardStore


def capture_optional_receipt_state(
    store: GuardStore, connection: OAuthConnectionSnapshot | None, *, credential_lock_held: bool = False
) -> ReceiptSyncCapture | None:
    if connection is None:
        return None
    try:
        if credential_lock_held:
            return _capture_receipt_sync_state_with_credential_lock(store, required_connection=connection)
        return capture_receipt_sync_state(store, required_connection=connection)
    except (OSError, RuntimeError, ValueError, TypeError, sqlite3.Error):
        return None


def optional_upload_settings(
    store: GuardStore, state: WorkspacePreferenceState | None, *, telemetry: bool = False
) -> tuple[bool, str]:
    """A current source permits optional content only within all local privacy limits."""
    try:
        config = load_guard_config(store.guard_home)
        signed = validated_synced_policy_bundle(store)
        remote_level = None if state is None or state.preferences is None else state.preferences.redaction_level
        level = compose_receipt_redaction_level(config, signed, remote_level)
        if (
            config.sync is not True
            or (telemetry and config.telemetry is not True)
            or state is None
            or not state.confirmed
        ):
            return False, level
        preferences = state.preferences
        allowed = (
            state.mode == "legacy"
            if preferences is None
            else preferences.sync_enabled and (not telemetry or preferences.telemetry_enabled)
        )
        return allowed, level
    except (OSError, RuntimeError, ValueError, TypeError, sqlite3.Error):
        return False, "full"


class ReceiptUploadPreparation:
    """Retain the metadata of the last actual request without exposing it in repr."""

    def __init__(
        self,
        store: GuardStore,
        *,
        connection: OAuthConnectionSnapshot | None,
        selection: ReceiptSyncCapture | None,
        redaction_level: str,
        receipt_batch: Sequence[Mapping[str, object]],
        sync_context: Mapping[str, object],
        serialize: Callable[[list[dict[str, object]], str], list[dict[str, object]]],
        authorized_empty_exhaustion: bool = False,
    ) -> None:
        self.store = store
        self.connection = connection
        self.selection = selection
        self.redaction_level = redaction_level
        self._batch_json = json.dumps(_plain_json([dict(item) for item in receipt_batch]))
        self._context_json = json.dumps(_plain_json(dict(sync_context)))
        self.serialize = serialize
        self.authorized_empty_exhaustion = authorized_empty_exhaustion
        self.attempt: ReceiptSyncAttempt | None = None
        self.sent_batch: tuple[Mapping[str, object], ...] = ()

    def prepare(self, request: urllib.request.Request) -> None:
        captured = capture_optional_receipt_state(self.store, self.connection)
        state = None if captured is None else captured.preference_state
        allowed, level = optional_upload_settings(self.store, state)
        # Changed query bookkeeping or redaction requires a fresh bounded selection.
        allowed = (
            allowed
            and captured is not None
            and self.selection is not None
            and self.selection.preference_state.connection.same_authority(captured.preference_state.connection)
            and captured.rows == self.selection.rows
            and level == self.redaction_level
        )
        batch = cast(list[dict[str, object]], json.loads(self._batch_json)) if allowed else []
        metadata = tuple(
            MappingProxyType(
                {key: item.get(key) for key in ("receipt_id", "receipt_rowid", "__command_detail_backfill")}
            )
            for item in batch
        )
        try:
            serialized = _plain_json(self.serialize(batch, level)) if allowed else []
        except (ValueError, TypeError, RecursionError):
            serialized = None
        expected_ids = [item.get("receipt_id") for item in metadata]
        valid_wire = (
            type(serialized) is list
            and len(serialized) == len(metadata)
            and all(type(item) is dict for item in serialized)
        )
        wire_receipts = cast(list[dict[str, object]], serialized) if valid_wire else []
        if (
            not valid_wire
            or any(type(value) is not str or not value for value in expected_ids)
            or len(set(expected_ids)) != len(expected_ids)
            or any(
                type(item.get("receipt_rowid")) is not int or not 0 < cast(int, item["receipt_rowid"]) <= (1 << 63) - 1
                for item in metadata
            )
            or any(
                item.get("__command_detail_backfill") is not None
                and type(item.get("__command_detail_backfill")) is not bool
                for item in metadata
            )
            or [item.get("receiptId") for item in wire_receipts] != expected_ids
        ):
            allowed = False
            wire_receipts = []
            metadata = ()
        self.sent_batch = metadata
        context = cast(dict[str, object], json.loads(self._context_json))
        context.pop("workspacePreferenceRevision", None)
        context.pop("workspacePreferencesContract", None)
        context.update({"workspacePreferencesContract": CONTRACT} if state is None else state.sync_context())
        request.data = json.dumps({"receipts": wire_receipts, "syncContext": context}).encode("utf-8")
        self.attempt = (
            None
            if captured is None
            else ReceiptSyncAttempt(
                captured,
                None if state is None or state.preferences is None else state.preferences.revision,
                allowed,
                level,
                len(metadata),
                self.authorized_empty_exhaustion and allowed and not metadata,
            )
        )

    def complete(self, payload: object, *, candidate: ReceiptProgressCandidate) -> ReceiptSyncCompletion | None:
        if self.attempt is None:
            return None
        try:
            return accept_receipt_sync_response(self.store, self.attempt, payload, candidate=candidate)
        except (OSError, RuntimeError, ValueError, TypeError, sqlite3.Error):
            # Optional negotiation cannot prevent the existing signed control response processing.
            return None


class OptionalUploadPausedError(RuntimeError):
    """Optional work stops before another transport attempt when consent is unavailable."""


def require_optional_telemetry(
    store: GuardStore, connection: OAuthConnectionSnapshot | None, *, credential_lock_held: bool = False
) -> None:
    captured = capture_optional_receipt_state(store, connection, credential_lock_held=credential_lock_held)
    allowed, _ = optional_upload_settings(
        store, None if captured is None else captured.preference_state, telemetry=True
    )
    if not allowed:
        raise OptionalUploadPausedError("optional_upload_paused")
