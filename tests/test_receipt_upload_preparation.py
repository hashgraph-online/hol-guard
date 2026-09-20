"""Independent controls for the draft caller's actual receipt preparation boundary."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import receipt_sync_authority as authority
from codex_plugin_scanner.guard.runtime import receipt_upload, runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_receipt_redaction_cursor import _store_blocked_command_receipt
from tests.test_receipt_sync_authority import CURSOR, NOW, _candidate, _marker, _ready, _reply
from tests.test_workspace_preference_authority import _accept, _wire


def _selected(store: GuardStore) -> list[dict[str, object]]:
    _store_blocked_command_receipt(store, "selected-a")
    _store_blocked_command_receipt(store, "selected-b")
    return store.list_receipts(limit=10)


def _serialize(store: GuardStore, batch: Sequence[Mapping[str, object]], level: str) -> list[dict[str, object]]:
    return runner._cloud_sync_receipts_payload(
        [dict(item) for item in batch],
        store=store,
        device_id="synthetic-device",
        device_name="synthetic-device-name",
        redaction_level=level,
    )


def _preparation(
    store: GuardStore, rows: list[dict[str, object]], **overrides: Any
) -> receipt_upload.ReceiptUploadPreparation:
    capture = authority.capture_receipt_sync_state(store)
    return receipt_upload.ReceiptUploadPreparation(
        store,
        **{
            "connection": capture.preference_state.connection,
            "selection": capture,
            "redaction_level": "partial",
            "receipt_batch": rows,
            "sync_context": {"existingControl": {"values": ["original"]}},
            "serialize": lambda batch, level: _serialize(store, batch, level),
            **overrides,
        },
    )


def _request() -> urllib.request.Request:
    return urllib.request.Request(
        "https://example.invalid/receipts",
        method="POST",
        data=b"old",
        headers={"Authorization": "DPoP synthetic", "DPoP": "synthetic-proof", "X-Request-Context": "retained"},
    )


def _body(request: urllib.request.Request) -> dict[str, Any]:
    assert request.data is not None
    return json.loads(request.data)


def test_actual_serializer_binds_success_to_sent_ids_and_exact_backfill_flag(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    rows = _selected(store)
    rows[0]["__command_detail_backfill"] = True
    preparation = _preparation(store, rows)
    request = _request()
    identity = (request.full_url, request.get_method(), dict(request.header_items()))
    preparation.prepare(request)
    body = _body(request)
    assert (request.full_url, request.get_method(), dict(request.header_items())) == identity
    assert [row["receiptId"] for row in body["receipts"]] == [row["receipt_id"] for row in rows]
    assert preparation.sent_batch[0]["__command_detail_backfill"] is True
    assert preparation.attempt is not None and preparation.attempt.rows_sent == len(body["receipts"]) == 2
    assert body["syncContext"]["workspacePreferenceRevision"] == 1
    candidate = _candidate(max(row["receipt_rowid"] for row in rows))
    result = preparation.complete(_reply(), candidate=candidate)
    assert result is not None and result.progress_committed


def test_withdrawal_between_real_preparations_records_only_final_empty_attempt(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    rows = _selected(store)
    serialized: list[int] = []

    def serialize(batch: Sequence[Mapping[str, object]], level: str) -> list[dict[str, object]]:
        serialized.append(len(batch))
        return _serialize(store, batch, level)

    preparation = _preparation(store, rows, serialize=serialize)
    request = _request()
    preparation.prepare(request)
    assert len(_body(request)["receipts"]) == 2
    (store.guard_home / "config.toml").write_text('sync = false\nreceipt_redaction_level = "none"\n')
    preparation.prepare(request)
    assert _body(request)["receipts"] == [] and serialized == [2]
    assert preparation.sent_batch == ()
    assert preparation.attempt is not None and preparation.attempt.rows_sent == 0
    assert not preparation.attempt.optional_allowed
    result = preparation.complete(_reply(), candidate=_candidate(2))
    assert result is not None and result.preference_accepted and not result.progress_committed
    assert store.get_sync_payload(CURSOR) is None


def test_new_current_revision_is_used_on_later_actual_attempt(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    rows = _selected(store)
    preparation = _preparation(store, rows)
    request = _request()
    preparation.prepare(request)
    _accept(store, _wire(2), sent=2)
    preparation.prepare(request)
    assert len(_body(request)["receipts"]) == 2
    assert _body(request)["syncContext"]["workspacePreferenceRevision"] == 2
    assert preparation.attempt is not None and preparation.attempt.sent_revision == 2
    result = preparation.complete(_reply(2), candidate=_candidate(2))
    assert result is not None and result.progress_committed


@pytest.mark.parametrize("change", ["cursor-reset", "local-redaction", "remote-redaction", "remote-withdrawal"])
def test_changed_selection_or_privacy_strips_optional_rows_and_retains_control(tmp_path: Path, change: str) -> None:
    store, _ = _ready(tmp_path)
    preparation = _preparation(store, _selected(store))
    if change == "cursor-reset":
        store.set_sync_payload(CURSOR, {"last_rowid": 0}, NOW)
    elif change == "local-redaction":
        (store.guard_home / "config.toml").write_text('sync = true\nreceipt_redaction_level = "full"\n')
    elif change == "remote-redaction":
        _accept(store, _wire(2, redaction="full"), sent=2)
    else:
        _accept(store, _wire(2, sync=False), sent=2)
    request = _request()
    preparation.prepare(request)
    assert _body(request)["receipts"] == []
    assert _body(request)["syncContext"]["existingControl"] == {"values": ["original"]}
    assert preparation.sent_batch == ()
    assert preparation.attempt is not None and not preparation.attempt.optional_allowed
    if change == "cursor-reset":
        assert store.get_sync_payload(CURSOR) == {"last_rowid": 0}


def test_selection_from_another_actual_source_never_authorizes_shared_global_rows(tmp_path: Path) -> None:
    first, _ = _ready(tmp_path, source="first")
    rows = _selected(first)
    selection = authority.capture_receipt_sync_state(first)
    second, _ = _ready(tmp_path, source="second")
    current = authority.capture_receipt_sync_state(second)
    assert current.rows == selection.rows
    assert not current.preference_state.connection.same_authority(selection.preference_state.connection)
    preparation = _preparation(second, rows, selection=selection)
    request = _request()
    preparation.prepare(request)
    assert _body(request)["receipts"] == []
    assert preparation.attempt is not None and not preparation.attempt.optional_allowed


@pytest.mark.parametrize("change", ["replace", "unbound"])
def test_lost_or_missing_actual_auth_source_cannot_reuse_revision_or_selection(tmp_path: Path, change: str) -> None:
    store, inputs = _ready(tmp_path)
    rows = _selected(store)
    overrides = {"connection": None} if change == "unbound" else {}
    preparation = _preparation(
        store,
        rows,
        sync_context={"workspacePreferenceRevision": 999, "workspacePreferencesContract": "stale"},
        **overrides,
    )
    if change == "replace":
        store.set_oauth_local_credentials(**inputs)
    request = _request()
    preparation.prepare(request)
    assert _body(request)["receipts"] == []
    assert _body(request)["syncContext"] == {"workspacePreferencesContract": "guard.workspace-preferences.v1"}
    assert preparation.attempt is None and preparation.sent_batch == ()
    assert preparation.complete(_reply(), candidate=_candidate(2)) is None


def test_same_authority_refresh_retains_valid_selection(tmp_path: Path) -> None:
    store, inputs = _ready(tmp_path)
    preparation = _preparation(store, _selected(store))
    store.set_oauth_local_credentials(
        **{**inputs, "access_token": "new-access", "refresh_token": "new-refresh"},
        expected_connection=preparation.connection,
    )
    request = _request()
    preparation.prepare(request)
    assert len(_body(request)["receipts"]) == 2
    assert preparation.attempt is not None and preparation.attempt.optional_allowed
    result = preparation.complete(_reply(), candidate=_candidate(2))
    assert result is not None and result.progress_committed


@pytest.mark.parametrize("target", ["receipt", "context"])
def test_nested_input_aliases_cannot_change_frozen_selection_or_control(tmp_path: Path, target: str) -> None:
    store, _ = _ready(tmp_path)
    rows = _selected(store)
    rows[0]["capabilities"] = ["original-capability"]
    context = {"existingControl": {"values": ["original"]}}
    preparation = _preparation(store, rows, sync_context=context)
    if target == "receipt":
        rows[0]["capabilities"].append("mutated-capability")
    else:
        context["existingControl"]["values"].append("mutated")
    request = _request()
    preparation.prepare(request)
    assert _body(request)["receipts"][0]["capabilities"] == ["original-capability"]
    assert _body(request)["syncContext"]["existingControl"] == {"values": ["original"]}


@pytest.mark.parametrize("change", ["drop", "reverse", "duplicate", "replace-id"])
def test_serializer_mismatch_cannot_borrow_original_batch_metadata(tmp_path: Path, change: str) -> None:
    store, _ = _ready(tmp_path)
    rows = _selected(store)

    def serialize(batch: Sequence[Mapping[str, object]], level: str) -> list[dict[str, object]]:
        values = _serialize(store, batch, level)
        if change == "drop":
            return values[:1]
        if change == "reverse":
            return list(reversed(values))
        if change == "duplicate":
            return [values[0], values[0]]
        values[0]["receiptId"] = "different-id"
        return values

    preparation = _preparation(store, rows, serialize=serialize)
    request = _request()
    preparation.prepare(request)
    assert _body(request)["receipts"] == [] and preparation.sent_batch == ()
    assert preparation.attempt is not None and preparation.attempt.rows_sent == 0
    result = preparation.complete(_reply(), candidate=_candidate(2))
    assert result is not None and not result.progress_committed
    assert store.get_sync_payload(CURSOR) is None


def test_optional_preference_conflict_returns_no_acceptance_for_control_caller(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    preparation = _preparation(store, _selected(store))
    preparation.prepare(_request())
    _accept(store, _wire(2, sync=False), sent=2)
    assert preparation.complete(_reply(), candidate=_candidate(2)) is None
    assert store.get_sync_payload(CURSOR) is None


def test_optional_sql_write_failure_rolls_back_and_returns_no_acceptance(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    preparation = _preparation(store, _selected(store))
    preparation.prepare(_request())
    with store._connect() as connection:
        connection.execute(
            "create trigger reject_preference before insert on sync_state "
            "when NEW.state_key like 'workspace_preference_authority:%' "
            "begin select raise(abort, 'synthetic optional preference failure'); end"
        )
    assert preparation.complete(_reply(), candidate=_candidate(2)) is None
    assert store.get_sync_payload(CURSOR) is None


def test_authorized_empty_query_can_complete_with_only_explicit_empty_marker(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    preparation = _preparation(store, [], authorized_empty_exhaustion=True)
    request = _request()
    preparation.prepare(request)
    assert _body(request)["receipts"] == []
    assert preparation.attempt is not None and preparation.attempt.authorized_empty_exhaustion
    marker = _marker(receipts=0, queried=0, before_rowid=None, complete=True)
    result = preparation.complete(_reply(), candidate=_candidate(None, marker))
    assert result is not None and result.progress_committed
    assert store.get_sync_payload(CURSOR) is None
