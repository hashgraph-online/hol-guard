"""Receipt progress commits only with the acknowledged source and exact selected state."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import receipt_sync_authority as receipts
from codex_plugin_scanner.guard import workspace_preference_authority as preferences
from codex_plugin_scanner.guard.oauth_connection_authority import advance_connection_epoch
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import validated_synced_policy_bundle
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.test_synced_policy import _signed_policy_bundle
from tests.test_workspace_preference_authority import NOW, WORKSPACE, _accept, _store, _wire

LATER = "2026-06-01T00:00:01+00:00"
CURSOR = "receipt_sync_cursor"
BACKFILL = "cloud_receipt_command_detail_backfill_v2"
REDACTION = "cloud_receipt_redaction_level"
RELAXATION = "cloud_receipt_redaction_relaxed_resync_v1"


def _marker(**changes: object) -> receipts.ReceiptBackfillMarker:
    return receipts.ReceiptBackfillMarker.from_payload(
        {
            "level": "partial",
            "updated_at": NOW,
            "days": 30,
            "limit": 200,
            "receipts": 2,
            "queried": 2,
            "before_rowid": 7,
            "complete": False,
            **changes,
        }
    )


def _ready(tmp_path: Path, *, source: str = "default") -> tuple[GuardStore, dict[str, Any]]:
    store, inputs = _store(tmp_path, source=source)
    _accept(store)
    return store, inputs


def _attempt(store: GuardStore, **changes: Any) -> receipts.ReceiptSyncAttempt:
    return receipts.ReceiptSyncAttempt(
        **{
            "capture": receipts.capture_receipt_sync_state(store),
            "sent_revision": 1,
            "optional_allowed": True,
            "redaction_level": "partial",
            "rows_sent": 2,
            **changes,
        }
    )


def _reply(revision: int = 1, **changes: Any) -> dict[str, object]:
    return {"workspacePreferences": _wire(revision, **changes), "receiptSyncAccepted": True}


def _candidate(
    cursor: int | None = 12, marker: receipts.ReceiptBackfillMarker | None = None
) -> receipts.ReceiptProgressCandidate:
    return receipts.ReceiptProgressCandidate(cursor, marker, NOW)


def _complete(
    store: GuardStore,
    attempt: receipts.ReceiptSyncAttempt,
    *,
    candidate: receipts.ReceiptProgressCandidate | None = None,
    payload: object = None,
) -> receipts.ReceiptSyncCompletion:
    return receipts.accept_receipt_sync_response(
        store,
        attempt,
        _reply() if payload is None else payload,
        candidate=_candidate() if candidate is None else candidate,
    )


def _raw_rows(store: GuardStore) -> list[tuple[str, str, str]]:
    with store._connect() as connection:
        return [
            tuple(row)
            for row in connection.execute(
                "select state_key, payload_json, updated_at from sync_state "
                "where state_key in (?, ?, ?, ?) or state_key like 'workspace_preference_%' order by state_key",
                (CURSOR, BACKFILL, REDACTION, RELAXATION),
            )
        ]


def test_capture_uses_selected_source_and_copied_exact_rows(tmp_path: Path) -> None:
    store, inputs = _ready(tmp_path, source="secondary")
    store.set_sync_payload(CURSOR, {"last_rowid": " 4 ", "synced_at": NOW}, NOW)
    captured = receipts.capture_receipt_sync_state(store)
    assert captured.preference_state.connection.credential_key.endswith(":secondary")
    assert captured.rows.cursor is not None
    assert captured.rows.backfill is None and captured.rows.redaction is None and captured.rows.relaxation is None
    decoded = captured.rows.cursor.payload()
    assert isinstance(decoded, dict)
    decoded["last_rowid"] = 999
    assert captured.rows.cursor.payload() == {"last_rowid": " 4 ", "synced_at": NOW}
    for value in (inputs["refresh_token"], inputs["dpop_private_key_pem"], WORKSPACE):
        assert value not in repr(captured) and value not in repr(captured.rows)
    other = GuardStore(store.guard_home, allow_system_keyring=False)
    other.set_oauth_local_credentials(**inputs)
    with pytest.raises(ValueError, match="source_changed"):
        receipts.capture_receipt_sync_state(other, required_connection=captured.preference_state.connection)


def test_negotiated_progress_returns_new_expected_rows_and_refuses_reused_capture(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    first_attempt = _attempt(store)
    result = _complete(store, first_attempt, candidate=_candidate(marker=_marker()))
    assert result.preference_accepted and result.receipt_acknowledged and result.progress_committed
    assert result.capture.rows.cursor is not None
    assert result.capture.rows.cursor.payload() == {"last_rowid": 12, "synced_at": NOW}
    assert result.capture.rows.backfill is not None and result.capture.rows.backfill.payload() == _marker().to_payload()
    stale = _complete(store, first_attempt, candidate=_candidate(20))
    assert stale.receipt_acknowledged and not stale.progress_committed
    following = _complete(store, replace(first_attempt, capture=result.capture), candidate=_candidate(20))
    assert following.progress_committed
    assert store.get_sync_payload(CURSOR) == {"last_rowid": 20, "synced_at": NOW}


def test_later_preference_is_learned_without_old_revision_progress(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    store.set_sync_payload(CURSOR, {"last_rowid": 4}, NOW)
    attempt = _attempt(store)
    result = _complete(store, attempt, payload=_reply(2))
    assert result.preference_accepted and not result.receipt_acknowledged and not result.progress_committed
    assert result.capture.preference_state.preferences is not None
    assert result.capture.preference_state.preferences.revision == 2
    assert result.capture.rows == attempt.capture.rows
    assert store.get_sync_payload(CURSOR) == {"last_rowid": 4}


@pytest.mark.parametrize("key", [CURSOR, BACKFILL, REDACTION, RELAXATION])
def test_changed_progress_row_learns_preference_but_refuses_acknowledged_candidate(tmp_path: Path, key: str) -> None:
    store, _ = _ready(tmp_path)
    values = {
        CURSOR: {"last_rowid": 4},
        BACKFILL: _marker(before_rowid=50).to_payload(),
        REDACTION: {"level": "partial"},
        RELAXATION: {"level": "partial"},
    }
    store.set_sync_payload(key, values[key], NOW)
    attempt = _attempt(store, sent_revision=2)
    replacements = {
        CURSOR: {"last_rowid": 0},
        BACKFILL: _marker(before_rowid=80).to_payload(),
        REDACTION: {"level": "full"},
        RELAXATION: {"level": "none"},
    }
    store.set_sync_payload(key, replacements[key], LATER)
    result = _complete(store, attempt, payload=_reply(2), candidate=_candidate(marker=_marker()))
    assert result.preference_accepted and result.receipt_acknowledged and not result.progress_committed
    assert result.capture.preference_state.preferences is not None
    assert result.capture.preference_state.preferences.revision == 2
    assert store.get_sync_payload(key) == replacements[key]
    assert result.capture.rows != attempt.capture.rows


@pytest.mark.parametrize("change", ["json-bytes", "updated-at"])
def test_cas_compares_raw_json_and_updated_at_even_when_payload_is_equal(tmp_path: Path, change: str) -> None:
    store, _ = _ready(tmp_path)
    store.set_sync_payload(CURSOR, {"last_rowid": 4}, NOW)
    attempt = _attempt(store)
    with store._connect() as connection:
        if change == "json-bytes":
            connection.execute(
                "update sync_state set payload_json = ? where state_key = ?", ('{"last_rowid":4}', CURSOR)
            )
        else:
            connection.execute("update sync_state set updated_at = ? where state_key = ?", (LATER, CURSOR))
    result = _complete(store, attempt)
    assert result.receipt_acknowledged and not result.progress_committed
    assert result.capture.rows.cursor is not None and attempt.capture.rows.cursor is not None
    assert result.capture.rows.cursor.payload() == attempt.capture.rows.cursor.payload()
    assert result.capture.rows.cursor != attempt.capture.rows.cursor


@pytest.mark.parametrize(
    "raw",
    [
        '{"last_rowid":true}',
        '{"last_rowid":4,"unexpected":true}',
        '{"last_rowid":4,"last_rowid":4}',
        "null",
        "[4]",
        "{",
        '{"last_rowid":NaN}',
    ],
)
def test_malformed_existing_progress_does_not_block_valid_preference_learning(tmp_path: Path, raw: str) -> None:
    store, _ = _ready(tmp_path)
    with store._connect() as connection:
        connection.execute("insert into sync_state values (?, ?, ?)", (CURSOR, raw, NOW))
    attempt = _attempt(store, sent_revision=2)
    result = _complete(store, attempt, payload=_reply(2))
    assert result.preference_accepted and result.receipt_acknowledged and not result.progress_committed
    assert result.capture.preference_state.preferences is not None
    assert result.capture.preference_state.preferences.revision == 2
    assert result.capture.rows.cursor is not None and result.capture.rows.cursor.payload_json == raw


def test_absence_is_distinct_from_present_null_and_legacy_numeric_rows_remain_usable(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    absent = _attempt(store)
    with store._connect() as connection:
        connection.execute("insert into sync_state values (?, ?, ?)", (CURSOR, "null", NOW))
    assert not _complete(store, absent).progress_committed
    store.set_sync_payload(CURSOR, {"last_rowid": " 4 "}, NOW)
    marker = _marker().to_payload()
    marker["before_rowid"] = " 7 "
    store.set_sync_payload(BACKFILL, marker, NOW)
    assert _complete(store, _attempt(store)).progress_committed


def test_fault_after_preference_and_cursor_writes_rolls_everything_back(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    store.set_sync_payload(CURSOR, {"last_rowid": 4}, NOW)
    attempt = _attempt(store, sent_revision=2)
    before = _raw_rows(store)
    with store._connect() as connection:
        connection.execute(
            "create trigger reject_backfill before insert on sync_state "
            "when NEW.state_key = 'cloud_receipt_command_detail_backfill_v2' "
            "begin select raise(abort, 'synthetic atomic rollback'); end"
        )
    with pytest.raises(sqlite3.IntegrityError, match="atomic rollback"):
        _complete(store, attempt, payload=_reply(2), candidate=_candidate(marker=_marker()))
    assert _raw_rows(store) == before


@pytest.mark.parametrize("mutation", ["replacement", "clear", "subprocess-replacement"])
def test_actual_connection_mutations_reject_old_response_without_any_progress(tmp_path: Path, mutation: str) -> None:
    store, inputs = _ready(tmp_path)
    store.set_sync_payload(CURSOR, {"last_rowid": 4}, NOW)
    attempt = _attempt(store)
    if mutation == "replacement":
        store.set_oauth_local_credentials(**inputs)
    elif mutation == "clear":
        store.clear_oauth_local_credentials()
    else:
        script = (
            "from pathlib import Path\nimport sys\n"
            "from codex_plugin_scanner.guard.store import GuardStore\n"
            "store=GuardStore(Path(sys.argv[1]),allow_system_keyring=False)\n"
            "key=store._oauth_local_credentials_state_key\n"
            "store.set_sync_payload(key,store.get_sync_payload(key),sys.argv[2])\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, str(store.guard_home), NOW],
            check=False,
            capture_output=True,
            timeout=15,
        )
        assert completed.returncode == 0, completed.stderr.decode()
    before = _raw_rows(store)
    with pytest.raises(ValueError, match="source_changed"):
        _complete(store, attempt)
    assert _raw_rows(store) == before


def test_same_authority_token_refresh_allows_original_progress(tmp_path: Path) -> None:
    store, inputs = _ready(tmp_path)
    attempt = _attempt(store)
    store.set_oauth_local_credentials(
        **{**inputs, "access_token": "refreshed-access", "refresh_token": "refreshed-refresh"},
        expected_connection=attempt.capture.preference_state.connection,
    )
    result = _complete(store, attempt)
    assert result.progress_committed
    assert result.capture.preference_state.connection.same_authority(attempt.capture.preference_state.connection)
    assert result.capture.preference_state.connection.credentials()["access_token"] == "refreshed-access"


def test_same_sql_source_check_refuses_epoch_change_after_initial_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _ready(tmp_path)
    attempt = _attempt(store)
    before = _raw_rows(store)
    original = preferences._current_source

    def changing(target: GuardStore, required: object) -> object:
        current = original(target, required)
        with target._connect() as connection:
            advance_connection_epoch(connection, current.credential_key, NOW)
        return current

    monkeypatch.setattr(preferences, "_current_source", changing)
    with pytest.raises(ValueError, match="source_changed"):
        _complete(store, attempt)
    assert _raw_rows(store) == before


@pytest.mark.parametrize("mutation", ["withdraw", "local-redaction", "signed-redaction"])
def test_current_local_and_signed_restrictions_refuse_progress_without_losing_preference(
    tmp_path: Path, mutation: str
) -> None:
    store, _ = _ready(tmp_path)
    attempt = _attempt(store, sent_revision=2)
    if mutation == "signed-redaction":
        bundle = _signed_policy_bundle()
        bundle["receiptRedactionLevel"] = "full"
        store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id=WORKSPACE), NOW)
        store.set_sync_payload("policy_bundle", sign_policy_bundle(bundle, workspace_id=WORKSPACE), NOW)
        validated = validated_synced_policy_bundle(store)
        assert validated is not None and validated["receiptRedactionLevel"] == "full"
    else:
        (store.guard_home / "config.toml").write_text(
            'sync = false\nreceipt_redaction_level = "none"\n'
            if mutation == "withdraw"
            else 'sync = true\nreceipt_redaction_level = "full"\n'
        )
    result = _complete(store, attempt, payload=_reply(2))
    assert result.preference_accepted and result.receipt_acknowledged and not result.progress_committed
    assert result.capture.preference_state.preferences is not None
    assert result.capture.preference_state.preferences.revision == 2
    assert store.get_sync_payload(CURSOR) is None


@pytest.mark.parametrize("optional", [False, True])
def test_empty_final_attempt_cannot_borrow_selected_cursor_or_marker(tmp_path: Path, optional: bool) -> None:
    store, _ = _ready(tmp_path)
    attempt = _attempt(store, rows_sent=0, optional_allowed=optional)
    result = _complete(store, attempt, candidate=_candidate(marker=_marker(complete=True)))
    assert result.preference_accepted and result.receipt_acknowledged and not result.progress_committed
    assert store.get_sync_payload(CURSOR) is None and store.get_sync_payload(BACKFILL) is None


def test_authorized_empty_exhaustion_commits_only_explicit_empty_marker(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    store.set_sync_payload(CURSOR, {"last_rowid": 4}, NOW)
    store.set_sync_payload(BACKFILL, _marker(before_rowid=7).to_payload(), NOW)
    attempt = _attempt(store, rows_sent=0, authorized_empty_exhaustion=True)
    marker = _marker(receipts=0, queried=0, before_rowid=7, complete=True)
    result = _complete(store, attempt, candidate=_candidate(None, marker))
    assert result.progress_committed and result.receipt_acknowledged
    assert store.get_sync_payload(CURSOR) == {"last_rowid": 4}
    assert store.get_sync_payload(BACKFILL) == marker.to_payload()
    for candidate in [_candidate(12, marker), _candidate(None, _marker(complete=True)), _candidate(None)]:
        current = replace(attempt, capture=result.capture)
        assert not _complete(store, current, candidate=candidate).progress_committed


def test_legacy_confirmation_and_progress_preserve_existing_acknowledgement(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    initial = _attempt(store, sent_revision=None, redaction_level="none")
    response = {"syncedAt": NOW, "receiptsStored": 2}
    unconfirmed = _complete(store, initial, payload=response)
    assert unconfirmed.receipt_acknowledged and not unconfirmed.progress_committed
    assert unconfirmed.capture.preference_state.mode == "legacy"
    confirmed = replace(initial, capture=unconfirmed.capture)
    assert _complete(store, confirmed, payload=response).progress_committed


def test_response_and_candidate_are_copied_before_waiting_for_credential_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _ready(tmp_path)
    attempt = _attempt(store)
    payload = _reply()
    candidate = _candidate()
    original = store.hold_oauth_credential_lock

    @contextmanager
    def mutate_after_copy(**kwargs: Any) -> Iterator[None]:
        wire = payload["workspacePreferences"]
        assert isinstance(wire, dict)
        wire["revision"] = 999
        object.__setattr__(candidate, "cursor_rowid", 999)
        with original(**kwargs):
            yield

    monkeypatch.setattr(store, "hold_oauth_credential_lock", mutate_after_copy)
    result = _complete(store, attempt, payload=payload, candidate=candidate)
    assert result.progress_committed
    assert store.get_sync_payload(CURSOR) == {"last_rowid": 12, "synced_at": NOW}
    assert result.capture.preference_state.preferences is not None
    assert result.capture.preference_state.preferences.revision == 1


def test_completion_captures_under_credential_lock_before_only_final_sql_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _ready(tmp_path)
    attempt = _attempt(store)
    events: list[str] = []
    original_lock = store.hold_oauth_credential_lock
    original_capture = store._capture_oauth_connection_unlocked
    original_connect = store._connect
    active = False

    @contextmanager
    def lock(**kwargs: Any) -> Iterator[None]:
        nonlocal active
        assert not kwargs
        with original_lock(**kwargs):
            active = True
            events.append("lock")
            try:
                yield
            finally:
                active = False
                events.append("unlock")

    def capture(**kwargs: Any) -> object:
        assert active and "begin immediate" not in events
        events.append("capture")
        return original_capture(**kwargs)

    @contextmanager
    def connect() -> Iterator[sqlite3.Connection]:
        with original_connect() as connection:

            def trace(sql: str) -> None:
                if sql.lower() == "begin immediate":
                    assert active
                    events.append(sql.lower())

            connection.set_trace_callback(trace)
            yield connection

    monkeypatch.setattr(store, "hold_oauth_credential_lock", lock)
    monkeypatch.setattr(store, "_capture_oauth_connection_unlocked", capture)
    monkeypatch.setattr(store, "_connect", connect)
    assert _complete(store, attempt).progress_committed
    assert events == ["lock", "capture", "begin immediate", "unlock"]


class _String(str):
    pass


@pytest.mark.parametrize(
    "field,value",
    [
        ("level", _String("partial")),
        ("updated_at", _String(NOW)),
        ("days", True),
        ("limit", "200"),
        ("receipts", True),
        ("queried", 201),
        ("before_rowid", True),
        ("complete", 1),
        ("unknown", 0),
    ],
)
def test_marker_rejects_ambiguous_and_unknown_fields(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        _marker(**{field: value})


def test_marker_copies_payload_and_rejects_mutable_or_subclass_inputs() -> None:
    payload = _marker().to_payload()
    copied = receipts.ReceiptBackfillMarker.from_payload(payload)
    payload["before_rowid"] = 999
    assert copied.before_rowid == 7
    rendered = copied.to_payload()
    rendered["queried"] = 999
    assert copied.queried == 2
    with pytest.raises(ValueError):
        receipts.ReceiptStateRow(bytearray(b"{}"), NOW)
    with pytest.raises(ValueError):
        receipts.ReceiptStateRow("{}", _String(NOW))
    with pytest.raises(ValueError):
        receipts.ReceiptProgressCandidate(True, None, NOW)
    with pytest.raises(ValueError):
        receipts.ReceiptProgressCandidate(1, {"complete": True}, NOW)


@pytest.mark.parametrize(
    "changes",
    [
        {"sent_revision": True},
        {"rows_sent": True},
        {"optional_allowed": 1},
        {"redaction_level": _String("partial")},
        {"authorized_empty_exhaustion": 1},
        {"authorized_empty_exhaustion": True},
        {"rows_sent": -1},
    ],
)
def test_attempt_rejects_ambiguous_permission_and_count_inputs(tmp_path: Path, changes: dict[str, object]) -> None:
    store, _ = _ready(tmp_path)
    with pytest.raises(ValueError):
        _attempt(store, **changes)


def test_capture_rejects_nested_mutable_or_subclass_aliases(tmp_path: Path) -> None:
    store, _ = _ready(tmp_path)
    captured = receipts.capture_receipt_sync_state(store)
    state = captured.preference_state
    with pytest.raises(ValueError):
        receipts.ReceiptSyncCapture(replace(state, mode=_String(state.mode)), captured.rows)
    assert state.preferences is not None
    with pytest.raises(ValueError):
        receipts.ReceiptSyncCapture(
            replace(state, preferences=replace(state.preferences, sync_enabled=[])), captured.rows
        )
