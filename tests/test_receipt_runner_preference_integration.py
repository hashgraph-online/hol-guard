"""Proposed actual-runner receipt controls; not validated until executed on the bound source."""

from __future__ import annotations

import hashlib
import io
import json
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import receipt_sync_authority as authority
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import validated_synced_policy_bundle
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle
from tests.test_guard_receipt_redaction_cursor import _store_blocked_command_receipt
from tests.test_synced_policy import _signed_policy_bundle
from tests.test_workspace_preference_authority import NOW, WORKSPACE, _accept, _store, _wire

CURSOR = "receipt_sync_cursor"
BACKFILL = "cloud_receipt_command_detail_backfill_v2"
REDACTION = "cloud_receipt_redaction_level"
RELAXATION = "cloud_receipt_redaction_relaxed_resync_v1"
LATER = "2026-06-01T00:00:01+00:00"
CONTRACT = "guard.workspace-preferences.v1"


def _settings(store: GuardStore, *, sync: bool = True, telemetry: bool = False, redaction: str = "none") -> None:
    (store.guard_home / "config.toml").write_text(
        f'sync = {str(sync).lower()}\ntelemetry = {str(telemetry).lower()}\nreceipt_redaction_level = "{redaction}"\n',
        encoding="utf-8",
    )


def _rows(
    store: GuardStore, count: int, *, commands: bool = True, recent_commands: bool = False
) -> list[dict[str, Any]]:
    for index in range(count):
        receipt_id = f"runner-control-{index:04d}"
        if commands and not recent_commands:
            _store_blocked_command_receipt(store, receipt_id)
        else:
            # Fresh command rows exercise the real bounded backfill query; plain rows isolate cursor replay.
            store.add_receipt(
                GuardReceipt(
                    receipt_id=receipt_id,
                    timestamp=datetime.now(timezone.utc).isoformat() if commands else NOW,
                    harness="synthetic-harness",
                    artifact_id=receipt_id,
                    artifact_hash=hashlib.sha256(receipt_id.encode()).hexdigest(),
                    policy_decision="review",
                    capabilities_summary="synthetic capability summary",
                    changed_capabilities=(),
                    provenance_summary="synthetic",
                    raw_command_text="printf synthetic" if commands else None,
                ),
                action_envelope=(
                    GuardActionEnvelope(
                        schema_version=1,
                        action_id=receipt_id,
                        harness="codex",
                        event_name="PreToolUse",
                        action_type="shell_command",
                        workspace=None,
                        workspace_hash="synthetic-workspace",
                        tool_name="bash",
                        command="printf synthetic",
                        prompt_excerpt=None,
                        prompt_text=None,
                        target_paths=(),
                        network_hosts=(),
                        mcp_server=None,
                        mcp_tool=None,
                        package_manager=None,
                        package_name=None,
                        package_intent_kind=None,
                        package_targets=(),
                    )
                    if commands
                    else None
                ),
            )
    values = sorted(store.list_receipts(limit=count + 1), key=_receipt_rowid)
    assert len(values) == count
    return values


def _receipt_rowid(row: dict[str, object]) -> int:
    value = row["receipt_rowid"]
    assert type(value) is int
    return value


def _receipt_ids(rows: list[dict[str, Any]]) -> list[str]:
    return [row["receipt_id"] for row in rows]


class _Response:
    def __init__(self, payload: dict[str, Any], *, before_read: Callable[[], None] | None = None) -> None:
        self.status = 200
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"
        self._stream = io.BytesIO(json.dumps(payload).encode())
        self._before_read = before_read

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def read(self, size: int = -1) -> bytes:
        callback, self._before_read = self._before_read, None
        if callback is not None:
            callback()
        return self._stream.read(size)

    def getcode(self) -> int:
        return self.status

    def close(self) -> None:
        self._stream.close()


class _Transport:
    """Intercept the existing transport without replacing auth, selection, or completion."""

    def __init__(self, *, revision: int = 1, redaction: str = "full", telemetry: bool = False) -> None:
        self.revision = revision
        self.redaction = redaction
        self.telemetry = telemetry
        self.calls: list[dict[str, Any]] = []
        self.receipt_calls: list[dict[str, Any]] = []
        self.receipt_handler: Callable[[dict[str, Any], int], _Response | BaseException] | None = None

    def reply(
        self,
        body: dict[str, Any],
        *,
        revision: int | None = None,
        before_read: Callable[[], None] | None = None,
        **extra: Any,
    ) -> _Response:
        return _Response(
            {
                "syncedAt": NOW,
                "workspacePreferences": _wire(
                    self.revision if revision is None else revision,
                    telemetry=self.telemetry,
                    redaction=self.redaction,
                ),
                "receiptSyncAccepted": True,
                "receiptsStored": len(body["receipts"]),
                **extra,
            },
            before_read=before_read,
        )

    def __call__(self, request: urllib.request.Request, *args: Any, **kwargs: Any) -> _Response:
        assert isinstance(request, urllib.request.Request)
        assert isinstance(request.data, bytes)
        body = json.loads(request.data)
        assert type(body) is dict
        recorded = {
            "body": body,
            "method": request.get_method(),
            "headers": {key.lower(): value for key, value in request.header_items()},
        }
        self.calls.append(recorded)
        if "session" in body:
            recorded["kind"] = "session"
            return _Response({"syncedAt": NOW})
        assert "receipts" in body, f"unexpected optional request keys: {sorted(body)}"
        assert type(body["receipts"]) is list
        recorded["kind"] = "receipts"
        self.receipt_calls.append(recorded)
        if self.receipt_handler is not None:
            response = self.receipt_handler(body, len(self.receipt_calls))
            if isinstance(response, BaseException):
                raise response
            return response
        return self.reply(body)

    def sent_ids(self, *, since: int = 0) -> list[str]:
        return [
            receipt["receiptId"] for request in self.receipt_calls[since:] for receipt in request["body"]["receipts"]
        ]


@pytest.fixture
def _local_runtime(monkeypatch: pytest.MonkeyPatch) -> Callable[[_Transport], None]:
    def deny_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("unexpected raw network access")

    # Copy the module namespace: do not mutate the process-wide time module.
    # The original monotonic, sleep, and operation budgets remain intact.
    original_sleep = time.sleep
    monkeypatch.setattr(runner, "time", SimpleNamespace(**vars(time)))
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda *args, **kwargs: False)
    monkeypatch.setattr(runner, "_safe_private_ip", lambda: None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(urllib.request, "urlopen", deny_network)
    assert time.sleep is original_sleep

    def install(transport: _Transport) -> None:
        monkeypatch.setattr(runner, "managed_urlopen", transport)

    return install


def _invoke(
    store: GuardStore,
    entrypoint: str = "receipts",
    *,
    auth_context: dict[str, object] | None = None,
) -> object:
    if entrypoint == "proof":
        return runner.sync_local_guard_cloud_proof(store, auth_context=auth_context)
    assert entrypoint == "receipts"
    return runner.sync_receipts(store, auth_context=auth_context)


def _ordinary_auth(store: GuardStore) -> dict[str, object]:
    context = runner._resolve_guard_sync_auth_context(store)
    assert type(context) is dict
    assert set(context) == {"sync_url", "access_token", "dpop_key_material"}
    return dict(context)


def _ready(
    tmp_path: Path, *, source: str = "default", redaction: str = "full", telemetry: bool = False
) -> tuple[GuardStore, dict[str, Any]]:
    store, inputs = _store(tmp_path, source=source)
    _settings(store)
    _accept(store, _wire(telemetry=telemetry, redaction=redaction))
    return store, inputs


def _cursor(store: GuardStore) -> int | None:
    value = store.get_sync_payload(CURSOR)
    if value is None:
        return None
    assert isinstance(value, dict)
    rowid = value["last_rowid"]
    assert type(rowid) is int
    return rowid


@pytest.mark.parametrize("source", ["default", "secondary"])
@pytest.mark.parametrize("entrypoint", ["receipts", "proof"])
@pytest.mark.parametrize("provided", [False, True])
def test_real_entrypoints_negotiate_before_uploading_from_actual_source(
    tmp_path: Path,
    _local_runtime: Callable[[_Transport], None],
    source: str,
    entrypoint: str,
    provided: bool,
) -> None:
    store, _ = _store(tmp_path, source=source)
    _settings(store)
    rows = _rows(store, 3)
    transport = _Transport()
    _local_runtime(transport)
    auth = _ordinary_auth(store) if provided else None

    _invoke(store, entrypoint, auth_context=auth)
    assert len(transport.receipt_calls) == 1
    first = transport.receipt_calls[0]["body"]
    assert first["receipts"] == []
    assert first["syncContext"]["workspacePreferencesContract"] == CONTRACT
    assert "workspacePreferenceRevision" not in first["syncContext"]
    assert _cursor(store) is None
    learned = authority.capture_receipt_sync_state(store).preference_state
    assert learned.preferences is not None and learned.preferences.revision == 1
    assert learned.connection.credential_key.endswith(f":{source}") if source != "default" else True

    _invoke(store, entrypoint, auth_context=auth)
    assert len(transport.receipt_calls) == 2
    assert transport.sent_ids(since=1) == _receipt_ids(rows)
    assert transport.receipt_calls[1]["body"]["syncContext"]["workspacePreferenceRevision"] == 1
    assert _cursor(store) == rows[-1]["receipt_rowid"]
    expected_kinds = ["session", "receipts"] if entrypoint == "proof" else ["receipts"]
    assert [call["kind"] for call in transport.calls] == expected_kinds * 2


@pytest.mark.parametrize("source", ["default", "secondary"])
def test_more_than_one_page_advances_in_ascending_order_without_omissions_or_replay(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None], source: str
) -> None:
    store, _ = _ready(tmp_path, source=source)
    rows = _rows(store, 205)
    transport = _Transport()
    _local_runtime(transport)
    auth = _ordinary_auth(store)

    _invoke(store, auth_context=auth)
    first_boundary = len(transport.receipt_calls)
    assert transport.sent_ids() == _receipt_ids(rows[:200])
    assert _cursor(store) == rows[199]["receipt_rowid"]

    _invoke(store, auth_context=auth)
    assert transport.sent_ids(since=first_boundary) == _receipt_ids(rows[200:])
    assert _cursor(store) == rows[-1]["receipt_rowid"]
    assert len(transport.sent_ids()) == len(set(transport.sent_ids())) == 205

    exhausted_boundary = len(transport.receipt_calls)
    _invoke(store, auth_context=auth)
    assert transport.sent_ids(since=exhausted_boundary) == []
    assert _cursor(store) == rows[-1]["receipt_rowid"]


def _nonce_challenge() -> urllib.error.HTTPError:
    headers = Message()
    headers["DPoP-Nonce"] = "synthetic-next-nonce"
    return urllib.error.HTTPError(
        "https://example.invalid/receipts",
        401,
        "synthetic nonce challenge",
        headers,
        io.BytesIO(b'{"error":"use_dpop_nonce"}'),
    )


def test_final_real_retry_withdrawal_stops_all_remaining_selected_batches(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None]
) -> None:
    store, _ = _ready(tmp_path)
    _rows(store, 205)
    transport = _Transport()
    _local_runtime(transport)

    def respond(body: dict[str, Any], number: int) -> _Response | BaseException:
        if number == 1:
            assert len(body["receipts"]) > 0
            _settings(store, sync=False)
            return _nonce_challenge()
        assert number == 2
        assert body["receipts"] == []
        assert body["syncContext"]["workspacePreferenceRevision"] == 1
        return transport.reply(body)

    transport.receipt_handler = respond
    _invoke(store)
    assert len(transport.receipt_calls) == 2
    assert transport.receipt_calls[-1]["body"]["receipts"] == []
    assert _cursor(store) is None
    marker = store.get_sync_payload(BACKFILL)
    assert marker is None or (isinstance(marker, dict) and marker["complete"] is False)


def test_acknowledged_first_batch_cannot_complete_backfill_after_later_empty_retry(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None]
) -> None:
    store, _ = _ready(tmp_path, redaction="partial")
    rows = _rows(store, 125, recent_commands=True)
    queried = store.list_receipts_for_command_detail_backfill(
        limit=runner._RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT,
        days=runner._RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS,
        before_rowid=None,
    )
    assert len(queried) == 125
    assert set(_receipt_ids(queried)) == set(_receipt_ids(rows))
    store.set_sync_payload(CURSOR, {"last_rowid": rows[74]["receipt_rowid"], "synced_at": NOW}, NOW)
    store.set_sync_payload(REDACTION, {"level": "partial", "updated_at": NOW}, NOW)
    store.set_sync_payload(RELAXATION, {"level": "partial", "updated_at": NOW}, NOW)
    transport = _Transport(redaction="partial")
    _local_runtime(transport)

    def respond(body: dict[str, Any], number: int) -> _Response | BaseException:
        if number == 1:
            assert [item["receiptId"] for item in body["receipts"]] == _receipt_ids(rows[75:])
            return transport.reply(body)
        if number == 2:
            assert body["receipts"]
            _settings(store, sync=False)
            return _nonce_challenge()
        assert number == 3
        assert body["receipts"] == []
        return transport.reply(body)

    transport.receipt_handler = respond
    _invoke(store)
    assert len(transport.receipt_calls) == 3
    first_ids = {receipt["receiptId"] for receipt in transport.receipt_calls[0]["body"]["receipts"]}
    actual_rows = store.list_receipts(limit=200)
    acknowledged_rowids = [_receipt_rowid(row) for row in actual_rows if row["receipt_id"] in first_ids]
    assert acknowledged_rowids and _cursor(store) == max(acknowledged_rowids)
    marker = store.get_sync_payload(BACKFILL)
    assert marker is None or (isinstance(marker, dict) and marker["complete"] is False)
    assert _cursor(store) == rows[-1]["receipt_rowid"]
    retry_boundary = len(transport.receipt_calls)
    _settings(store)
    transport.receipt_handler = None
    _invoke(store)
    retried_ids = set(transport.sent_ids(since=retry_boundary))
    assert set(_receipt_ids(rows[:75])) <= retried_ids
    assert _cursor(store) == rows[-1]["receipt_rowid"]
    completed_marker = store.get_sync_payload(BACKFILL)
    assert isinstance(completed_marker, dict) and completed_marker["complete"] is True


def test_newer_response_revision_is_learned_without_old_progress_or_later_batches(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None]
) -> None:
    store, _ = _ready(tmp_path)
    rows = _rows(store, 205)
    transport = _Transport(revision=2)
    _local_runtime(transport)

    _invoke(store)
    assert len(transport.receipt_calls) == 1
    assert transport.receipt_calls[0]["body"]["receipts"]
    assert transport.receipt_calls[0]["body"]["syncContext"]["workspacePreferenceRevision"] == 1
    assert _cursor(store) is None
    learned = authority.capture_receipt_sync_state(store).preference_state.preferences
    assert learned is not None and learned.revision == 2

    boundary = len(transport.receipt_calls)
    _invoke(store)
    assert transport.sent_ids(since=boundary) == _receipt_ids(rows[:200])
    assert all(
        call["body"]["syncContext"]["workspacePreferenceRevision"] == 2 for call in transport.receipt_calls[boundary:]
    )
    assert _cursor(store) == rows[199]["receipt_rowid"]


def test_external_cursor_zero_written_during_response_read_survives_completion(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None]
) -> None:
    store, _ = _ready(tmp_path)
    rows = _rows(store, 75)
    store.set_sync_payload(CURSOR, {"last_rowid": rows[0]["receipt_rowid"], "synced_at": NOW}, NOW)
    transport = _Transport()
    _local_runtime(transport)
    replacement = {"last_rowid": 0, "synced_at": LATER}

    def respond(body: dict[str, Any], number: int) -> _Response:
        assert number == 1
        assert body["receipts"]
        return transport.reply(body, before_read=lambda: store.set_sync_payload(CURSOR, replacement, LATER))

    transport.receipt_handler = respond
    _invoke(store)
    assert len(transport.receipt_calls) == 1
    assert store.get_sync_payload(CURSOR) == replacement
    state = authority.capture_receipt_sync_state(store)
    assert state.rows.cursor is not None and state.rows.cursor.updated_at == LATER
    assert state.preference_state.preferences is not None
    assert state.preference_state.preferences.revision == 1


@pytest.mark.parametrize("source", ["default", "secondary"])
def test_source_replacement_during_response_read_never_commits_selected_progress(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None], source: str
) -> None:
    store, inputs = _ready(tmp_path, source=source)
    _rows(store, 75)
    before = authority.capture_receipt_sync_state(store).preference_state.connection
    auth = _ordinary_auth(store)
    transport = _Transport()
    _local_runtime(transport)

    def respond(body: dict[str, Any], number: int) -> _Response:
        assert number == 1
        assert body["receipts"]

        def replace_connection() -> None:
            store.set_oauth_local_credentials(**inputs)

        return transport.reply(body, before_read=replace_connection)

    transport.receipt_handler = respond
    with pytest.raises(RuntimeError, match="connection changed"):
        _invoke(store, auth_context=auth)
    assert len(transport.receipt_calls) == 1
    assert _cursor(store) is None
    after = authority.capture_receipt_sync_state(store).preference_state.connection
    assert not after.same_authority(before)


@pytest.mark.parametrize("local_telemetry,remote_telemetry", [(False, True), (True, False), (False, False)])
def test_either_telemetry_withdrawal_avoids_extra_optional_requests(
    tmp_path: Path,
    _local_runtime: Callable[[_Transport], None],
    local_telemetry: bool,
    remote_telemetry: bool,
) -> None:
    store, _ = _ready(tmp_path, telemetry=remote_telemetry)
    _settings(store, telemetry=local_telemetry)
    rows = _rows(store, 2)
    transport = _Transport(telemetry=remote_telemetry)
    _local_runtime(transport)

    _invoke(store, "proof", auth_context=_ordinary_auth(store))
    assert [call["kind"] for call in transport.calls] == ["session", "receipts"]
    assert transport.sent_ids() == _receipt_ids(rows)
    assert _cursor(store) == rows[-1]["receipt_rowid"]


@pytest.mark.parametrize("optional_failure", ["new-revision", "optional-ledger"])
def test_signed_control_is_processed_after_optional_completion_is_declined(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None], optional_failure: str
) -> None:
    store, _ = _ready(tmp_path)
    _rows(store, 75)
    store.set_sync_payload("policy_bundle_keyring", policy_bundle_test_keyring(workspace_id=WORKSPACE), NOW)
    unsigned = _signed_policy_bundle()
    unsigned["receiptRedactionLevel"] = "partial"
    signed = sign_policy_bundle(unsigned, workspace_id=WORKSPACE)
    transport = _Transport(revision=2 if optional_failure == "new-revision" else 1)
    _local_runtime(transport)
    if optional_failure == "optional-ledger":
        with store._connect() as connection:
            connection.execute(
                "create trigger reject_optional_preference before insert on sync_state "
                "when NEW.state_key like 'workspace_preference_authority:%' "
                "begin select raise(abort, 'synthetic optional preference failure'); end"
            )

    def respond(body: dict[str, Any], number: int) -> _Response:
        assert number == 1
        return transport.reply(body, policyBundle=signed)

    transport.receipt_handler = respond
    _invoke(store)
    assert len(transport.receipt_calls) == 1
    assert _cursor(store) is None
    accepted = validated_synced_policy_bundle(store)
    assert accepted is not None and accepted["receiptRedactionLevel"] == "partial"


def test_partial_redaction_without_signed_policy_keeps_relaxation_progress_between_syncs(
    tmp_path: Path, _local_runtime: Callable[[_Transport], None]
) -> None:
    store, _ = _ready(tmp_path, redaction="partial")
    rows = _rows(store, 405, commands=False)
    assert store.get_sync_payload("policy_bundle") is None
    assert all(not row.get("raw_command_text") and not row.get("action_envelope") for row in rows)
    # A previous stricter upload requires one bounded replay when consent relaxes.
    store.set_sync_payload(REDACTION, {"level": "full", "updated_at": NOW}, NOW)
    store.set_sync_payload(CURSOR, {"last_rowid": rows[-1]["receipt_rowid"], "synced_at": NOW}, NOW)
    transport = _Transport(redaction="partial")
    _local_runtime(transport)

    _invoke(store)
    first_boundary = len(transport.receipt_calls)
    assert transport.sent_ids() == _receipt_ids(rows[:200])
    assert _cursor(store) == rows[199]["receipt_rowid"]
    assert store.get_sync_payload(RELAXATION) is not None

    _invoke(store)
    second_boundary = len(transport.receipt_calls)
    assert transport.sent_ids(since=first_boundary) == _receipt_ids(rows[200:400])
    assert _cursor(store) == rows[399]["receipt_rowid"]
    assert store.get_sync_payload(RELAXATION) is not None

    _invoke(store)
    assert transport.sent_ids(since=second_boundary) == _receipt_ids(rows[400:])
    assert _cursor(store) == rows[-1]["receipt_rowid"]
    assert len(transport.sent_ids()) == len(set(transport.sent_ids())) == 405
    assert store.get_sync_payload("policy_bundle") is None
