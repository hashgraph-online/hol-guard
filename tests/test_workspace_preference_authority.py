"""Optional consent remains bound to actual durable connection authority."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from codex_plugin_scanner.guard import workspace_preference_authority as authority
from codex_plugin_scanner.guard.oauth_connection_authority import advance_connection_epoch
from codex_plugin_scanner.guard.runtime.workspace_preferences import (
    effective_receipt_redaction_level,
    optional_upload_allowed,
    preference_sync_context,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_oauth_connection_authority import NOW, _inputs

WORKSPACE = "00000000-0000-4000-8000-000000000042"
OTHER = "00000000-0000-4000-8000-000000000043"


def _wire(
    revision: int = 1, *, sync: bool = True, telemetry: bool = True, redaction: str = "partial"
) -> dict[str, object]:
    return {
        "contractVersion": authority.CONTRACT,
        "workspaceId": WORKSPACE,
        "revision": revision,
        "updatedAt": NOW,
        "preferences": {"syncEnabled": sync, "telemetryEnabled": telemetry, "receiptRedactionLevel": redaction},
    }


def _store(
    tmp_path: Path, *, source: str = "default", issuer: str = "https://hol.org"
) -> tuple[GuardStore, dict[str, Any]]:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False, source=source)
    inputs: dict[str, Any] = {**_inputs(), "workspace_id": WORKSPACE, "issuer": issuer}
    store.set_oauth_local_credentials(**inputs)
    (store.guard_home / "config.toml").write_text('sync = true\ntelemetry = true\nreceipt_redaction_level = "none"\n')
    return store, inputs


def _accept(
    store: GuardStore,
    wire: object = None,
    *,
    sent: object = 1,
    ack: object = True,
    state: authority.WorkspacePreferenceState | None = None,
) -> authority.PreferenceResponseAcceptance:
    request = state or authority.capture_workspace_preference_state(store)
    return authority.accept_workspace_preference_response(
        store,
        request,
        {"workspacePreferences": _wire() if wire is None else wire, "receiptSyncAccepted": ack},
        sent_revision=sent,
    )


def _raw_write(store: GuardStore, key: str, value: str | None) -> None:
    with store._connect() as connection:
        if value is None:
            connection.execute("delete from sync_state where state_key = ?", (key,))
        else:
            connection.execute("update sync_state set payload_json = ? where state_key = ?", (value, key))


@pytest.mark.parametrize(
    "field,value",
    [
        ("contractVersion", "other"),
        ("workspaceId", OTHER),
        ("revision", True),
        ("revision", -1),
        ("revision", 1.5),
        ("revision", 2**53),
        ("revision", "1"),
        ("updatedAt", "bad"),
        ("updatedAt", "2026-02-30T00:00:00Z"),
        ("updatedAt", "2026-09-18T00:00:00"),
        ("preferences", []),
        ("preferences", {}),
        ("extra", True),
    ],
)
def test_strict_wire_fields(field: str, value: object) -> None:
    candidate = _wire()
    candidate[field] = value
    with pytest.raises((ValueError, TypeError)):
        authority.parse_workspace_preferences(candidate, workspace_id=WORKSPACE)


@pytest.mark.parametrize(
    "field,value",
    [("syncEnabled", 1), ("telemetryEnabled", "false"), ("receiptRedactionLevel", "other"), ("extra", False)],
)
def test_strict_preference_fields(field: str, value: object) -> None:
    candidate = _wire()
    preferences = candidate["preferences"]
    assert isinstance(preferences, dict)
    preferences[field] = value
    with pytest.raises(ValueError):
        authority.parse_workspace_preferences(candidate, workspace_id=WORKSPACE)


@pytest.mark.parametrize(
    "ack,sent,enabled,accepted",
    [
        (True, 1, True, True),
        (False, 1, True, False),
        (None, 1, True, False),
        ("true", 1, True, False),
        (1, 1, True, False),
        (True, None, True, False),
        (True, 0, True, False),
        (True, True, True, False),
        (True, 1, False, False),
    ],
)
def test_exact_revision_ack(tmp_path: Path, ack: object, sent: object, enabled: bool, accepted: bool) -> None:
    store, _ = _store(tmp_path)
    result = _accept(store, _wire(sync=enabled), sent=sent, ack=ack)
    assert result.receipt_accepted is accepted
    assert result.state.preferences is not None
    assert result.state.confirmed


def test_new_domain_empty_until_negotiated_and_same_revision_timestamp_can_change(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    initial = authority.capture_workspace_preference_state(store)
    assert not initial.confirmed and not optional_upload_allowed(store)
    first = _accept(store, _wire(2), sent=None)
    assert not first.receipt_accepted
    assert optional_upload_allowed(store)
    same = _wire(2)
    same["updatedAt"] = "2026-07-01T00:00:00Z"
    _accept(store, same, sent=2)
    reopened = GuardStore(store.guard_home, allow_system_keyring=False)
    assert authority.capture_workspace_preference_state(reopened).preferences == authority.parse_workspace_preferences(
        same, workspace_id=WORKSPACE
    )
    for wire in (_wire(1), _wire(2, sync=False)):
        with pytest.raises(ValueError):
            _accept(reopened, wire, sent=2)
    assert preference_sync_context(store)["workspacePreferenceRevision"] == 2


@pytest.mark.parametrize("source", ["default", "secondary"])
def test_replacement_preserves_floor_but_requires_new_confirmation(tmp_path: Path, source: str) -> None:
    store, inputs = _store(tmp_path, source=source)
    initial = _accept(store, _wire(5), sent=5).state
    store.set_oauth_local_credentials(**inputs)
    current = authority.capture_workspace_preference_state(store)
    assert current.preferences == initial.preferences and not current.confirmed
    assert not optional_upload_allowed(store)
    assert current.sync_context()["workspacePreferenceRevision"] == 5
    with pytest.raises(ValueError, match="source_changed"):
        _accept(store, _wire(6), sent=6, state=initial)
    with pytest.raises(ValueError, match="stale"):
        _accept(store, _wire(4), sent=4)
    _accept(store, _wire(5), sent=5)
    assert optional_upload_allowed(store)


def test_same_authority_refresh_preserves_optional_permission(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    state = _accept(store).state
    refreshed: dict[str, Any] = {**inputs, "access_token": "next-access", "refresh_token": "next-refresh"}
    store.set_oauth_local_credentials(
        **refreshed,
        expected_connection=state.connection,
    )
    assert optional_upload_allowed(store)
    assert _accept(store, state=state).receipt_accepted


@pytest.mark.parametrize(
    "field,value",
    [
        ("workspace_id", OTHER),
        ("issuer", "http://localhost:3041"),
        ("client_id", "different-client"),
        ("grant_id", "different-grant"),
    ],
)
def test_inflight_binding_change_never_adopts_replacement(tmp_path: Path, field: str, value: str) -> None:
    store, inputs = _store(tmp_path)
    captured = _accept(store).state
    changed: dict[str, Any] = {**inputs, field: value}
    store.set_oauth_local_credentials(**changed)
    with pytest.raises(ValueError, match="source_changed"):
        _accept(store, state=captured)
    assert not optional_upload_allowed(store, required_connection=captured.connection)


def test_named_source_and_same_uuid_at_another_issuer_cannot_share_permission(tmp_path: Path) -> None:
    default, _ = _store(tmp_path)
    enabled = _accept(default, _wire(7)).state
    named, inputs = _store(tmp_path, source="secondary")
    assert not optional_upload_allowed(named)
    paused = _accept(named, _wire(1, sync=False)).state
    assert enabled.domain != paused.domain and optional_upload_allowed(default)
    other_issuer: dict[str, Any] = {**inputs, "issuer": "http://localhost:3041"}
    named.set_oauth_local_credentials(**other_issuer)
    fresh = authority.capture_workspace_preference_state(named)
    assert fresh.domain not in {enabled.domain, paused.domain}
    assert fresh.preferences is None and not fresh.confirmed
    _accept(named, _wire(2))
    named.set_oauth_local_credentials(**inputs)
    restored = authority.capture_workspace_preference_state(named)
    assert restored.domain == paused.domain and restored.preferences == paused.preferences
    assert not optional_upload_allowed(named)


def test_workspace_aba_never_revives_old_request(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    captured = _accept(store).state
    other_workspace: dict[str, Any] = {**inputs, "workspace_id": OTHER}
    store.set_oauth_local_credentials(**other_workspace)
    store.set_oauth_local_credentials(**inputs)
    with pytest.raises(ValueError, match="source_changed"):
        _accept(store, state=captured)
    assert not optional_upload_allowed(store)


def test_pending_reset_cannot_capture_or_accept_then_complete_reset_needs_confirmation(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    state = _accept(store).state
    with store.hold_oauth_credential_lock(), store._connect() as connection:
        advance_connection_epoch(connection, state.connection.credential_key, NOW, reset_token="a" * 32)
    with pytest.raises(ValueError, match="source_changed"):
        authority.capture_workspace_preference_state(store)
    assert not optional_upload_allowed(store)
    with pytest.raises(ValueError, match="source_changed"):
        _accept(store, state=state)
    with store.hold_oauth_credential_lock(), store._connect() as connection:
        advance_connection_epoch(connection, state.connection.credential_key, NOW, complete_reset_token="a" * 32)
    assert not authority.capture_workspace_preference_state(store).confirmed


@pytest.mark.parametrize("key_kind", ["ledger", "marker"])
@pytest.mark.parametrize(
    "raw", [None, "[]", "null", "{", '{"version":true}', '{"version":1,"version":1}', '{"number":NaN}']
)
def test_adopted_missing_or_corrupt_authority_never_reopens_permission(
    tmp_path: Path, key_kind: str, raw: str | None
) -> None:
    store, _ = _store(tmp_path)
    state = _accept(store).state
    prefix = authority._LEDGER_PREFIX if key_kind == "ledger" else authority._MARKER_PREFIX
    _raw_write(store, prefix + state.domain, raw)
    assert not optional_upload_allowed(store)
    assert effective_receipt_redaction_level(store) == "full"
    with pytest.raises(ValueError, match="authority_invalid"):
        _accept(store, state=state)


def test_transaction_rollback_keeps_marker_and_ledger_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, _ = _store(tmp_path)
    original = authority._write

    def failing(connection: sqlite3.Connection, key: str, payload: object, now: str) -> None:
        original(connection, key, payload, now)
        if key.startswith(authority._MARKER_PREFIX):
            raise RuntimeError("synthetic rollback")

    monkeypatch.setattr(authority, "_write", failing)
    with pytest.raises(RuntimeError, match="rollback"):
        authority.capture_workspace_preference_state(store)
    with store._connect() as connection:
        assert (
            connection.execute(
                "select count(*) from sync_state where state_key like 'workspace_preference_%'"
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("mutation", ["set", "unlocked-set", "delete", "bulk-delete", "unlocked-delete", "sequence"])
@pytest.mark.parametrize("prefix", [authority._LEDGER_PREFIX, authority._MARKER_PREFIX])
def test_generic_mutation_cannot_edit_private_ledger(tmp_path: Path, mutation: str, prefix: str) -> None:
    store, _ = _store(tmp_path)
    state = _accept(store).state
    key = prefix + state.domain
    before = store.get_sync_payload(key)
    with pytest.raises(ValueError, match="dedicated"):
        if mutation == "set":
            store.set_sync_payload(key, {}, NOW)
        elif mutation == "unlocked-set":
            store._set_sync_payload_unlocked(key, {}, NOW)
        elif mutation == "delete":
            store.delete_sync_payload(key)
        elif mutation == "bulk-delete":
            store.delete_sync_payloads(["unrelated", key])
        elif mutation == "unlocked-delete":
            store._delete_sync_payloads_unlocked([key])
        else:
            store.reserve_sync_sequence(key, "sequence", NOW)
    assert store.get_sync_payload(key) == before


def test_plain_string_key_required_even_with_deceptive_hash(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)

    class Key(str):
        def __hash__(self) -> int:
            return hash("harmless")

        def __eq__(self, other: object) -> bool:
            return other == "harmless"

    with pytest.raises(ValueError, match="plain strings"):
        store.delete_sync_payload(Key(authority._LEDGER_PREFIX + "secret"))
    wire = _wire()
    wire[Key("extra")] = True
    with pytest.raises(ValueError, match="plain strings"):
        _accept(store, wire)


def test_negotiation_cannot_downgrade_after_reconnect(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    initial = authority.capture_workspace_preference_state(store)
    legacy = {"syncedAt": NOW, "receiptsStored": 0}
    assert authority.accept_workspace_preference_response(store, initial, legacy, sent_revision=None).receipt_accepted
    assert optional_upload_allowed(store)
    _accept(store)
    store.set_oauth_local_credentials(**inputs)
    with pytest.raises(ValueError, match="legacy_invalid"):
        authority.accept_workspace_preference_response(
            store, authority.capture_workspace_preference_state(store), legacy, sent_revision=None
        )
    assert not optional_upload_allowed(store)


@pytest.mark.parametrize(
    "old_prefix,old_payload",
    [("workspace_preferences:", {"revision": 1}), ("workspace_preferences_legacy:", {"legacyReceiptSync": True})],
)
def test_unbound_old_records_never_grant_current_source_permission(
    tmp_path: Path, old_prefix: str, old_payload: dict[str, object]
) -> None:
    store, _ = _store(tmp_path)
    key = old_prefix + WORKSPACE
    store.set_sync_payload(key, old_payload, NOW)
    state = authority.capture_workspace_preference_state(store)
    assert not state.legacy_allowed and not optional_upload_allowed(store)
    with pytest.raises(ValueError, match="legacy_invalid"):
        authority.accept_workspace_preference_response(
            store, state, {"syncedAt": NOW, "receiptsStored": 0}, sent_revision=None
        )
    _accept(store)
    assert optional_upload_allowed(store) and store.get_sync_payload(key) == old_payload


def test_conflicting_concurrent_responses_serialize(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    other = GuardStore(store.guard_home, allow_system_keyring=False)
    barrier = Barrier(2)

    def submit(target: GuardStore, enabled: bool) -> str:
        state = authority.capture_workspace_preference_state(target)
        barrier.wait(timeout=5)
        try:
            _accept(target, _wire(sync=enabled), state=state)
            return "accepted"
        except ValueError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(submit, store, True), pool.submit(submit, other, False)]
        assert sorted(f.result(timeout=10) for f in futures) == ["accepted", "workspace_preferences_conflict"]


@pytest.mark.parametrize(
    "local_sync,local_telemetry,cloud_sync,cloud_telemetry",
    [(a, b, c, d) for a in (False, True) for b in (False, True) for c in (False, True) for d in (False, True)],
)
def test_remote_permission_never_grants_local_consent(
    tmp_path: Path, local_sync: bool, local_telemetry: bool, cloud_sync: bool, cloud_telemetry: bool
) -> None:
    store, _ = _store(tmp_path)
    (store.guard_home / "config.toml").write_text(
        f"sync = {str(local_sync).lower()}\ntelemetry = {str(local_telemetry).lower()}\n"
    )
    _accept(store, _wire(sync=cloud_sync, telemetry=cloud_telemetry))
    assert optional_upload_allowed(store) is (local_sync and cloud_sync)
    assert optional_upload_allowed(store, telemetry=True) is (
        local_sync and local_telemetry and cloud_sync and cloud_telemetry
    )


def test_mutable_response_is_copied_and_private_representation_does_not_expose_credentials(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    payload = {"workspacePreferences": _wire(), "receiptSyncAccepted": True, "unrelatedFiniteNumber": 1.5}
    state = authority.capture_workspace_preference_state(store)
    result = authority.accept_workspace_preference_response(store, state, payload, sent_revision=1)
    wire = payload["workspacePreferences"]
    assert isinstance(wire, dict)
    wire["revision"] = 999
    assert result.state.preferences is not None and result.state.preferences.revision == 1
    assert result.receipt_accepted
    for value in (inputs["refresh_token"], inputs["dpop_private_key_pem"], inputs["issuer"], WORKSPACE):
        assert value not in repr(state) and value not in repr(result)


@pytest.mark.parametrize("mutation", ["credential", "preference"])
def test_actual_separate_process_invalidates_old_response(tmp_path: Path, mutation: str) -> None:
    store, _ = _store(tmp_path)
    state = _accept(store).state
    script = """
import sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_workspace_preference_authority import _accept, _wire, NOW
store = GuardStore(Path(sys.argv[1]), allow_system_keyring=False)
if sys.argv[2] == 'credential':
    key = store._oauth_local_credentials_state_key
    payload = store.get_sync_payload(key)
    assert isinstance(payload, dict)
    store.set_sync_payload(key, payload, NOW)
else:
    _accept(store, _wire(2, sync=False), sent=2)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(store.guard_home), mutation], check=False, capture_output=True, timeout=15
    )
    assert completed.returncode == 0, completed.stderr.decode()
    with pytest.raises(ValueError, match=r"source_changed|stale"):
        _accept(store, state=state)
    assert not optional_upload_allowed(store)


def test_response_write_failure_preserves_existing_preference(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, _ = _store(tmp_path)
    state = _accept(store).state
    before = store.get_sync_payload(authority._LEDGER_PREFIX + state.domain)
    original = authority._write

    def failing(connection: sqlite3.Connection, key: str, payload: object, now: str) -> None:
        original(connection, key, payload, now)
        raise RuntimeError("synthetic response rollback")

    monkeypatch.setattr(authority, "_write", failing)
    with pytest.raises(RuntimeError, match="response rollback"):
        _accept(store, _wire(2, sync=False), sent=2, state=state)
    assert store.get_sync_payload(authority._LEDGER_PREFIX + state.domain) == before


@pytest.mark.parametrize(
    "local,remote,expected",
    [
        ("none", "full", "full"),
        ("full", "none", "full"),
        ("partial", "none", "partial"),
        ("none", "partial", "partial"),
    ],
)
def test_stricter_redaction_remains_after_connection_replacement(
    tmp_path: Path, local: str, remote: str, expected: str
) -> None:
    store, inputs = _store(tmp_path)
    (store.guard_home / "config.toml").write_text(f'receipt_redaction_level = "{local}"\n')
    _accept(store, _wire(redaction=remote))
    assert effective_receipt_redaction_level(store) == expected
    store.set_oauth_local_credentials(**inputs)
    assert effective_receipt_redaction_level(store) == expected
