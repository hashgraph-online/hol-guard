"""Connection generations reject stale writers across actual credential mutations."""

from __future__ import annotations

import json
import os
import selectors
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.oauth_connection_authority import (
    CONNECTION_AUTHORITY_VERSION_KEY,
    connection_epoch_key,
    read_connection_epoch,
)
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-06-01T00:00:00+00:00"


def _inputs() -> dict[str, Any]:
    key = generate_dpop_key_pair()
    return {
        "issuer": "https://hol.org",
        "client_id": "guard-local-daemon",
        "refresh_token": "synthetic-refresh",
        "access_token": "synthetic-access",
        "access_token_expires_at": "2099-01-01T00:00:00+00:00",
        "dpop_private_key_pem": key.private_key_pem,
        "dpop_public_jwk": key.public_jwk,
        "dpop_public_jwk_thumbprint": key.public_jwk_thumbprint,
        "grant_id": "synthetic-grant",
        "device_id": "synthetic-device",
        "machine_id": "synthetic-machine",
        "runtime_id": "synthetic-runtime",
        "workspace_id": "synthetic-workspace",
        "now": NOW,
    }


def _store(tmp_path: Path, *, source: str = "default") -> tuple[GuardStore, dict[str, Any]]:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False, source=source)
    inputs = _inputs()
    store.set_oauth_local_credentials(**inputs)
    return store, inputs


def _epoch(store: GuardStore) -> str | None:
    with store._connect() as connection:
        return read_connection_epoch(connection, store._oauth_local_credentials_state_key)


def test_identical_clear_and_reconnect_never_reuses_authority(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    payload = store.get_sync_payload(store._oauth_local_credentials_state_key)
    store.clear_oauth_local_credentials()
    cleared_epoch = _epoch(store)
    assert store.capture_oauth_connection() is None
    assert cleared_epoch != before.epoch
    store.set_oauth_local_credentials(**inputs)
    after = store.capture_oauth_connection()
    assert after is not None
    assert store.get_sync_payload(store._oauth_local_credentials_state_key) == payload
    assert after.credentials() == before.credentials()
    assert after.epoch not in {before.epoch, cleared_epoch}
    assert not before.same_authority(after)
    with pytest.raises(RuntimeError, match="connection changed"):
        store.set_oauth_local_credentials(**inputs, expected_connection=before)
    assert store.capture_oauth_connection() == after


def test_same_connection_refresh_preserves_epoch_and_updates_secret(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    refreshed: dict[str, Any] = {**inputs, "refresh_token": "rotated-refresh", "access_token": "rotated-access"}
    store.set_oauth_local_credentials(**refreshed, expected_connection=before)
    after = store.capture_oauth_connection()
    assert after is not None
    assert before.same_authority(after)
    assert after.credentials()["refresh_token"] == "rotated-refresh"
    assert after.credentials()["access_token"] == "rotated-access"
    with pytest.raises(RuntimeError, match="connection changed"):
        store.set_oauth_local_credentials(**inputs, expected_connection=before)
    assert store.capture_oauth_connection() == after


@pytest.mark.parametrize("field", ["issuer", "grant_id", "device_id", "machine_id", "workspace_id", "runtime_id"])
def test_refresh_binding_change_invalidates_original_authority(tmp_path: Path, field: str) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    replacement = "http://localhost:3041" if field == "issuer" else "replacement"
    changed_inputs: dict[str, Any] = {**inputs, field: replacement}
    store.set_oauth_local_credentials(**changed_inputs, expected_connection=before)
    after = store.capture_oauth_connection()
    assert after is not None
    assert after.epoch != before.epoch
    assert not before.same_authority(after)


def test_refresh_key_change_invalidates_original_authority(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    next_key = _inputs()
    changed = {key: value for key, value in next_key.items() if key.startswith("dpop_")}
    store.set_oauth_local_credentials(**{**inputs, **changed}, expected_connection=before)
    after = store.capture_oauth_connection()
    assert after is not None
    assert after.epoch != before.epoch
    assert not before.same_authority(after)


def test_ordinary_identical_replacement_is_a_new_connection(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    store.set_oauth_local_credentials(**inputs)
    after = store.capture_oauth_connection()
    assert before is not None and after is not None
    assert after.credentials() == before.credentials()
    assert after.epoch != before.epoch


@pytest.mark.parametrize("mutation", ["set", "delete", "bulk-delete", "reconnect-reset"])
def test_all_supported_metadata_mutations_invalidate_snapshot(tmp_path: Path, mutation: str) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    key = store._oauth_local_credentials_state_key
    if mutation == "set":
        payload = store.get_sync_payload(key)
        assert isinstance(payload, dict)
        store.set_sync_payload(key, payload, NOW)
    elif mutation == "delete":
        store.delete_sync_payload(key)
    elif mutation == "bulk-delete":
        store.delete_sync_payloads([key, "unrelated-absent-key"])
    else:
        store.clear_cloud_sync_state_for_reconnect(now=NOW)
    assert _epoch(store) != before.epoch
    with pytest.raises(RuntimeError, match="connection changed"):
        store.set_oauth_local_credentials(**inputs, expected_connection=before)


def test_named_source_does_not_invalidate_default_source(tmp_path: Path) -> None:
    default, inputs = _store(tmp_path)
    named = GuardStore(default.guard_home, allow_system_keyring=False, source="secondary")
    named.set_oauth_local_credentials(**inputs)
    first = default.capture_oauth_connection()
    second = named.capture_oauth_connection()
    assert first is not None and second is not None
    assert not first.same_authority(second)
    named.clear_oauth_local_credentials()
    named.set_oauth_local_credentials(**inputs)
    assert default.capture_oauth_connection() == first
    assert named.capture_oauth_connection() != second
    with pytest.raises(RuntimeError, match="connection changed"):
        named.set_oauth_local_credentials(**inputs, expected_connection=first)


def test_snapshot_is_immutable_and_does_not_repr_credentials(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    captured = store.capture_oauth_connection()
    assert captured is not None
    copied = captured.credentials()
    copied["workspace_id"] = "changed-copy"
    jwk = copied["dpop_public_jwk"]
    assert isinstance(jwk, dict)
    jwk.clear()
    assert captured == store.capture_oauth_connection()
    assert "synthetic-refresh" not in repr(captured)
    assert "PRIVATE KEY" not in repr(captured)
    assert str(store.guard_home) not in repr(captured)


def test_legacy_connection_epoch_initializes_once_across_store_instances(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _make_legacy_credentials(store)
    first = store.capture_oauth_connection()
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    second = peer.capture_oauth_connection()
    assert first is not None
    assert first == second


def test_invalid_payload_serialization_rolls_back_epoch_change(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    before = store.capture_oauth_connection()
    with pytest.raises(TypeError):
        store.set_sync_payload(store._oauth_local_credentials_state_key, {"unserializable": object()}, NOW)
    assert store.capture_oauth_connection() == before


def test_other_state_commits_do_not_invalidate_connection(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    before = store.capture_oauth_connection()
    for key in ("receipt_cursor", "sync_summary", "telemetry_upload", "aibom_sync_summary"):
        store.set_sync_payload(key, {"value": 1}, NOW)
        store.delete_sync_payload(key)
    assert store.capture_oauth_connection() == before


def test_missing_metadata_recovery_allocates_new_epoch(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    # Preserve the actual encrypted secret for the normal recovery method to discover.
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync", allowed_origin="https://hol.org", now=NOW
    )
    store.delete_sync_payload(store._oauth_local_credentials_state_key)
    assert store.repair_oauth_local_credential_storage_from_primary()
    after = store.capture_oauth_connection()
    assert after is not None
    assert before.epoch != after.epoch


def test_epoch_is_not_reset_with_credential_row(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    before = _epoch(store)
    store.delete_sync_payloads([store._oauth_local_credentials_state_key])
    with store._connect() as connection:
        row = connection.execute(
            "select payload_json from sync_state where state_key = ?",
            (connection_epoch_key(store._oauth_local_credentials_state_key),),
        ).fetchone()
    assert row is not None
    assert json.loads(str(row[0]))["epoch"] != before


def test_bulk_delete_failure_rolls_back_generation_and_credentials(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    before = store.capture_oauth_connection()
    with store._connect() as connection:
        connection.execute(
            """create trigger deny_credentials_delete before delete on sync_state
            when old.state_key = 'oauth_local_credentials'
            begin select raise(abort, 'controlled credential deletion failure'); end"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="controlled credential deletion failure"):
        store.delete_sync_payloads([store._oauth_local_credentials_state_key])
    assert store.capture_oauth_connection() == before


def test_two_processes_cannot_refresh_from_the_same_stale_snapshot(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    script = """
import socket, sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
def no_network(*args, **kwargs):
    raise AssertionError('Network is forbidden in the authority control.')
socket.create_connection = no_network
store = GuardStore(Path(sys.argv[1]), allow_system_keyring=False)
captured = store.capture_oauth_connection()
assert captured is not None
credentials = captured.credentials()
fields = ('issuer', 'client_id', 'grant_id', 'device_id', 'machine_id', 'runtime_id',
          'workspace_id', 'refresh_token', 'access_token', 'access_token_expires_at',
          'dpop_private_key_pem', 'dpop_public_jwk', 'dpop_public_jwk_thumbprint')
inputs = {key: credentials.get(key) for key in fields}
inputs['refresh_token'] = 'synthetic-rotated-' + sys.argv[2]
inputs['now'] = '2026-06-01T00:00:00+00:00'
print('ready', flush=True)
assert sys.stdin.readline().strip() == 'go'
try:
    store.set_oauth_local_credentials(**inputs, expected_connection=captured)
except RuntimeError as error:
    assert str(error) == 'The connection changed before credentials could be refreshed.'
    print('rejected')
else:
    print('committed')
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(store.guard_home), str(index)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
        )
        for index in range(2)
    ]
    try:
        for process in processes:
            assert process.stdout is not None
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                assert ready.select(timeout=20), "The independent credential writer did not become ready."
            assert process.stdout.readline().strip() == "ready"
        for process in processes:
            assert process.stdin is not None
            process.stdin.write("go\n")
            process.stdin.flush()
        outcomes = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stderr
            outcomes.append(stdout.strip())
        assert sorted(outcomes) == ["committed", "rejected"]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
    after = store.capture_oauth_connection()
    assert after is not None
    assert before.same_authority(after)
    assert before != after


def test_reset_refuses_capture_until_all_cleanup_completes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, _ = _store(tmp_path)
    before = store.capture_oauth_connection()
    observed = []
    clear_policy = store.clear_policy_bundle_authority
    delete_states = store.delete_sync_payloads

    def observe_policy(*args: Any, **kwargs: Any) -> None:
        observed.append(store.capture_oauth_connection())
        clear_policy(*args, **kwargs)
        observed.append(store.capture_oauth_connection())

    def observe_cleanup(keys: list[str]) -> int:
        observed.append(store.capture_oauth_connection())
        result = delete_states(keys)
        observed.append(store.capture_oauth_connection())
        return result

    monkeypatch.setattr(store, "clear_policy_bundle_authority", observe_policy)
    monkeypatch.setattr(store, "delete_sync_payloads", observe_cleanup)
    store.clear_cloud_sync_state_for_reconnect(now=NOW)
    after = store.capture_oauth_connection()
    assert observed == [None, None, None, None]
    assert before is not None and after is not None
    assert after.epoch != before.epoch


@pytest.mark.parametrize(
    "phase", ["clear_review_policy_memory_state", "clear_policy_bundle_authority", "delete_sync_payloads"]
)
def test_failed_reset_stays_unavailable_until_successful_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None

    def fail(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("controlled reset failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, phase, fail)
        with pytest.raises(RuntimeError, match="controlled reset failure"):
            store.clear_cloud_sync_state_for_reconnect(now=NOW)
    assert store.capture_oauth_connection() is None
    with pytest.raises(RuntimeError, match="connection changed"):
        store.set_oauth_local_credentials(**inputs, expected_connection=before)
    # A successful credential write alone cannot claim that the incomplete reset finished.
    store.set_oauth_local_credentials(**inputs)
    assert store.capture_oauth_connection() is None
    store.clear_cloud_sync_state_for_reconnect(now=NOW)
    after = store.capture_oauth_connection()
    assert after is not None
    assert after.epoch != before.epoch


def test_crashed_reset_releases_admission_and_requires_complete_recovery(tmp_path: Path) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    script = """
import os, socket, sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
def no_network(*args, **kwargs):
    raise AssertionError('Network is forbidden in the reset control.')
socket.create_connection = no_network
store = GuardStore(Path(sys.argv[1]), allow_system_keyring=False)
def crash(*args, **kwargs):
    os._exit(17)
store.clear_policy_bundle_authority = crash
store.clear_cloud_sync_state_for_reconnect(now='2026-06-01T00:00:00+00:00')
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(store.guard_home)],
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    assert result.returncode == 17, result.stderr
    assert store.capture_oauth_connection() is None
    with pytest.raises(RuntimeError, match="connection changed"):
        store.set_oauth_local_credentials(**inputs, expected_connection=before)
    store.clear_cloud_sync_state_for_reconnect(now=NOW)
    after = store.capture_oauth_connection()
    assert after is not None and after.epoch != before.epoch


def _make_legacy_credentials(store: GuardStore) -> None:
    key = store._oauth_local_credentials_state_key
    payload = store.get_sync_payload(key)
    assert isinstance(payload, dict)
    payload.pop(CONNECTION_AUTHORITY_VERSION_KEY)
    with store._connect() as connection:
        connection.execute("update sync_state set payload_json = ? where state_key = ?", (json.dumps(payload), key))
        connection.execute("delete from sync_state where state_key = ?", (connection_epoch_key(key),))


def _corrupt_epoch(store: GuardStore, raw: str | None) -> None:
    key = connection_epoch_key(store._oauth_local_credentials_state_key)
    with store._connect() as connection:
        if raw is None:
            connection.execute("delete from sync_state where state_key = ?", (key,))
        else:
            connection.execute(
                "insert into sync_state(state_key, payload_json, updated_at) values (?, ?, ?) "
                "on conflict(state_key) do update set payload_json = excluded.payload_json",
                (key, raw, NOW),
            )


_CORRUPT_EPOCHS = [
    None,
    "{",
    "[]",
    "null",
    '"invalid"',
    "{}",
    '{"epoch":"invalid"}',
    '{"epoch":true}',
    '{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reset":null}',
    '{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reset":false}',
    '{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reset":""}',
    '{"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unexpected":true}',
    '{"reset":null,"epoch":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","reset":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}',
]


@pytest.mark.parametrize("raw", _CORRUPT_EPOCHS)
def test_uncertain_adopted_authority_requires_complete_reset(tmp_path: Path, raw: str | None) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    _corrupt_epoch(store, raw)
    assert store.capture_oauth_connection() is None
    with pytest.raises(RuntimeError, match="connection changed"):
        store.set_oauth_local_credentials(**inputs, expected_connection=before)
    store.set_oauth_local_credentials(**inputs)
    assert store.capture_oauth_connection() is None
    store.clear_oauth_local_credentials()
    store.set_oauth_local_credentials(**inputs)
    assert store.capture_oauth_connection() is None
    store.clear_cloud_sync_state_for_reconnect(now=NOW)
    after = store.capture_oauth_connection()
    assert after is not None and after.epoch != before.epoch
    assert after.credentials() == before.credentials()


@pytest.mark.parametrize("raw", _CORRUPT_EPOCHS)
def test_corruption_cannot_reopen_capture_during_legacy_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw: str | None
) -> None:
    store, _ = _store(tmp_path)
    _make_legacy_credentials(store)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)

    def corrupt_during_cleanup(*args: object, **kwargs: object) -> None:
        _corrupt_epoch(store, raw)
        assert peer.capture_oauth_connection() is None

    with monkeypatch.context() as context:
        context.setattr(store, "clear_policy_bundle_authority", corrupt_during_cleanup)
        with pytest.raises(RuntimeError, match="connection reset changed"):
            store.clear_cloud_sync_state_for_reconnect(now=NOW)
    assert peer.capture_oauth_connection() is None
    store.clear_cloud_sync_state_for_reconnect(now=NOW)
    assert peer.capture_oauth_connection() is not None


@pytest.mark.parametrize("raw", _CORRUPT_EPOCHS[1:])
def test_malformed_legacy_authority_is_never_initialized(tmp_path: Path, raw: str) -> None:
    store, _ = _store(tmp_path)
    _make_legacy_credentials(store)
    _corrupt_epoch(store, raw)
    assert store.capture_oauth_connection() is None


def test_adoption_marker_is_private_and_legacy_upgrade_is_atomic(tmp_path: Path) -> None:
    store, _ = _store(tmp_path)
    _make_legacy_credentials(store)
    credentials = store.get_oauth_local_credentials()
    with store._connect() as connection:
        connection.execute(
            """create trigger deny_authority_adoption before update on sync_state
            when old.state_key = 'oauth_local_credentials'
            begin select raise(abort, 'controlled adoption failure'); end"""
        )
    with pytest.raises(sqlite3.IntegrityError, match="controlled adoption failure"):
        store.capture_oauth_connection()
    assert _epoch(store) is None
    with store._connect() as connection:
        connection.execute("drop trigger deny_authority_adoption")
    captured = store.capture_oauth_connection()
    assert captured is not None and captured.credentials() == credentials
    assert CONNECTION_AUTHORITY_VERSION_KEY not in captured.credentials()
    payload = store.get_sync_payload(store._oauth_local_credentials_state_key)
    assert isinstance(payload, dict) and payload[CONNECTION_AUTHORITY_VERSION_KEY] == 1
    assert store.get_oauth_local_credentials() == credentials
