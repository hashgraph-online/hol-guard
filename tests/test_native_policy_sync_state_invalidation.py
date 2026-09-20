"""Native policy authority sync-state mutations invalidate readiness immediately."""

from __future__ import annotations

import json
import re
from contextlib import contextmanager

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_publisher_scoped as scoped
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.native_policy_authority_state_keys import NATIVE_POLICY_AUTHORITY_SYNC_KEYS
from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_canonical_policy_row_authority import _NOW, _activated_store
from tests.test_native_policy_authority_read import _TIME
from tests.test_native_policy_snapshot_v4_barrier import _assert_closed, _resident
from tests.test_native_policy_snapshot_v4_publication import _ack


@pytest.mark.parametrize("state_key", NATIVE_POLICY_AUTHORITY_SYNC_KEYS)
def test_native_authority_sync_write_invalidates_registered_publisher(tmp_path, state_key: str) -> None:
    store = GuardStore(tmp_path / "guard")
    publisher = get_native_policy_snapshot_publisher(store)
    try:
        with publisher._condition:
            publisher._acked = True
            epoch = publisher._epoch
        store.set_sync_payload(state_key, {"synthetic": True}, "2026-09-19T00:00:00Z")
        assert publisher._epoch == epoch + 1
        assert publisher._acked is False
        assert publisher._source_authority_required is True
    finally:
        publisher.close()


def test_unrelated_sync_write_does_not_invalidate_native_publisher(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    publisher = get_native_policy_snapshot_publisher(store)
    try:
        with publisher._condition:
            publisher._acked = True
            epoch = publisher._epoch
        store.set_sync_payload("synthetic_unrelated_sync_state", {"count": 1}, "2026-09-19T00:00:00Z")
        assert publisher._epoch == epoch
        assert publisher._acked is True
        assert publisher._source_authority_required is False
    finally:
        publisher.close()


@pytest.mark.parametrize("state_key", NATIVE_POLICY_AUTHORITY_SYNC_KEYS)
def test_native_authority_sync_delete_invalidates_registered_publisher(tmp_path, state_key: str) -> None:
    store = GuardStore(tmp_path / "guard")
    store.set_sync_payload(state_key, {"synthetic": True}, "2026-09-19T00:00:00Z")
    publisher = get_native_policy_snapshot_publisher(store)
    try:
        with publisher._condition:
            publisher._acked = True
            epoch = publisher._epoch
        assert store.delete_sync_payloads([state_key]) == 1
        assert publisher._epoch == epoch + 1
        assert publisher._acked is False
        assert publisher._source_authority_required is True
    finally:
        publisher.close()


def test_real_keyring_revocation_supersedes_ack_and_fresh_capture_refuses_transport(tmp_path) -> None:
    """Keep real write notifications distinct from the independent post-ACK fence."""
    store = _activated_store(tmp_path, action="block")
    status = _status()
    status.capabilities.features += tuple(scoped.SCOPED_PUBLISH_FEATURES)
    calls = []

    def client(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        calls.append(snapshot)
        _resident(store.guard_home)
        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
        store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
        return json.dumps(_ack(snapshot)).encode()

    publisher = NativePolicySnapshotPublisher(
        store=store, status_provider=lambda: status, client_request=client, wall_clock=lambda: _TIME
    )
    try:
        epoch = publisher._epoch
        publisher._publish_once()
        assert len(calls) == 1
        assert calls[0]["scoped_authority"]["rows"][0]["action"] == "block"
        _assert_closed(publisher)
        assert publisher._epoch == epoch + 1
        assert publisher._source_authority_required is True
        assert publisher._publish_event.is_set()
        # A superseded attempt must not put its failure onto the new epoch.
        assert publisher.last_error is None
        publisher._publish_once()
        _assert_closed(publisher)
        assert publisher.last_error == "native_policy_authority_bundle_unavailable"
        assert publisher._epoch == epoch + 1
        assert len(calls) == 1
    finally:
        publisher.close()


def test_every_actually_captured_sync_input_invalidates_after_commit(tmp_path, monkeypatch) -> None:
    """Exercise the real capture query, including its source-specific OAuth key."""
    store = GuardStore(tmp_path / "guard")
    store._policy_integrity_secret_material(create=True)
    captured_keys: set[str] = set()
    connect = store._connect

    def trace(statement: str) -> None:
        if statement.startswith("select state_key, payload_json from sync_state where state_key in ("):
            captured_keys.update(re.findall(r"'([^']+)'", statement))

    @contextmanager
    def capture_connection():
        with connect() as connection:
            connection.set_trace_callback(trace)
            try:
                yield connection
            finally:
                connection.set_trace_callback(None)

    with monkeypatch.context() as capture:
        capture.setattr(store, "_connect", capture_connection)
        inputs = read_native_policy_authority_inputs(store, now=_TIME)
    assert inputs.authority.rows == ()
    assert captured_keys == {*NATIVE_POLICY_AUTHORITY_SYNC_KEYS, store._oauth_local_credentials_state_key}
    publisher = get_native_policy_snapshot_publisher(store)
    try:
        for state_key in sorted(captured_keys):
            for delete in (False, True):
                with publisher._condition:
                    publisher._acked = True
                    epoch = publisher._epoch
                if delete:
                    assert store.delete_sync_payloads([state_key]) == 1
                else:
                    store.set_sync_payload(state_key, {"synthetic": True}, _NOW)
                # Inspect committed state through a fresh actual connection.
                with connect() as connection:
                    row = connection.execute(
                        "select payload_json from sync_state where state_key = ?", (state_key,)
                    ).fetchone()
                assert (row is None) is delete
                assert publisher._epoch == epoch + 1, state_key
                assert publisher._acked is False, state_key
                assert publisher._source_authority_required is True, state_key
    finally:
        publisher.close()
