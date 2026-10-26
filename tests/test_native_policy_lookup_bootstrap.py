"""Native policy lookup provisions boot authority without restoring Python decisions."""

from __future__ import annotations

import base64
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard import store_policy
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotError
from codex_plugin_scanner.guard.store import GuardStore


def _lookup_transport(monkeypatch, store):
    result = {"decision": None, "source": None}
    transport = Mock(return_value={"status": "ok", "payload": result})
    monkeypatch.setattr(store_policy, "_resident_request", transport)
    monkeypatch.setattr(store, "_cached_policy_bundle_decision_identities", lambda **_: ())
    return transport, result


def test_empty_lookup_provisions_resident_before_dispatch_without_signing_rows(monkeypatch, tmp_path):
    store = GuardStore(tmp_path / "guard")
    master = b"\x07" * 32
    material = Mock(return_value=(master, "test-key-id"))
    monkeypatch.setattr(store, "_policy_integrity_secret_material", material)
    refresh = Mock(side_effect=AssertionError("empty lookup must not refresh policy rows"))
    monkeypatch.setattr(store, "_refresh_policy_integrity_state", refresh)
    transport, expected = _lookup_transport(monkeypatch, store)
    calls = []
    provision = Mock(side_effect=lambda home, key: calls.append("provision"))
    monkeypatch.setattr(store_policy, "provision_native_policy_verifier_key", provision)
    transport.side_effect = lambda **_: calls.append("dispatch") or {"status": "ok", "payload": expected}

    assert store.resolve_policy_decision_lookup("codex", "codex:project:absent") == expected
    assert calls == ["provision", "dispatch"]
    # The empty-store lookup reads the keyring non-creatively; the mocked
    # material answer then lets the resident authority provisioning proceed.
    material.assert_called_once_with(create=False)
    provision.assert_called_once_with(store.guard_home, master)
    refresh.assert_not_called()


def test_remote_only_bootstrap_keeps_local_once_evidence_without_signing_policy_rows(monkeypatch, tmp_path):
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **_: (b"\x07" * 32, "test-key-id"))
    monkeypatch.setattr(store_policy, "provision_native_policy_verifier_key", Mock())
    transport, _ = _lookup_transport(monkeypatch, store)
    store.resolve_policy_decision_lookup("codex", "codex:project:absent")
    request = transport.call_args.kwargs["request"]
    assert request["integrity_state"] == {}
    assert request["integrity_key_b64"] is None
    assert request["integrity_key_id"] is None
    assert request["local_once_integrity_key_b64"] == base64.urlsafe_b64encode(b"\x07" * 32).rstrip(b"=").decode(
        "ascii"
    )
    assert request["local_once_integrity_key_id"] == "test-key-id"


def test_verifier_mismatch_prevents_dispatch_and_is_not_replaced(monkeypatch, tmp_path):
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **_: (b"\x07" * 32, "test-key-id"))
    provision = Mock(side_effect=NativePolicySnapshotError("native_policy_verifier_key_mismatch"))
    monkeypatch.setattr(store_policy, "provision_native_policy_verifier_key", provision)
    transport, _ = _lookup_transport(monkeypatch, store)
    with pytest.raises(NativePolicySnapshotError, match="native_policy_verifier_key_mismatch"):
        store.resolve_policy_decision_lookup("codex", "codex:project:absent")
    provision.assert_called_once()
    transport.assert_not_called()


def test_missing_native_response_remains_terminal(monkeypatch, tmp_path):
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **_: (b"\x07" * 32, "test-key-id"))
    monkeypatch.setattr(store_policy, "provision_native_policy_verifier_key", Mock())
    transport, _ = _lookup_transport(monkeypatch, store)
    transport.return_value = None
    with pytest.raises(ValueError, match="native_policy_decision_lookup_unavailable"):
        store.resolve_policy_decision_lookup("codex", "codex:project:absent")
    transport.assert_called_once()
