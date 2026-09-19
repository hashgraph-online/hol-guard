"""Installation rotation preserves signed admission and exact source binding."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.policy_bundle_ack_contract import generic_ack_matches_bundle
from codex_plugin_scanner.guard.policy_bundle_materialization import (
    POLICY_BUNDLE_MATERIALIZATION_KEY,
    verified_policy_materialization_time,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _sync_signed_v2_bundle,
)

_NOW = "2026-09-17T12:00:00Z"
_LATER = "2026-09-17T12:01:00Z"
_ARTIFACT = "skill:synthetic-rotation-target"


def _seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[GuardStore, dict[str, object], str, dict[str, object]]:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private, workspace_id="workspace-alpha")
    store = _seed_v2_admission_store(tmp_path, key)
    installation = store.get_or_create_installation_id()
    payload = _generic_v2_payload(rule_id="synthetic-rotation-rule", artifact_id=_ARTIFACT)
    spec = payload["spec"]
    assert isinstance(spec, dict)
    rules = spec["rules"]
    assert isinstance(rules, list) and len(rules) == 1
    rule = rules[0]
    assert isinstance(rule, dict)
    match = rule["match"]
    assert isinstance(match, dict)
    match["devices"] = [installation]
    bundle = _signed_bundle(private, key, payload_base=payload)
    _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at=_NOW)
    assert store.get_sync_payload("policy_bundle") == bundle
    assert _reason(store) is None
    assert _selected(store)
    binding = _verified_binding(store, bundle)
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict)
    assert generic_ack_matches_bundle(acknowledgement, bundle, device_id=installation)
    return store, bundle, installation, binding


def _reason(store: GuardStore) -> object:
    error = store.get_sync_payload("policy_bundle_last_error")
    return error.get("reason") if isinstance(error, dict) else error


def _selected(store: GuardStore) -> bool:
    result = store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_LATER)
    decision = result["decision"]
    return decision is not None and decision["action"] == "block"


def _verified_binding(store: GuardStore, bundle: dict[str, object]) -> dict[str, object]:
    binding = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    assert isinstance(binding, dict)
    key, key_id = store._policy_integrity_secret_material(create=False)
    verified = verified_policy_materialization_time(
        binding,
        bundle=bundle,
        device_id=store.get_or_create_installation_id(),
        key=key,
        key_id=key_id,
    )
    assert verified is not None
    return binding


@pytest.mark.parametrize("operation", ["rename", "rotate"])
def test_authorized_device_change_can_receive_the_same_signed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    store, bundle, previous_id, previous_binding = _seed(tmp_path, monkeypatch)
    if operation == "rename":
        store.set_device_label("Synthetic renamed device", _LATER)
    else:
        store.rotate_installation_id(_LATER)
    current_id = store.get_or_create_installation_id()
    assert (current_id == previous_id) is (operation == "rename")
    if operation == "rotate":
        assert store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_LATER)["decision"] is None
        assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
        assert store.get_sync_payload("policy_bundle_ack") is None
        assert store.get_sync_payload("policy_bundle") == bundle
    _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at=_LATER)

    # The actual activation failure stays visible without printing signed state.
    reason = _reason(store)
    assert reason is None
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert isinstance(acknowledgement, dict)
    assert generic_ack_matches_bundle(acknowledgement, bundle, device_id=current_id)
    assert store.get_sync_payload("policy_bundle") == bundle
    binding = _verified_binding(store, bundle)
    assert (binding == previous_binding) is (operation == "rename")
    assert _selected(store) is (operation == "rename")


def test_untrusted_installation_row_change_cannot_rebind_a_signed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, bundle, previous_id, previous_binding = _seed(tmp_path, monkeypatch)
    previous_ack = store.get_sync_payload("policy_bundle_ack")
    forged_id = uuid4().hex
    assert forged_id != previous_id
    with store._connect() as connection:
        connection.execute(
            "update guard_devices set installation_id=? where device_key='local-device'",
            (forged_id,),
        )
    _sync_signed_v2_bundle(store, monkeypatch, bundle, synced_at=_LATER)

    assert _reason(store) == "policy_bundle_materialization_unavailable"
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == previous_binding
    assert store.get_sync_payload("policy_bundle_ack") == previous_ack
    assert store.get_sync_payload("policy_bundle") == bundle


def test_failed_rotation_preserves_identity_binding_ack_and_policy_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, bundle, previous_id, previous_binding = _seed(tmp_path, monkeypatch)
    previous_ack = store.get_sync_payload("policy_bundle_ack")
    with store._connect() as connection:
        previous_sync = [tuple(row) for row in connection.execute("select * from sync_state order by state_key")]
        previous_rows = [
            tuple(row) for row in connection.execute("select * from policy_decisions order by decision_id")
        ]
        connection.execute(
            """
            create trigger reject_rotation_cleanup
            before delete on sync_state
            when old.state_key = 'policy_bundle_materialization'
            begin
                select raise(abort, 'synthetic_rotation_failure');
            end
            """
        )
    try:
        with pytest.raises(sqlite3.IntegrityError, match="synthetic_rotation_failure"):
            store.rotate_installation_id(_LATER)
    finally:
        with store._connect() as connection:
            connection.execute("drop trigger reject_rotation_cleanup")

    assert store.get_or_create_installation_id() == previous_id
    assert store.get_sync_payload("policy_bundle") == bundle
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == previous_binding
    assert store.get_sync_payload("policy_bundle_ack") == previous_ack
    assert _verified_binding(store, bundle) == previous_binding
    assert _selected(store)
    with store._connect() as connection:
        current_sync = [tuple(row) for row in connection.execute("select * from sync_state order by state_key")]
        assert current_sync == previous_sync
        assert [
            tuple(row) for row in connection.execute("select * from policy_decisions order by decision_id")
        ] == previous_rows
