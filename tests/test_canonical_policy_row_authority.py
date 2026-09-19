"""Signed canonical rows retain their source authority through reuse."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_keyring_payload
from codex_plugin_scanner.guard.runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key

_NOW = "2026-09-17T00:00:00Z"
_ARTIFACT = "codex:project:synthetic-policy-fixture"


def _activated_store(tmp_path: Path, *, action: str = "allow", bundle_version: int = 8) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    device = store.get_device_metadata()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = _verification_key(private_key, workspace_id="workspace-alpha")
    payload: dict[str, object] = {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "synthetic.policy", "name": "Synthetic policy", "revision": 8},
        "spec": {
            "defaults": {"mode": "enforce", "defaultAction": "warn"},
            "rules": [
                {
                    "id": "synthetic.rule",
                    "enabled": True,
                    "effect": action,
                    "match": {"harnesses": ["codex"], "artifacts": [_ARTIFACT], "devices": [device["installation_id"]]},
                    "lifetime": {"mode": "permanent", "expiresAt": None},
                    "provenance": {"source": "cloud", "createdAt": _NOW},
                }
            ],
        },
    }
    bundle = _signed_bundle(
        private_key, key, payload_base=payload, rollout_state="enforcing", bundle_version=bundle_version
    )
    decisions = build_canonical_policy_bundle_decisions(
        bundle, device_id=device["installation_id"], device_name=device["device_label"]
    )
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, _NOW)
    assert (
        store.apply_policy_bundle_authority(
            decisions,
            _NOW,
            policy_bundle=bundle,
            policy_bundle_keyring=policy_bundle_keyring_payload((key,), workspace_id="workspace-alpha"),
            cloud_exceptions=[],
            policy_bundle_ack={
                "bundleHash": bundle["bundleHash"],
                "bundleVersion": bundle_version,
                "status": "validated",
            },
            policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
            update_last_good=True,
            remote_write_authorized=True,
        )
        is not None
    )
    return store


def test_current_canonical_row_can_resolve_and_be_reused(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    lookup = store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_NOW, consume_one_shot=False)
    decision = lookup["decision"]
    assert isinstance(decision, dict)
    assert decision["source"] == "policy-bundle-canonical"
    assert decision["action"] == "allow"
    assert store.claim_approval_reuse_decision(decision, now=_NOW)


@pytest.mark.parametrize(
    "mutation",
    ["expired", "signature", "revoked-key", "wrong-workspace", "wrong-device", "cleared", "action", "target"],
)
def test_canonical_row_cannot_outlive_or_escape_its_signed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store = _activated_store(tmp_path, action="block" if mutation == "action" else "allow")
    lookup_time = "2031-01-01T00:00:00Z" if mutation == "expired" else _NOW
    artifact = _ARTIFACT
    if mutation == "signature":
        bundle = store.get_sync_payload("policy_bundle")
        assert isinstance(bundle, dict)
        verifier = bundle["verifier"]
        assert isinstance(verifier, dict)
        verifier["signature"] = "invalid"
        store.set_sync_payload("policy_bundle", bundle, _NOW)
    elif mutation == "wrong-workspace":
        store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-other"}, _NOW)
    elif mutation == "wrong-device":
        metadata = {**store.get_device_metadata(), "installation_id": "00000000-0000-4000-8000-000000000099"}
        monkeypatch.setattr(store, "get_device_metadata", lambda: metadata)
    elif mutation == "revoked-key":
        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        keys = keyring["keys"]
        assert isinstance(keys, list) and isinstance(keys[0], dict)
        keys[0]["state"] = "revoked"
        store.set_sync_payload("policy_bundle_keyring", keyring, _NOW)
    elif mutation == "cleared":
        store.set_sync_payload("policy_bundle", {}, _NOW)
    elif mutation in {"action", "target"}:
        with sqlite3.connect(store.path) as connection:
            if mutation == "action":
                connection.execute("update policy_decisions set action = 'allow'")
            else:
                artifact = "codex:project:different-synthetic-target"
                connection.execute("update policy_decisions set artifact_id = ?", (artifact,))
    lookup = store.resolve_policy_decision_lookup("codex", artifact, now=lookup_time, consume_one_shot=False)
    assert lookup["decision"] is None
    assert store.resolve_policy("codex", artifact, now=lookup_time) is None
    stored = store.list_policy_decisions()[0]
    candidate = {**stored, "_approval_authority_revision": lookup["authority_revision"]}
    assert not store.claim_approval_reuse_decision(candidate, now=lookup_time)


def test_canonical_reuse_revalidates_signature_after_lookup(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    lookup = store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_NOW, consume_one_shot=False)
    decision = lookup["decision"]
    assert isinstance(decision, dict)
    with sqlite3.connect(store.path) as connection:
        # A direct durable mutation need not increment the normal mutation
        # counter; claim must still verify the original source authority.
        connection.execute(
            "update sync_state set payload_json = ? where state_key = 'policy_bundle'", (json.dumps({}),)
        )
    assert not store.claim_approval_reuse_decision(decision, now=_NOW)


def test_materialization_recency_cannot_be_changed_without_authority(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="block",
            artifact_id=_ARTIFACT,
            artifact_hash="synthetic-hash",
            source="local",
        ),
        "2026-09-17T00:00:01Z",
    )
    assert store.resolve_policy("codex", _ARTIFACT, "synthetic-hash", now="2026-09-17T00:00:02Z") == "block"
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update policy_decisions set updated_at = ? where source = 'policy-bundle-canonical'",
            ("2026-09-17T00:00:02.000000+00:00",),
        )
    assert store.resolve_policy("codex", _ARTIFACT, "synthetic-hash", now="2026-09-17T00:00:03Z") == "block"


def _reapply_current(store: GuardStore, now: str) -> object:
    bundle = store.get_sync_payload("policy_bundle")
    keyring = store.get_sync_payload("policy_bundle_keyring")
    assert isinstance(bundle, dict) and isinstance(keyring, dict)
    device = store.get_device_metadata()
    return store.apply_policy_bundle_authority(
        build_canonical_policy_bundle_decisions(
            bundle, device_id=device["installation_id"], device_name=device["device_label"]
        ),
        now,
        policy_bundle=bundle,
        policy_bundle_keyring=keyring,
        cloud_exceptions=[],
        policy_bundle_ack={"bundleHash": bundle["bundleHash"], "bundleVersion": 8, "status": "validated"},
        policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
        update_last_good=True,
        remote_write_authorized=True,
    )


def test_identical_bundle_reapplication_retains_original_materialization_time(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    initial = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    assert isinstance(initial, dict)
    assert _reapply_current(store, "2026-09-17T00:01:00Z") is not None
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == initial
    rows = store.list_policy_decisions()
    assert len(rows) == 1
    assert rows[0]["updated_at"] == initial["materializedAt"]


@pytest.mark.parametrize("mutation", ["empty", "timestamp", "bundle", "version-type", "key"])
def test_materialization_binding_cannot_be_modified_or_replaced(tmp_path: Path, mutation: str) -> None:
    store = _activated_store(tmp_path)
    record = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    assert isinstance(record, dict)
    if mutation == "empty":
        record = {}
    elif mutation == "timestamp":
        record["materializedAt"] = "2026-09-17T00:00:02.000000+00:00"
        with sqlite3.connect(store.path) as connection:
            connection.execute("update policy_decisions set updated_at = ?", (record["materializedAt"],))
    elif mutation == "bundle":
        record["bundleHash"] = "sha256:" + "f" * 64
    elif mutation == "version-type":
        record["bundleVersion"] = "8"
    else:
        record["keyId"] = "different-key"
    store.set_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY, record, _NOW)
    lookup = store.resolve_policy_decision_lookup("codex", _ARTIFACT, now=_NOW, consume_one_shot=False)
    assert lookup["decision"] is None
    stored = store.list_policy_decisions()[0]
    candidate = {**stored, "_approval_authority_revision": lookup["authority_revision"]}
    assert not store.claim_approval_reuse_decision(candidate, now=_NOW)
    assert _reapply_current(store, "2026-09-17T00:01:00Z") is None


def test_materialization_key_failure_preserves_previous_durable_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _activated_store(tmp_path)
    before_rows = store.list_policy_decisions()
    before_record = store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY)
    monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda **_kwargs: (None, None))
    assert _reapply_current(store, "2026-09-17T00:01:00Z") is None
    assert store.list_policy_decisions() == before_rows
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) == before_record


def test_unbound_legacy_rows_require_validated_reapplication_and_clear_removes_binding(tmp_path: Path) -> None:
    store = _activated_store(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute("delete from sync_state where state_key = ?", (POLICY_BUNDLE_MATERIALIZATION_KEY,))
    assert store.resolve_policy("codex", _ARTIFACT, now=_NOW) is None
    assert _reapply_current(store, "2026-09-17T00:01:00Z") is not None
    assert store.resolve_policy("codex", _ARTIFACT, now="2026-09-17T00:01:01Z") == "allow"
    store.clear_policy_bundle_authority("2026-09-17T00:02:00Z", policy_bundle_last_error={"reason": "fixture-clear"})
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
