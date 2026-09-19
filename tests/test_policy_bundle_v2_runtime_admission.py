"""Runtime admission regressions for signed generic policy bundle v2 documents."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.policy_bundle_parser import (
    policy_bundle_is_enforceable,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    POLICY_BUNDLE_V2_CANONICALIZATION,
    POLICY_BUNDLE_V2_CONTRACT,
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
)
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument, JsonValue, canonical_json_bytes
from codex_plugin_scanner.guard.policy_document_yaml import PolicyDocumentError
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.synced_policy import cached_policy_bundle_validation
from tests.support.network import stub_authenticated_urlopen
from tests.test_policy_bundle_v2 import (
    _signed_bundle,
    _verification_key,
)


def _generic_v2_payload(
    *,
    rule_id: str,
    artifact_id: str,
    rollout_state: object = "enforcing",
    omit_rollout_state: bool = False,
) -> dict[str, object]:
    spec: dict[str, object] = {
        "defaults": {"mode": "prompt", "defaultAction": "warn"},
        "rules": [
            {
                "id": rule_id,
                "enabled": True,
                "effect": "block",
                "match": {
                    "artifacts": [artifact_id],
                    "harnesses": ["codex"],
                },
                "lifetime": {"mode": "permanent", "expiresAt": None},
                "provenance": {
                    "source": "suggested-memory",
                    "receiptIds": ["receipt-1"],
                    "suggestionId": "suggestion-1",
                    "createdAt": "2026-07-15T12:00:00Z",
                    "createdBy": "owner-1",
                },
            }
        ],
    }
    if not omit_rollout_state:
        spec["rolloutState"] = rollout_state
    return {
        "apiVersion": "guard.hashgraphonline.com/v1alpha1",
        "kind": "GuardPolicy",
        "metadata": {"id": "policy.runtime-admission", "name": "Admission", "revision": 1},
        "spec": spec,
    }


class _SyncResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self) -> _SyncResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        del exc_type, exc, tb
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def _seed_v2_admission_store(tmp_path: Path, verification_key: PolicyBundleVerificationKey) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload("policy_bundle_keyring", {"keys": [verification_key.to_dict()]}, "2026-07-15T12:00:00Z")
    store.set_sync_payload("oauth_local_credentials", {"workspace_id": "workspace-alpha"}, "2026-07-15T12:00:00Z")
    return store


def _sync_receipts(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    synced_at: str,
    policy_bundle: dict[str, object] | None = None,
    include_policy_bundle: bool = True,
) -> dict[str, object]:
    payload: dict[str, object] = {"syncedAt": synced_at, "receiptsStored": 0}
    if include_policy_bundle:
        payload["policyBundle"] = policy_bundle
    stub_authenticated_urlopen(monkeypatch, lambda request, timeout: _SyncResponse(payload))
    monkeypatch.setattr(guard_runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(guard_runner, "sync_guard_events", lambda _store, auth_context=None: 0)
    return guard_runner.sync_receipts(
        store,
        auth_context={
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "test-token",
            "dpop_key_material": None,
        },
    )


def _sync_signed_v2_bundle(
    store: GuardStore,
    monkeypatch: pytest.MonkeyPatch,
    bundle: dict[str, object],
    *,
    synced_at: str,
) -> dict[str, object]:
    return _sync_receipts(store, monkeypatch, synced_at=synced_at, policy_bundle=bundle)


def test_v2_publication_contract_matches_live_rollout_states() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    draft = _signed_bundle(private_key, verification_key)
    pending = _signed_bundle(private_key, verification_key, rollout_state="pending_approval")
    published = _signed_bundle(private_key, verification_key, rollout_state="enforcing")

    enforced = _signed_bundle(private_key, verification_key, rollout_state="enforced")
    rollback = _signed_bundle(private_key, verification_key, rollout_state="rollback_available")

    assert policy_bundle_is_enforceable(draft) is False
    assert policy_bundle_is_enforceable(pending) is False
    assert policy_bundle_is_enforceable(published) is True
    assert policy_bundle_is_enforceable(enforced) is True
    assert policy_bundle_is_enforceable(rollback) is True
    omitted_payload = _generic_v2_payload(
        rule_id="rule.live",
        artifact_id="command:live",
        omit_rollout_state=True,
    )
    omitted = _signed_bundle(private_key, verification_key, payload_base=omitted_payload)
    assert policy_bundle_is_enforceable(omitted) is True


@pytest.mark.parametrize("rollout_state", ["draft", "pending_approval"])
def test_signed_unpublished_generic_v2_bundle_is_not_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rollout_state: str,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    live = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=8,
        payload_base=_generic_v2_payload(
            rollout_state="enforcing",
            rule_id="rule.live-block",
            artifact_id="command:live-block",
        ),
    )
    unpublished = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=9,
        payload_base=_generic_v2_payload(
            rollout_state=rollout_state,
            rule_id="rule.draft-block",
            artifact_id="command:draft-block",
        ),
    )
    validated, reason, _keys = validate_synced_policy_bundle(
        unpublished,
        stored_keyring={"keys": [verification_key.to_dict()]},
        expected_workspace_id="workspace-alpha",
    )
    assert reason is None
    assert validated is not None
    assert policy_bundle_is_enforceable(unpublished) is False

    store = _seed_v2_admission_store(tmp_path, verification_key)

    _sync_signed_v2_bundle(store, monkeypatch, live, synced_at="2026-07-15T12:01:00Z")
    assert store.get_sync_payload("policy_bundle") == live
    live_rows = [row["artifact_id"] for row in store.list_policy_decisions()]
    assert "command:live-block" in live_rows
    assert store.get_sync_payload("policy_bundle_ack") == {}

    _sync_signed_v2_bundle(store, monkeypatch, unpublished, synced_at="2026-07-15T12:02:00Z")
    assert store.get_sync_payload("policy_bundle") == live
    assert store.get_sync_payload("policy_bundle_last_good") == live
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert isinstance(last_error, dict)
    assert last_error.get("reason") == "inactive_rollout_state"
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    assert acknowledgement == {} or (isinstance(acknowledgement, dict) and acknowledgement.get("status") != "applied")
    remaining_rows = [row["artifact_id"] for row in store.list_policy_decisions()]
    assert "command:draft-block" not in remaining_rows
    assert "command:live-block" in remaining_rows

    assert cached_policy_bundle_validation(store, unpublished) == (None, "inactive_rollout_state")

    store.set_sync_payload("policy_bundle", unpublished, "2026-07-15T12:03:00Z")
    assert cached_policy_bundle_validation(store, unpublished) == (None, "inactive_rollout_state")
    assert cached_policy_bundle_validation(store, live)[0] == live


def test_signed_enforcing_generic_v2_bundle_is_admitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    published = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=10,
        payload_base=_generic_v2_payload(
            rollout_state="enforcing",
            rule_id="rule.published-block",
            artifact_id="command:published-block",
        ),
    )
    store = _seed_v2_admission_store(tmp_path, verification_key)

    _sync_signed_v2_bundle(store, monkeypatch, published, synced_at="2026-07-15T12:04:00Z")
    assert store.get_sync_payload("policy_bundle") == published
    last_error = store.get_sync_payload("policy_bundle_last_error")
    assert last_error in (None, {})
    assert "command:published-block" in [row["artifact_id"] for row in store.list_policy_decisions()]
    assert cached_policy_bundle_validation(store, published)[0] == published


@pytest.mark.parametrize(
    ("cached_rollout_state", "expected_reason"),
    [
        ("draft", "inactive_rollout_state"),
        ("pending_approval", "inactive_rollout_state"),
        (None, "invalid_policy_document"),
    ],
)
def test_cached_inactive_v2_bundle_is_not_activated_when_last_good_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cached_rollout_state: str | None,
    expected_reason: str,
) -> None:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    live = _signed_bundle(
        private_key,
        verification_key,
        bundle_version=8,
        payload_base=_generic_v2_payload(
            rollout_state="enforcing",
            rule_id="rule.live-block",
            artifact_id="command:live-block",
        ),
    )
    inactive = (
        _signed_bundle(
            private_key,
            verification_key,
            bundle_version=9,
            payload_base=_generic_v2_payload(
                rollout_state=cached_rollout_state,
                rule_id="rule.draft-block",
                artifact_id="command:draft-block",
            ),
        )
        if cached_rollout_state is not None
        else _signed_v2_with_rollout_value(private_key, verification_key, None, bundle_version=9)
    )
    store = _seed_v2_admission_store(tmp_path, verification_key)
    _sync_signed_v2_bundle(store, monkeypatch, live, synced_at="2026-07-15T12:01:00Z")
    assert store.get_sync_payload("policy_bundle") == live
    assert store.get_sync_payload("policy_bundle_last_good") == live
    assert "command:live-block" in [row["artifact_id"] for row in store.list_policy_decisions()]

    store.set_sync_payload("policy_bundle", inactive, "2026-07-15T12:03:00Z")
    assert store.get_sync_payload("policy_bundle_last_good") == live
    _sync_receipts(store, monkeypatch, synced_at="2026-07-15T12:04:00Z", include_policy_bundle=False)

    assert store.get_sync_payload("policy_bundle") == live
    assert store.get_sync_payload("policy_bundle_last_good") == live
    remaining_rows = [row["artifact_id"] for row in store.list_policy_decisions()]
    assert "command:live-block" in remaining_rows
    assert "command:draft-block" not in remaining_rows
    cached, cached_reason = cached_policy_bundle_validation(store, inactive)
    assert cached is None
    assert cached_reason == expected_reason


def _signed_v2_with_rollout_value(
    private_key: rsa.RSAPrivateKey,
    verification_key: PolicyBundleVerificationKey,
    rollout_state: object,
    *,
    bundle_version: int = 11,
) -> dict[str, object]:
    payload = _generic_v2_payload(
        rollout_state=rollout_state,
        rule_id="rule.invalid-rollout",
        artifact_id="command:invalid-rollout",
    )
    try:
        return _signed_bundle(private_key, verification_key, bundle_version=bundle_version, payload_base=payload)
    except (PolicyDocumentError, TypeError, ValueError):
        bundle: dict[str, object] = {
            "envelopeVersion": 2,
            "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
            "bundleVersion": bundle_version,
            "bundleHash": "",
            "payloadHash": "",
            "issuedAt": "2026-07-15T12:00:00Z",
            "expiresAt": "2030-07-15T12:00:00Z",
            "workspaceId": "workspace-alpha",
            "canonicalization": POLICY_BUNDLE_V2_CANONICALIZATION,
            "verifier": {
                "algorithm": "rsa-pss-sha256",
                "keyId": verification_key.key_id,
                "keyFingerprint": verification_key.fingerprint_sha256,
                "publicKeyPem": verification_key.public_key_pem,
                "signature": "",
            },
            "payload": payload,
            "rollback": None,
        }
        try:
            bundle["payloadHash"] = payload_hash_for_policy_bundle_v2(bundle)
        except (PolicyDocumentError, TypeError, ValueError):
            digest = hashlib.sha256(canonical_json_bytes(cast(JsonValue, payload))).hexdigest()
            bundle["payloadHash"] = f"sha256:{digest}"
        bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
        signature = private_key.sign(
            canonical_policy_bundle_v2_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        verifier = bundle["verifier"]
        assert isinstance(verifier, dict)
        verifier["signature"] = base64.b64encode(signature).decode("ascii")
        return bundle


@pytest.mark.parametrize("rollout_state", [None, 7, {"state": "enforcing"}])
def test_signed_v2_present_invalid_rollout_state_is_not_enforceable(rollout_state: object) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    payload = _generic_v2_payload(
        rollout_state=rollout_state,
        rule_id="rule.invalid-rollout",
        artifact_id="command:invalid-rollout",
    )
    with pytest.raises(TypeError, match="validated_policy_document_shape"):
        GuardPolicyDocument.from_mapping(payload)
    bundle = _signed_v2_with_rollout_value(private_key, verification_key, rollout_state)
    assert policy_bundle_is_enforceable(bundle) is False
    validated, _reason, _keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring={"keys": [verification_key.to_dict()]},
        expected_workspace_id="workspace-alpha",
    )
    assert validated is None


def test_signed_v2_omitted_rollout_state_remains_enforceable() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key, workspace_id="workspace-alpha")
    omitted = _signed_bundle(
        private_key,
        verification_key,
        payload_base=_generic_v2_payload(
            rule_id="rule.compat",
            artifact_id="command:compat",
            omit_rollout_state=True,
        ),
    )
    assert policy_bundle_is_enforceable(omitted) is True
    validated, reason, _keys = validate_synced_policy_bundle(
        omitted,
        stored_keyring={"keys": [verification_key.to_dict()]},
        expected_workspace_id="workspace-alpha",
    )
    assert reason is None
    assert validated is not None
    assert policy_bundle_is_enforceable(validated) is True
