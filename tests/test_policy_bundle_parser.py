"""Policy bundle parser contract tests (HGC071-HGC075)."""

from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy
from codex_plugin_scanner.guard.policy_bundle_parser import (
    canonical_policy_bundle_payload,
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
    policy_bundle_rejection_message,
    validated_policy_bundle_payload,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    POLICY_BUNDLE_KEY_PURPOSE,
    POLICY_BUNDLE_KEYRING_CONTRACT_VERSION,
    PolicyBundleVerificationKey,
    load_policy_bundle_verification_keys,
    policy_bundle_keyring_payload,
    policy_bundle_verification_context,
    policy_bundle_verification_key_from_public_key,
    safe_load_policy_bundle_verification_keys,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_signing_helpers import review_verification_keys
from tests.policy_bundle_signing_helpers import (
    TEST_POLICY_BUNDLE_WORKSPACE_ID,
    policy_bundle_test_keyring,
    policy_bundle_test_verification_key,
    sign_policy_bundle,
)

_TEST_SIGNING_KEY = policy_bundle_test_verification_key()


def _managed_policy_state(
    keyring: dict[str, object] | None,
) -> ManagedPolicyState:
    payload: dict[str, object] = {
        "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
        "settings": {},
    }
    if keyring is not None:
        payload["policyBundleKeyring"] = keyring
    return ManagedPolicyState(
        "active",
        "managed-policy-test",
        policy=parse_managed_policy(payload),
    )


def _guard_store(tmp_path: Path) -> GuardStore:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return GuardStore(guard_home)


def _sample_policy_bundle(*, bundle_hash: str | None = None) -> dict[str, object]:
    bundle: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-04-19.1",
        "bundleHash": bundle_hash or "",
        "issuedAt": "2026-04-19T00:00:10+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": _TEST_SIGNING_KEY.key_id,
            "signature": None,
        },
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [
            {
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs before execution.",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": ["npm"],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        "acknowledgements": [],
    }
    signed_bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)
    if bundle_hash is not None:
        signed_bundle["bundleHash"] = bundle_hash
    return signed_bundle


def _signed_policy_bundle(
    *,
    key_id: str = "guard-policy-bundle-test-key",
) -> tuple[dict[str, object], tuple[object, ...]]:
    trusted_key = policy_bundle_test_verification_key(
        key_id=key_id,
    )
    return sign_policy_bundle(_sample_policy_bundle(), key=trusted_key), (trusted_key,)


def _validate_policy_bundle(
    bundle: dict[str, object],
    *,
    trusted_keys: tuple[PolicyBundleVerificationKey, ...] = (_TEST_SIGNING_KEY,),
    anchored_keys: tuple[PolicyBundleVerificationKey, ...] | None = None,
    expected_workspace_id: str = TEST_POLICY_BUNDLE_WORKSPACE_ID,
    now: float | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    return validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=trusted_keys,
        anchored_verification_keys=anchored_keys if anchored_keys is not None else trusted_keys,
        expected_workspace_id=expected_workspace_id,
        now=now,
    )


def test_hgc071_valid_policy_bundle_parses() -> None:
    bundle = _sample_policy_bundle()

    validated_bundle, reason = _validate_policy_bundle(bundle)

    assert reason is None
    assert validated_bundle is not None
    assert validated_bundle["bundleVersion"] == "policy-2026-04-19.1"
    assert validated_bundle["bundleHash"] == computed_policy_bundle_hash(bundle)
    assert validated_bundle["rules"] == bundle["rules"]


def test_hgc071_signed_policy_bundle_parses() -> None:
    bundle, trusted_keys = _signed_policy_bundle()

    validated_bundle, reason = _validate_policy_bundle(
        bundle,
        trusted_keys=trusted_keys,
        anchored_keys=trusted_keys,
    )

    assert reason is None
    assert validated_bundle is not None
    assert validated_bundle["workspaceId"] == "workspace-1"
    assert validated_bundle["payloadHash"] == payload_hash_for_policy_bundle(bundle)
    verifier = validated_bundle["verifier"]
    assert isinstance(verifier, dict)
    assert verifier["algorithm"] == "rsa-pss-sha256"


def test_hgc073_signed_policy_bundle_rejects_invalid_signature() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    verifier = dict(bundle["verifier"]) if isinstance(bundle["verifier"], dict) else {}
    verifier["signature"] = base64.b64encode(b"tampered-signature").decode("utf-8")
    bundle["verifier"] = verifier

    validated_bundle, reason = _validate_policy_bundle(
        bundle,
        trusted_keys=trusted_keys,
        anchored_keys=trusted_keys,
    )

    assert validated_bundle is None
    assert reason == "bundle_signature_invalid"


@pytest.mark.parametrize(
    ("reason", "expected_guidance"),
    [
        ("invalid_signature_encoding", "signing authority"),
        ("bundle_signature_invalid", "signing authority"),
        ("invalid_verifier", "signing authority"),
        ("payload_hash_mismatch", "integrity checks"),
        ("invalid_rules", "schema or required fields"),
        ("wrong_workspace", "Reconnect Guard"),
        ("bundle_expired", "Check the system clock"),
        ("bundle_not_yet_valid", "Check the system clock"),
        ("unsupported_daemon_version", "Update Guard"),
    ],
)
def test_policy_bundle_rejection_message_provides_actionable_guidance(
    reason: str,
    expected_guidance: str,
) -> None:
    message = policy_bundle_rejection_message(reason)

    assert message is not None
    assert expected_guidance in message
    assert "Sync again" in message


def test_policy_bundle_rejection_message_ignores_unknown_reason() -> None:
    assert policy_bundle_rejection_message("not_a_policy_bundle_reason") is None


def test_hgc073_bundle_hash_ignores_public_key_rotation() -> None:
    first_bundle, _ = _signed_policy_bundle()
    second_bundle = dict(first_bundle)
    second_bundle["verifier"] = dict(first_bundle["verifier"])
    second_bundle["verifier"]["publicKeyPem"] = "different-embedded-key"
    first_verifier = first_bundle["verifier"]
    second_verifier = second_bundle["verifier"]

    assert isinstance(first_verifier, dict)
    assert isinstance(second_verifier, dict)

    assert first_bundle["bundleHash"] == computed_policy_bundle_hash(first_bundle)
    assert second_bundle["bundleHash"] == computed_policy_bundle_hash(second_bundle)
    assert first_bundle["bundleHash"] == second_bundle["bundleHash"]
    assert first_verifier["publicKeyPem"] != second_verifier["publicKeyPem"]


def test_hgc071_legacy_sha256_bundle_is_not_an_authority_proof() -> None:
    bundle = _sample_policy_bundle()
    bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "legacy-digest-only",
        "signature": bundle["payloadHash"],
    }
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)

    validated_bundle, reason = _validate_policy_bundle(bundle)

    assert validated_bundle is None
    assert reason == "unsupported_signature_algorithm"


def test_hgc071_sha256_bundle_hash_ignores_public_key_field() -> None:
    bundle = _sample_policy_bundle()
    legacy_hash = computed_policy_bundle_hash(bundle)
    verifier = dict(bundle["verifier"]) if isinstance(bundle["verifier"], dict) else {}
    verifier["publicKeyPem"] = "unused-public-key"
    bundle["verifier"] = verifier

    assert computed_policy_bundle_hash(bundle) == legacy_hash


def test_hgc072_invalid_schema_rejected() -> None:
    bundle = _sample_policy_bundle()
    del bundle["rules"]

    validated_bundle, reason = _validate_policy_bundle(bundle)

    assert validated_bundle is None
    assert reason == "missing_required_field"


def test_hgc073_tampered_hash_rejected() -> None:
    bundle = _sample_policy_bundle(bundle_hash="sha256:tampered")

    validated_bundle, reason = _validate_policy_bundle(bundle)

    assert validated_bundle is None
    assert reason == "bundle_hash_mismatch"


def test_hgc073_missing_core_key_raises_for_hash() -> None:
    bundle = _sample_policy_bundle()
    del bundle["rules"]

    try:
        computed_policy_bundle_hash(bundle)
    except ValueError as exc:
        assert "missing_policy_bundle_key:rules" in str(exc)
    else:
        raise AssertionError("expected ValueError for missing policy bundle key")


def test_hgc074_persists_active_cloud_policy_version_in_guard_store(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    store = GuardStore(home)
    bundle = _sample_policy_bundle()
    validated_bundle, reason = _validate_policy_bundle(bundle)

    assert reason is None
    assert validated_bundle is not None

    store.set_sync_payload("policy_bundle", validated_bundle, "2026-04-19T00:00:10+00:00")

    reopened = GuardStore(home)
    persisted = reopened.get_sync_payload("policy_bundle")

    assert isinstance(persisted, dict)
    assert persisted["bundleVersion"] == validated_bundle["bundleVersion"]


def test_hgc075_preserves_last_known_good_policy_on_invalid_update(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    valid_bundle = _sample_policy_bundle()
    validated_bundle, reason = _validate_policy_bundle(valid_bundle)

    assert reason is None
    assert validated_bundle is not None

    store.set_sync_payload("policy_bundle", validated_bundle, now)
    store.set_sync_payload("policy_bundle_last_good", validated_bundle, now)

    invalid_bundle = dict(valid_bundle)
    del invalid_bundle["rules"]
    rejected_bundle, rejection_reason = _validate_policy_bundle(invalid_bundle)

    assert rejected_bundle is None
    assert rejection_reason == "missing_required_field"

    store.set_sync_payload(
        "policy_bundle_last_error",
        {"reason": rejection_reason or "invalid_policy_bundle"},
        now,
    )

    assert store.get_sync_payload("policy_bundle_last_good") == validated_bundle
    assert store.get_sync_payload("policy_bundle") == validated_bundle
    assert store.get_sync_payload("policy_bundle_last_error") == {
        "reason": "missing_required_field",
    }


def test_signed_policy_bundle_rejects_attacker_self_signed_key() -> None:
    attacker_key = policy_bundle_test_verification_key(key_id="attacker-self-signed-key")
    bundle = sign_policy_bundle(_sample_policy_bundle(), key=attacker_key)

    validated_bundle, reason = _validate_policy_bundle(bundle, trusted_keys=(), anchored_keys=())

    assert validated_bundle is None
    assert reason == "trusted_key_unavailable"


def test_signed_policy_bundle_accepts_trusted_sync_verification_keys() -> None:
    bundle, trusted_keys = _signed_policy_bundle()

    validated_bundle, reason = _validate_policy_bundle(
        bundle,
        trusted_keys=trusted_keys,
        anchored_keys=trusted_keys,
    )

    assert reason is None
    assert validated_bundle is not None


def test_signed_policy_bundle_rejects_sync_only_keys_without_anchor() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    sync_payload = {
        "policyBundleVerificationKeys": [trusted_keys[0].to_dict()],
    }

    validated_bundle, reason, _ = validate_synced_policy_bundle(
        bundle,
        stored_keyring=None,
        sync_payload=sync_payload,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert validated_bundle is None
    assert reason == "trusted_key_unavailable"


def test_validate_synced_policy_bundle_does_not_persist_unanchored_sync_keys() -> None:
    bundle, anchored_keys = _signed_policy_bundle(key_id="legitimate-anchor-key")
    attacker_key = policy_bundle_test_verification_key(
        key_id="attacker-sync-key",
    )
    stored_keyring = {
        "keys": [anchored_keys[0].to_dict()],
    }
    sync_payload = {
        "policyBundleVerificationKeys": [
            anchored_keys[0].to_dict(),
            attacker_key.to_dict(),
        ],
    }

    validated_bundle, reason, persistable_keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert reason is None
    assert validated_bundle is not None
    assert {key.key_id for key in persistable_keys} == {"legitimate-anchor-key"}

    attacker_bundle = sign_policy_bundle(_sample_policy_bundle(), key=attacker_key)

    promoted_keyring = {"keys": [item.to_dict() for item in persistable_keys]}
    promoted_bundle, promoted_reason, _ = validate_synced_policy_bundle(
        attacker_bundle,
        stored_keyring=promoted_keyring,
        sync_payload=None,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert promoted_bundle is None
    assert promoted_reason == "untrusted_signing_key"


def test_validate_synced_policy_bundle_ignores_malformed_sync_keyring() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    stored_keyring = {
        "keys": [trusted_keys[0].to_dict()],
    }
    sync_payload = {
        "policyBundleVerificationKeys": ["not-a-key-object"],
    }

    validated_bundle, reason, _ = validate_synced_policy_bundle(
        bundle,
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert reason is None
    assert validated_bundle is not None


def test_live_managed_anchor_overrides_user_store_key_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed_keyring = policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID)
    managed_state = _managed_policy_state(managed_keyring)
    review_public_key = review_verification_keys()[0]
    attacker_key = policy_bundle_verification_key_from_public_key(
        key_id=_TEST_SIGNING_KEY.key_id,
        public_key_pem=str(review_public_key["publicKeyPem"]),
        purpose=POLICY_BUNDLE_KEY_PURPOSE,
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )
    attacker_store_keyring = policy_bundle_keyring_payload(
        (attacker_key,),
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.policy.load_managed_policy",
        lambda: managed_state,
    )

    trusted_keys, anchored_keys = policy_bundle_verification_context(
        stored_keyring=attacker_store_keyring,
    )
    validated_bundle, reason, persisted_keys = validate_synced_policy_bundle(
        _sample_policy_bundle(),
        stored_keyring=attacker_store_keyring,
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert trusted_keys == (_TEST_SIGNING_KEY,)
    assert anchored_keys == (_TEST_SIGNING_KEY,)
    assert reason is None
    assert validated_bundle is not None
    assert persisted_keys == ()


@pytest.mark.parametrize(
    "managed_state",
    [
        _managed_policy_state(None),
        _managed_policy_state(policy_bundle_keyring_payload((), workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID)),
        ManagedPolicyState(
            "invalid",
            "managed-policy-test",
            reason_code="managed_policy_invalid",
        ),
        ManagedPolicyState(
            "inaccessible",
            "managed-policy-test",
            reason_code="managed_policy_inaccessible",
        ),
    ],
    ids=("omitted", "empty", "invalid", "inaccessible"),
)
def test_managed_policy_without_usable_anchor_ignores_user_store_keyring(
    monkeypatch: pytest.MonkeyPatch,
    managed_state: ManagedPolicyState,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.policy.load_managed_policy",
        lambda: managed_state,
    )

    validated_bundle, reason, anchored_keys = validate_synced_policy_bundle(
        _sample_policy_bundle(),
        stored_keyring=policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert validated_bundle is None
    assert reason == "trusted_key_unavailable"
    assert anchored_keys == ()


def test_absent_managed_policy_retains_local_anchor_compatibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.policy.load_managed_policy",
        lambda: ManagedPolicyState(
            "absent",
            "managed-policy-test",
            reason_code="managed_policy_absent",
        ),
    )

    validated_bundle, reason, anchored_keys = validate_synced_policy_bundle(
        _sample_policy_bundle(),
        stored_keyring=policy_bundle_test_keyring(workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID),
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert reason is None
    assert validated_bundle is not None
    assert anchored_keys == (_TEST_SIGNING_KEY,)


def test_strict_policy_bundle_keyring_contract_loads_workspace_bound_keys() -> None:
    payload = policy_bundle_keyring_payload(
        (_TEST_SIGNING_KEY,),
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    loaded = load_policy_bundle_verification_keys(
        payload,
        require_keyring_contract=True,
    )

    assert payload["contractVersion"] == POLICY_BUNDLE_KEYRING_CONTRACT_VERSION
    assert payload["purpose"] == POLICY_BUNDLE_KEY_PURPOSE
    assert loaded == (_TEST_SIGNING_KEY,)


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "error_field"),
    [
        ("contractVersion", "guard-policy-keyring.v2", "contractVersion"),
        ("purpose", "supply_chain", "purpose"),
        ("workspaceId", "", "workspaceId"),
    ],
)
def test_policy_bundle_keyring_rejects_invalid_wrapper_metadata_even_in_legacy_mode(
    field_name: str,
    invalid_value: object,
    error_field: str,
) -> None:
    payload = policy_bundle_keyring_payload(
        (_TEST_SIGNING_KEY,),
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )
    payload[field_name] = invalid_value

    with pytest.raises(ValueError, match=error_field):
        load_policy_bundle_verification_keys(payload)


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "error_field"),
    [
        ("purpose", "supply_chain", "key_purpose_mismatch"),
        ("workspaceId", "workspace-2", "key_workspace_mismatch"),
    ],
)
def test_strict_policy_bundle_keyring_rejects_per_key_wrapper_mismatch(
    field_name: str,
    invalid_value: object,
    error_field: str,
) -> None:
    payload = policy_bundle_keyring_payload(
        (_TEST_SIGNING_KEY,),
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )
    keys = payload["keys"]
    assert isinstance(keys, list)
    key_payload = keys[0]
    assert isinstance(key_payload, dict)
    key_payload[field_name] = invalid_value

    with pytest.raises(ValueError, match=error_field):
        load_policy_bundle_verification_keys(
            payload,
            require_keyring_contract=True,
        )


def test_strict_policy_bundle_keyring_rejects_duplicate_key_ids() -> None:
    payload = policy_bundle_keyring_payload(
        (_TEST_SIGNING_KEY, _TEST_SIGNING_KEY),
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    with pytest.raises(ValueError, match="duplicate_key_id"):
        load_policy_bundle_verification_keys(
            payload,
            require_keyring_contract=True,
        )


def test_strict_policy_bundle_keyring_rejects_malformed_validity() -> None:
    payload = policy_bundle_keyring_payload(
        (_TEST_SIGNING_KEY,),
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )
    keys = payload["keys"]
    assert isinstance(keys, list)
    key_payload = keys[0]
    assert isinstance(key_payload, dict)
    key_payload["validUntil"] = 0

    assert (
        safe_load_policy_bundle_verification_keys(
            payload,
            require_keyring_contract=True,
        )
        == ()
    )


def test_policy_bundle_keyring_legacy_shapes_require_explicit_non_strict_mode() -> None:
    key_payload = _TEST_SIGNING_KEY.to_dict()
    bare_list = [key_payload]
    keys_wrapper = {"keys": [key_payload]}

    assert load_policy_bundle_verification_keys(bare_list) == (_TEST_SIGNING_KEY,)
    assert load_policy_bundle_verification_keys(keys_wrapper) == (_TEST_SIGNING_KEY,)
    with pytest.raises(ValueError, match="wrapper"):
        load_policy_bundle_verification_keys(
            bare_list,
            require_keyring_contract=True,
        )
    with pytest.raises(ValueError, match="contractVersion"):
        load_policy_bundle_verification_keys(
            keys_wrapper,
            require_keyring_contract=True,
        )


def test_policy_bundle_keyring_rejects_partial_wrapper_in_non_strict_mode() -> None:
    partial_wrapper = {
        "contractVersion": POLICY_BUNDLE_KEYRING_CONTRACT_VERSION,
        "keys": [_TEST_SIGNING_KEY.to_dict()],
    }

    with pytest.raises(ValueError, match="purpose"):
        load_policy_bundle_verification_keys(partial_wrapper)


@pytest.mark.parametrize(
    ("field_name", "malformed_value"),
    [
        ("validFrom", ""),
        ("validFrom", 0),
        ("validUntil", ""),
        ("validUntil", 0),
    ],
)
def test_malformed_anchor_validity_never_becomes_an_unbounded_trust_window(
    field_name: str,
    malformed_value: object,
) -> None:
    bundle = _sample_policy_bundle()
    malformed_anchor = _TEST_SIGNING_KEY.to_dict()
    malformed_anchor[field_name] = malformed_value

    validated_bundle, reason, anchored_keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring={"keys": [malformed_anchor]},
        expected_workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
    )

    assert validated_bundle is None
    assert reason == "trusted_key_unavailable"
    assert anchored_keys == ()


def test_signed_policy_bundle_rejects_expired_signing_key() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    expired_key = policy_bundle_verification_key_from_public_key(
        key_id=trusted_keys[0].key_id,
        public_key_pem=trusted_keys[0].public_key_pem,
        workspace_id=TEST_POLICY_BUNDLE_WORKSPACE_ID,
        valid_until="2020-01-01T00:00:00Z",
    )

    validated_bundle, reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(expired_key,),
        anchored_keys=(expired_key,),
    )

    assert validated_bundle is None
    assert reason == "signing_key_not_current"


def test_digest_only_bundle_stays_rejected_after_policy_and_hash_recomputation() -> None:
    bundle = _sample_policy_bundle()
    rules = list(bundle["rules"])
    rules[0] = {**rules[0], "action": "allow"}
    bundle["rules"] = rules
    bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "unsupported_signature_algorithm"


@pytest.mark.parametrize(
    ("signature", "expected_reason"),
    [
        (None, "missing_signature"),
        ("not+strict/base64%%%", "invalid_signature_encoding"),
        ("Zm9v\n", "invalid_signature_encoding"),
    ],
)
def test_policy_bundle_rejects_missing_or_noncanonical_signature_encoding(
    signature: object,
    expected_reason: str,
) -> None:
    bundle = _sample_policy_bundle()
    verifier = dict(bundle["verifier"])
    verifier["signature"] = signature
    bundle["verifier"] = verifier

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == expected_reason


def test_policy_bundle_rejects_unknown_asymmetric_algorithm() -> None:
    bundle = _sample_policy_bundle()
    verifier = dict(bundle["verifier"])
    verifier["algorithm"] = "rsa-pkcs1v15-sha256"
    bundle["verifier"] = verifier

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "unsupported_signature_algorithm"


def test_policy_bundle_rejects_missing_signing_key_id() -> None:
    bundle = _sample_policy_bundle()
    verifier = dict(bundle["verifier"])
    verifier.pop("keyId")
    bundle["verifier"] = verifier

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "missing_signing_key_id"


def test_policy_bundle_rejects_unknown_key_even_when_hashes_are_recomputed() -> None:
    bundle = _sample_policy_bundle()
    verifier = dict(bundle["verifier"])
    verifier["keyId"] = "unknown-policy-key"
    bundle["verifier"] = verifier
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "untrusted_signing_key"


def test_policy_bundle_rejects_embedded_public_key_substitution() -> None:
    bundle = _sample_policy_bundle()
    verifier = dict(bundle["verifier"])
    verifier["publicKeyPem"] = "-----BEGIN PUBLIC KEY-----\nattacker\n-----END PUBLIC KEY-----"
    bundle["verifier"] = verifier

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "signing_key_fingerprint_mismatch"


def test_policy_bundle_rejects_modified_policy_after_all_hashes_are_recomputed() -> None:
    bundle = _sample_policy_bundle()
    rules = list(bundle["rules"])
    rules[0] = {**rules[0], "action": "allow"}
    bundle["rules"] = rules
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "bundle_signature_invalid"


def test_policy_bundle_rejects_payload_hash_mismatch_independently() -> None:
    bundle = _sample_policy_bundle()
    bundle["payloadHash"] = "sha256:" + ("0" * 64)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "payload_hash_mismatch"


def test_policy_bundle_accepts_and_normalizes_uppercase_payload_hash() -> None:
    bundle = _sample_policy_bundle()
    expected_hash = payload_hash_for_policy_bundle(bundle)
    bundle["payloadHash"] = f"SHA256:{expected_hash.upper()}"

    validated, reason = _validate_policy_bundle(bundle)

    assert reason is None
    assert validated is not None
    assert validated["payloadHash"] == expected_hash


def test_policy_bundle_rejects_wrong_workspace_before_rule_application() -> None:
    workspace_b_key = policy_bundle_test_verification_key(workspace_id="workspace-b")
    bundle = sign_policy_bundle(_sample_policy_bundle(), workspace_id="workspace-b", key=workspace_b_key)

    validated, reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(workspace_b_key,),
        anchored_keys=(workspace_b_key,),
        expected_workspace_id="workspace-a",
    )

    assert validated is None
    assert reason == "wrong_workspace"


def test_policy_bundle_rejects_revoked_or_wrong_purpose_anchor() -> None:
    bundle = _sample_policy_bundle()
    revoked_key = replace(_TEST_SIGNING_KEY, state="revoked")
    grace_key = replace(_TEST_SIGNING_KEY, state="grace")
    wrong_purpose_key = replace(_TEST_SIGNING_KEY, purpose="supply_chain")
    wrong_workspace_key = replace(_TEST_SIGNING_KEY, workspace_id="workspace-2")

    revoked, revoked_reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(revoked_key,),
        anchored_keys=(revoked_key,),
    )
    grace, grace_reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(grace_key,),
        anchored_keys=(grace_key,),
    )
    wrong_purpose, purpose_reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(wrong_purpose_key,),
        anchored_keys=(wrong_purpose_key,),
    )
    wrong_workspace, workspace_reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(wrong_workspace_key,),
        anchored_keys=(wrong_workspace_key,),
    )

    assert revoked is None
    assert revoked_reason == "signing_key_revoked"
    assert grace is None
    assert grace_reason == "signing_key_not_current"
    assert wrong_purpose is None
    assert purpose_reason == "signing_key_purpose_mismatch"
    assert wrong_workspace is None
    assert workspace_reason == "signing_key_workspace_mismatch"


def test_sync_advertisement_cannot_extend_an_expired_anchor() -> None:
    bundle = _sample_policy_bundle()
    expired_anchor = replace(_TEST_SIGNING_KEY, valid_until="2020-01-01T00:00:00Z")
    advertised_active_copy = replace(expired_anchor, state="active", valid_until=None)

    validated, reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(advertised_active_copy,),
        anchored_keys=(expired_anchor,),
    )

    assert validated is None
    assert reason == "signing_key_not_current"


def test_policy_bundle_rejects_signing_key_before_validity_window() -> None:
    bundle = _sample_policy_bundle()
    future_anchor = replace(_TEST_SIGNING_KEY, valid_from="2099-01-01T00:00:00Z")

    validated, reason = _validate_policy_bundle(
        bundle,
        trusted_keys=(future_anchor,),
        anchored_keys=(future_anchor,),
    )

    assert validated is None
    assert reason == "signing_key_not_current"


def test_expired_policy_bundle_is_rejected() -> None:
    bundle = _sample_policy_bundle()
    bundle["issuedAt"] = "2020-01-01T00:00:00Z"
    bundle["expiresAt"] = "2020-01-02T00:00:00Z"
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)

    validated, reason = _validate_policy_bundle(bundle, now=1_800_000_000)

    assert validated is None
    assert reason == "bundle_expired"


def test_canonical_signed_payload_binds_order_optional_fields_acknowledgements_and_workspace() -> None:
    bundle = _sample_policy_bundle()
    baseline = canonical_policy_bundle_payload(bundle)
    reordered = {key: bundle[key] for key in reversed(bundle)}
    verifier_without_signature = dict(bundle["verifier"])
    verifier_without_signature.pop("signature")
    reordered["verifier"] = verifier_without_signature

    assert canonical_policy_bundle_payload(reordered) == baseline

    with_ack = dict(bundle)
    with_ack["acknowledgements"] = [{"deviceId": "device-1", "status": "synced"}]
    assert canonical_policy_bundle_payload(with_ack) != baseline

    different_workspace = dict(bundle)
    different_workspace["workspaceId"] = "workspace-2"
    assert canonical_policy_bundle_payload(different_workspace) != baseline

    with_optional_field = dict(bundle)
    with_optional_field["receiptRedactionLevel"] = "metadata"
    assert canonical_policy_bundle_payload(with_optional_field) != baseline

    with_cloud_exception = dict(bundle)
    with_cloud_exception["cloudExceptions"] = [
        {
            "exceptionId": "artifact:test",
            "effect": "allow",
            "scope": "artifact",
            "owner": "security@example.com",
            "expiresAt": "2099-01-01T00:00:00Z",
        }
    ]
    assert canonical_policy_bundle_payload(with_cloud_exception) != baseline


def test_signed_optional_fields_survive_validation_and_cached_revalidation() -> None:
    bundle = _sample_policy_bundle()
    bundle["cloudExceptions"] = []
    bundle["minDaemonVersion"] = "2.0.0"
    bundle["receiptRedactionLevel"] = "partial"
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)

    persisted, reason = _validate_policy_bundle(bundle)

    assert reason is None
    assert persisted is not None
    assert persisted["cloudExceptions"] == []
    assert persisted["minDaemonVersion"] == "2.0.0"
    assert persisted["receiptRedactionLevel"] == "partial"
    cached, cached_reason = _validate_policy_bundle(persisted)
    assert cached_reason is None
    assert cached == persisted


@pytest.mark.parametrize("value", [None, "", "metadata", [], {}])
def test_policy_bundle_rejects_noncanonical_receipt_redaction_level(value: object) -> None:
    bundle = _sample_policy_bundle()
    bundle["receiptRedactionLevel"] = value
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "invalid_receipt_redaction_level"


@pytest.mark.parametrize("value", [None, "", "not-a-version", [], {}])
def test_policy_bundle_rejects_noncanonical_min_daemon_version(value: object) -> None:
    bundle = _sample_policy_bundle()
    bundle["minDaemonVersion"] = value
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "invalid_min_daemon_version"


def test_policy_bundle_rejects_unsupported_min_daemon_version() -> None:
    bundle = _sample_policy_bundle()
    bundle["minDaemonVersion"] = "999999.0.0"
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "unsupported_daemon_version"


def test_policy_bundle_rejects_explicit_null_cloud_exceptions() -> None:
    bundle = _sample_policy_bundle()
    bundle["cloudExceptions"] = None
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)

    validated, reason = _validate_policy_bundle(bundle)

    assert validated is None
    assert reason == "invalid_cloud_exceptions"


def test_hgc075_updates_last_known_good_on_valid_replacement(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    first_bundle = _sample_policy_bundle()
    first_validated, first_reason = _validate_policy_bundle(first_bundle)

    assert first_reason is None
    assert first_validated is not None

    store.set_sync_payload("policy_bundle", first_validated, now)
    store.set_sync_payload("policy_bundle_last_good", first_validated, now)

    replacement_bundle = _sample_policy_bundle()
    replacement_bundle["bundleVersion"] = "policy-2026-04-20.1"
    replacement_bundle = sign_policy_bundle(replacement_bundle, key=_TEST_SIGNING_KEY)
    replacement_validated, replacement_reason = _validate_policy_bundle(replacement_bundle)

    assert replacement_reason is None
    assert replacement_validated is not None

    store.set_sync_payload("policy_bundle", replacement_validated, now)
    store.set_sync_payload("policy_bundle_last_good", replacement_validated, now)

    assert store.get_sync_payload("policy_bundle") == replacement_validated
    assert store.get_sync_payload("policy_bundle_last_good") == replacement_validated


def _sample_rule(
    rule_id: str,
    action: str,
    ecosystems: list[str],
    matcher_families: list[str] | None = None,
) -> dict[str, object]:
    return {
        "ruleId": rule_id,
        "action": action,
        "reason": f"Reason for {rule_id}.",
        "matcherFamilies": matcher_families or ["package-request"],
        "scope": {
            "agents": [],
            "devices": [],
            "ecosystems": ecosystems,
            "environments": ["development"],
            "harnesses": ["codex"],
            "locations": [],
        },
    }


def _bundle_with_rules(rules: list[dict[str, object]]) -> dict[str, object]:
    bundle = _sample_policy_bundle()
    bundle["rules"] = rules
    return sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)


def test_hgps046_multi_rule_bundle_validates() -> None:
    rules = [
        _sample_rule("pkg-block", "block", ["npm"]),
        _sample_rule("mcp-allow", "allow", [], ["mcp"]),
        _sample_rule("tool-review", "review", ["python"], ["tool-action"]),
    ]
    bundle = _bundle_with_rules(rules)
    payload, reason = _validate_policy_bundle(bundle)
    assert payload is not None, reason
    assert len(payload["rules"]) == 3
    assert {rule["ruleId"] for rule in payload["rules"]} == {"pkg-block", "mcp-allow", "tool-review"}


def test_hgps048_multi_rule_bundle_rejects_malformed_entry() -> None:
    rules = [
        _sample_rule("pkg-block", "block", ["npm"]),
        {
            "ruleId": "bad-rule",
            "action": "not-an-action",
            "reason": "Bad action.",
            "matcherFamilies": ["package-request"],
        },
    ]
    bundle = _bundle_with_rules(rules)
    payload, reason = _validate_policy_bundle(bundle)
    assert payload is None
    assert reason == "invalid_rules"


def test_hgps50_sync_acknowledgement_counts_preserved() -> None:
    rules = [_sample_rule("pkg-block", "block", ["npm"])]
    acknowledgements = [
        {"deviceId": "device-a", "status": "synced"},
        {"deviceId": "device-b", "status": "pending"},
        {"deviceId": "device-c", "status": "failed"},
        {"deviceId": "device-d", "status": "offline"},
    ]
    bundle = _bundle_with_rules(rules)
    bundle["acknowledgements"] = acknowledgements
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)
    payload, reason = _validate_policy_bundle(bundle)
    assert payload is not None, reason
    acks = payload["acknowledgements"]
    assert len(acks) == 4
    statuses = {ack["deviceId"]: ack["status"] for ack in acks}
    assert statuses["device-a"] == "synced"
    assert statuses["device-b"] == "pending"
    assert statuses["device-c"] == "failed"
    assert statuses["device-d"] == "offline"
    assert sum(1 for ack in acks if ack["status"] == "synced") == 1
    assert sum(1 for ack in acks if ack["status"] == "pending") == 1
    assert sum(1 for ack in acks if ack["status"] == "failed") == 1


def test_hgps047_runtime_sync_persists_multi_rule_bundle(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    rules = [
        _sample_rule("mcp-allow", "allow", [], ["mcp"]),
        _sample_rule("pkg-block", "block", ["npm"]),
    ]
    acknowledgements = [
        {"deviceId": "agent-1", "status": "synced"},
        {"deviceId": "agent-2", "status": "synced"},
        {"deviceId": "agent-3", "status": "pending"},
        {"deviceId": "agent-4", "status": "failed"},
    ]
    bundle = _bundle_with_rules(rules)
    bundle["acknowledgements"] = acknowledgements
    bundle = sign_policy_bundle(bundle, key=_TEST_SIGNING_KEY)
    validated_bundle, reason = _validate_policy_bundle(bundle)

    assert reason is None
    assert validated_bundle is not None
    assert len(validated_bundle["rules"]) == 2

    store.set_sync_payload("policy_bundle", validated_bundle, now)
    reopened = GuardStore(tmp_path / "guard-home")
    persisted = reopened.get_sync_payload("policy_bundle")

    assert isinstance(persisted, dict)
    assert persisted["bundleVersion"] == validated_bundle["bundleVersion"]
    persisted_rules = persisted["rules"]
    assert isinstance(persisted_rules, list)
    assert len(persisted_rules) == 2
    persisted_acks = persisted["acknowledgements"]
    assert isinstance(persisted_acks, list)
    assert sum(1 for ack in persisted_acks if ack["status"] == "synced") == 2
    assert sum(1 for ack in persisted_acks if ack["status"] == "pending") == 1
    assert sum(1 for ack in persisted_acks if ack["status"] == "failed") == 1
