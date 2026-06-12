"""Trusted verification keys for Guard Cloud policy bundle signatures."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from .runtime.supply_chain_bundle_base import _parse_iso_timestamp

_VERIFICATION_KEY_STATES = frozenset({"active", "grace", "revoked"})


@dataclass(frozen=True, slots=True)
class PolicyBundleVerificationKey:
    key_id: str
    public_key_pem: str
    fingerprint_sha256: str
    state: str = "active"
    valid_until: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprintSha256": self.fingerprint_sha256,
            "keyId": self.key_id,
            "publicKeyPem": self.public_key_pem,
            "state": self.state,
            "validUntil": self.valid_until,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> PolicyBundleVerificationKey:
        key_id = data.get("keyId")
        public_key_pem = data.get("publicKeyPem")
        fingerprint = data.get("fingerprintSha256")
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("invalid_policy_bundle_verification_key:keyId")
        if not isinstance(public_key_pem, str) or not public_key_pem.strip():
            raise ValueError("invalid_policy_bundle_verification_key:publicKeyPem")
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            raise ValueError("invalid_policy_bundle_verification_key:fingerprintSha256")
        state = data.get("state")
        normalized_state = state if isinstance(state, str) and state in _VERIFICATION_KEY_STATES else "active"
        valid_until = data.get("validUntil")
        normalized_valid_until = valid_until if isinstance(valid_until, str) and valid_until.strip() else None
        normalized_pem = public_key_pem.replace("\r\n", "\n").strip()
        computed_fingerprint = policy_bundle_key_fingerprint(normalized_pem)
        if fingerprint.strip() != computed_fingerprint:
            raise ValueError("invalid_policy_bundle_verification_key:fingerprint_mismatch")
        return PolicyBundleVerificationKey(
            key_id=key_id.strip(),
            public_key_pem=normalized_pem,
            fingerprint_sha256=computed_fingerprint,
            state=normalized_state,
            valid_until=normalized_valid_until,
        )


def policy_bundle_key_fingerprint(public_key_pem: str) -> str:
    normalized_pem = public_key_pem.replace("\r\n", "\n").strip()
    return hashlib.sha256(normalized_pem.encode("utf-8")).hexdigest()


def policy_bundle_verification_key_from_public_key(
    *,
    key_id: str,
    public_key_pem: str,
    state: str = "active",
    valid_until: str | None = None,
) -> PolicyBundleVerificationKey:
    normalized_pem = public_key_pem.replace("\r\n", "\n").strip()
    return PolicyBundleVerificationKey(
        key_id=key_id.strip(),
        public_key_pem=normalized_pem,
        fingerprint_sha256=policy_bundle_key_fingerprint(normalized_pem),
        state=state,
        valid_until=valid_until,
    )


def load_policy_bundle_verification_keys(raw: object) -> tuple[PolicyBundleVerificationKey, ...]:
    raw_keys = raw
    if isinstance(raw, dict):
        raw_keys = raw.get("keys")
    if not isinstance(raw_keys, list):
        return ()
    parsed: list[PolicyBundleVerificationKey] = []
    for item in raw_keys:
        if not isinstance(item, dict):
            raise ValueError("invalid_policy_bundle_verification_keys")
        parsed.append(PolicyBundleVerificationKey.from_dict(item))
    return tuple(parsed)


def safe_load_policy_bundle_verification_keys(raw: object) -> tuple[PolicyBundleVerificationKey, ...]:
    try:
        return load_policy_bundle_verification_keys(raw)
    except ValueError:
        return ()


def policy_bundle_keys_from_supply_chain_keyring(raw: object) -> tuple[PolicyBundleVerificationKey, ...]:
    from .runtime.supply_chain_bundle_runtime import load_supply_chain_verification_keys

    try:
        supply_chain_keys = load_supply_chain_verification_keys(raw)
    except Exception:
        return ()
    return tuple(
        PolicyBundleVerificationKey(
            key_id=item.key_id,
            public_key_pem=item.public_key_pem,
            fingerprint_sha256=item.fingerprint_sha256,
            state=item.state,
            valid_until=item.valid_until,
        )
        for item in supply_chain_keys
    )


def builtin_policy_bundle_verification_keys() -> tuple[PolicyBundleVerificationKey, ...]:
    return ()


def merge_policy_bundle_trusted_keys(
    *sources: tuple[PolicyBundleVerificationKey, ...],
) -> tuple[PolicyBundleVerificationKey, ...]:
    merged: dict[str, PolicyBundleVerificationKey] = {}
    for source in sources:
        for key in source:
            merged[key.key_id] = key
    return tuple(merged[key_id] for key_id in sorted(merged))


def resolve_policy_bundle_signing_key(
    key_id: str,
    trusted_keys: tuple[PolicyBundleVerificationKey, ...],
) -> PolicyBundleVerificationKey | None:
    for key in trusted_keys:
        if key.key_id == key_id:
            return key
    return None


def signing_key_is_trusted(
    signing_key: PolicyBundleVerificationKey,
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
) -> bool:
    if not anchored_keys:
        return False
    trusted_fingerprints = {item.fingerprint_sha256 for item in anchored_keys}
    return signing_key.fingerprint_sha256 in trusted_fingerprints


def signing_key_is_current(
    signing_key: PolicyBundleVerificationKey,
    *,
    now: float | None = None,
) -> bool:
    if signing_key.state == "revoked":
        return False
    if signing_key.valid_until is None:
        return True
    current_time = now if now is not None else time.time()
    try:
        expiry = _parse_iso_timestamp(signing_key.valid_until, field_name="validUntil")
    except ValueError:
        return False
    return current_time <= expiry


def load_policy_bundle_verification_keys_from_sync(
    payload: dict[str, object],
) -> tuple[PolicyBundleVerificationKey, ...]:
    verification_keys = payload.get("policyBundleVerificationKeys")
    if verification_keys is None:
        return ()
    return safe_load_policy_bundle_verification_keys(verification_keys)


def policy_bundle_keyring_payload(
    keys: tuple[PolicyBundleVerificationKey, ...],
    *,
    workspace_id: str | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "keys": [item.to_dict() for item in keys],
    }
    if workspace_id is not None:
        payload["workspace_id"] = workspace_id
    return payload


def policy_bundle_verification_context(
    *,
    stored_keyring: object,
    sync_payload: dict[str, object] | None = None,
    supply_chain_keyring: object = None,
) -> tuple[tuple[PolicyBundleVerificationKey, ...], tuple[PolicyBundleVerificationKey, ...]]:
    builtin_keys = builtin_policy_bundle_verification_keys()
    stored_keys = safe_load_policy_bundle_verification_keys(stored_keyring)
    supply_chain_keys = policy_bundle_keys_from_supply_chain_keyring(supply_chain_keyring)
    sync_keys = load_policy_bundle_verification_keys_from_sync(sync_payload or {})
    trusted_keys = merge_policy_bundle_trusted_keys(builtin_keys, stored_keys, supply_chain_keys, sync_keys)
    anchored_keys = merge_policy_bundle_trusted_keys(builtin_keys, stored_keys, supply_chain_keys)
    return trusted_keys, anchored_keys


def validate_synced_policy_bundle(
    policy_bundle: dict[str, object],
    *,
    stored_keyring: object,
    sync_payload: dict[str, object] | None = None,
    supply_chain_keyring: object = None,
) -> tuple[dict[str, object] | None, str | None, tuple[PolicyBundleVerificationKey, ...]]:
    trusted_keys, anchored_keys = policy_bundle_verification_context(
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
        supply_chain_keyring=supply_chain_keyring,
    )
    from .policy_bundle_parser import validated_policy_bundle_payload

    validated_bundle, rejection_reason = validated_policy_bundle_payload(
        policy_bundle,
        trusted_verification_keys=trusted_keys,
        anchored_verification_keys=anchored_keys,
    )
    if validated_bundle is None:
        return None, rejection_reason, trusted_keys
    updated_keys = persistable_policy_bundle_keyring(
        trusted_keys=trusted_keys,
        policy_bundle=validated_bundle,
    )
    return validated_bundle, None, updated_keys


def persistable_policy_bundle_keyring(
    *,
    trusted_keys: tuple[PolicyBundleVerificationKey, ...],
    policy_bundle: dict[str, object],
) -> tuple[PolicyBundleVerificationKey, ...]:
    verifier = policy_bundle.get("verifier")
    if not isinstance(verifier, dict):
        return trusted_keys
    if verifier.get("algorithm") != "rsa-pss-sha256":
        return trusted_keys
    key_id = verifier.get("keyId")
    if not isinstance(key_id, str) or not key_id.strip():
        return trusted_keys
    signing_key = resolve_policy_bundle_signing_key(key_id.strip(), trusted_keys)
    if signing_key is None:
        return trusted_keys
    return merge_policy_bundle_trusted_keys(trusted_keys, (signing_key,))
