"""Trusted verification keys for Guard Cloud policy bundle signatures."""

from __future__ import annotations

import hashlib
import importlib
import time
from dataclasses import dataclass

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .runtime.supply_chain_bundle_base import SupplyChainBundleMalformedError, _parse_iso_timestamp

_VERIFICATION_KEY_STATES = frozenset({"active", "grace", "revoked"})
POLICY_BUNDLE_KEY_PURPOSE = "policy_bundle"
POLICY_BUNDLE_KEYRING_CONTRACT_VERSION = "guard-policy-keyring.v1"
MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY = "managed_policy_bundle_keyring_provenance"
_POLICY_BUNDLE_KEYRING_FIELDS = frozenset({"contractVersion", "purpose", "workspaceId", "keys"})
_POLICY_BUNDLE_KEY_FIELDS = frozenset(
    {
        "fingerprintSha256",
        "keyId",
        "publicKeyPem",
        "state",
        "purpose",
        "workspaceId",
        "validFrom",
        "validUntil",
    }
)
_MINIMUM_POLICY_BUNDLE_RSA_BITS = 2048


def _policy_bundle_parser_module():
    return importlib.import_module(".policy_bundle_parser", __package__)


@dataclass(frozen=True, slots=True)
class PolicyBundleVerificationKey:
    key_id: str
    public_key_pem: str
    fingerprint_sha256: str
    state: str = "active"
    purpose: str = "unscoped"
    workspace_id: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprintSha256": self.fingerprint_sha256,
            "keyId": self.key_id,
            "purpose": self.purpose,
            "publicKeyPem": self.public_key_pem,
            "state": self.state,
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
            "workspaceId": self.workspace_id,
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
        if not isinstance(state, str) or state not in _VERIFICATION_KEY_STATES:
            raise ValueError("invalid_policy_bundle_verification_key:state")
        purpose = data.get("purpose")
        normalized_purpose = purpose.strip() if isinstance(purpose, str) and purpose.strip() else "unscoped"
        workspace_id = data.get("workspaceId", data.get("workspace_id"))
        normalized_workspace_id = (
            workspace_id.strip() if isinstance(workspace_id, str) and workspace_id.strip() else None
        )
        valid_from = data.get("validFrom")
        if valid_from is not None and (not isinstance(valid_from, str) or not valid_from.strip()):
            raise ValueError("invalid_policy_bundle_verification_key:validFrom")
        normalized_valid_from = valid_from if isinstance(valid_from, str) else None
        valid_until = data.get("validUntil")
        if valid_until is not None and (not isinstance(valid_until, str) or not valid_until.strip()):
            raise ValueError("invalid_policy_bundle_verification_key:validUntil")
        normalized_valid_until = valid_until if isinstance(valid_until, str) else None
        for field_name, value in (
            ("validFrom", normalized_valid_from),
            ("validUntil", normalized_valid_until),
        ):
            if value is None:
                continue
            try:
                _parse_iso_timestamp(value, field_name=field_name)
            except (SupplyChainBundleMalformedError, TypeError, ValueError) as error:
                raise ValueError(f"invalid_policy_bundle_verification_key:{field_name}") from error
        if (
            normalized_valid_from is not None
            and normalized_valid_until is not None
            and _parse_iso_timestamp(normalized_valid_from, field_name="validFrom")
            > _parse_iso_timestamp(normalized_valid_until, field_name="validUntil")
        ):
            raise ValueError("invalid_policy_bundle_verification_key:validity_window")
        normalized_pem = public_key_pem.replace("\r\n", "\n").strip()
        try:
            parsed_public_key = serialization.load_pem_public_key(normalized_pem.encode("utf-8"))
        except (TypeError, UnsupportedAlgorithm, ValueError) as error:
            raise ValueError("invalid_policy_bundle_verification_key:publicKeyPem") from error
        if not isinstance(parsed_public_key, RSAPublicKey):
            raise ValueError("invalid_policy_bundle_verification_key:publicKeyType")
        if parsed_public_key.key_size < _MINIMUM_POLICY_BUNDLE_RSA_BITS:
            raise ValueError("invalid_policy_bundle_verification_key:keySize")
        computed_fingerprint = policy_bundle_key_fingerprint(normalized_pem)
        if fingerprint.strip() != computed_fingerprint:
            raise ValueError("invalid_policy_bundle_verification_key:fingerprint_mismatch")
        return PolicyBundleVerificationKey(
            key_id=key_id.strip(),
            public_key_pem=normalized_pem,
            fingerprint_sha256=computed_fingerprint,
            state=state,
            purpose=normalized_purpose,
            workspace_id=normalized_workspace_id,
            valid_from=normalized_valid_from,
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
    purpose: str = POLICY_BUNDLE_KEY_PURPOSE,
    workspace_id: str | None = None,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> PolicyBundleVerificationKey:
    normalized_pem = public_key_pem.replace("\r\n", "\n").strip()
    return PolicyBundleVerificationKey(
        key_id=key_id.strip(),
        public_key_pem=normalized_pem,
        fingerprint_sha256=policy_bundle_key_fingerprint(normalized_pem),
        state=state,
        purpose=purpose,
        workspace_id=workspace_id,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def load_policy_bundle_verification_keys(
    raw: object,
    *,
    require_keyring_contract: bool = False,
) -> tuple[PolicyBundleVerificationKey, ...]:
    """Load policy verification keys, optionally requiring the managed wrapper.

    Bare key lists and ``{"keys": [...]}`` remain supported for legacy local
    stores when ``require_keyring_contract`` is false. Any wrapper metadata
    that is present is still authoritative and must be valid.
    """

    raw_keys = raw
    wrapper_purpose: str | None = None
    wrapper_workspace_id: str | None = None
    if require_keyring_contract and not isinstance(raw, dict):
        raise ValueError("invalid_policy_bundle_verification_keyring:wrapper")
    if isinstance(raw, dict):
        wrapper_fields_present = any(field in raw for field in ("contractVersion", "purpose", "workspaceId"))
        validate_wrapper = require_keyring_contract or wrapper_fields_present
        if validate_wrapper and raw.get("contractVersion") != POLICY_BUNDLE_KEYRING_CONTRACT_VERSION:
            raise ValueError("invalid_policy_bundle_verification_keyring:contractVersion")
        if validate_wrapper:
            if raw.get("purpose") != POLICY_BUNDLE_KEY_PURPOSE:
                raise ValueError("invalid_policy_bundle_verification_keyring:purpose")
            wrapper_purpose = POLICY_BUNDLE_KEY_PURPOSE
            workspace_id = raw.get("workspaceId")
            if not isinstance(workspace_id, str) or not workspace_id.strip() or workspace_id != workspace_id.strip():
                raise ValueError("invalid_policy_bundle_verification_keyring:workspaceId")
            wrapper_workspace_id = workspace_id
        raw_keys = raw.get("keys")
        if validate_wrapper and not isinstance(raw_keys, list):
            raise ValueError("invalid_policy_bundle_verification_keyring:keys")
        if validate_wrapper and set(raw) != _POLICY_BUNDLE_KEYRING_FIELDS:
            raise ValueError("invalid_policy_bundle_verification_keyring:fields")
    if not isinstance(raw_keys, list):
        return ()
    parsed: list[PolicyBundleVerificationKey] = []
    seen_key_ids: set[str] = set()
    for item in raw_keys:
        if not isinstance(item, dict):
            raise ValueError("invalid_policy_bundle_verification_keys")
        if require_keyring_contract and not set(item).issubset(_POLICY_BUNDLE_KEY_FIELDS):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_fields")
        if require_keyring_contract and not {
            "fingerprintSha256",
            "keyId",
            "publicKeyPem",
            "state",
            "purpose",
            "workspaceId",
        }.issubset(item):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_fields")
        parsed_key = PolicyBundleVerificationKey.from_dict(item)
        if wrapper_purpose is not None and (
            item.get("purpose") != wrapper_purpose or parsed_key.purpose != wrapper_purpose
        ):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_purpose_mismatch")
        if wrapper_workspace_id is not None and (
            item.get("workspaceId") != wrapper_workspace_id or parsed_key.workspace_id != wrapper_workspace_id
        ):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_workspace_mismatch")
        if parsed_key.key_id in seen_key_ids:
            raise ValueError("invalid_policy_bundle_verification_keys:duplicate_key_id")
        seen_key_ids.add(parsed_key.key_id)
        parsed.append(parsed_key)
    return tuple(parsed)


def safe_load_policy_bundle_verification_keys(
    raw: object,
    *,
    require_keyring_contract: bool = False,
) -> tuple[PolicyBundleVerificationKey, ...]:
    try:
        return load_policy_bundle_verification_keys(
            raw,
            require_keyring_contract=require_keyring_contract,
        )
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
            purpose="supply_chain",
            valid_until=item.valid_until,
        )
        for item in supply_chain_keys
    )


def builtin_policy_bundle_verification_keys() -> tuple[PolicyBundleVerificationKey, ...]:
    return ()


def managed_policy_bundle_verification_keys() -> tuple[
    bool,
    tuple[PolicyBundleVerificationKey, ...],
]:
    """Resolve policy anchors from the live machine-managed trust boundary.

    The boolean distinguishes "no managed keyring configured" from a managed
    fail-closed state such as an empty keyring, invalid policy source, or
    inaccessible machine authority. User-writable sync-state mirrors are never
    substituted when machine authority is configured or unhealthy.
    """

    try:
        from .mdm.policy import load_managed_policy

        managed_state = load_managed_policy()
    except Exception:  # pragma: no cover - defensive trust-boundary failure
        return True, ()
    if managed_state.status == "absent":
        return False, ()
    if managed_state.status != "active" or managed_state.policy is None:
        return True, ()
    managed_keyring = managed_state.policy.policy_bundle_keyring
    if managed_keyring is None:
        # A present machine policy owns this trust domain. Omitting the field
        # cannot resurrect a stale user-store mirror or a local substitution.
        return True, ()
    try:
        keys = load_policy_bundle_verification_keys(
            managed_keyring,
            require_keyring_contract=True,
        )
    except ValueError:
        return True, ()
    return True, keys


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
    return any(
        item.key_id == signing_key.key_id
        and item.fingerprint_sha256 == signing_key.fingerprint_sha256
        and item.purpose == signing_key.purpose
        and item.workspace_id == signing_key.workspace_id
        for item in anchored_keys
    )


def signing_key_is_current(
    signing_key: PolicyBundleVerificationKey,
    *,
    now: float | None = None,
    require_active: bool = False,
) -> bool:
    if signing_key.state == "revoked" or (require_active and signing_key.state != "active"):
        return False
    current_time = now if now is not None else time.time()
    if signing_key.valid_from is not None:
        try:
            valid_from = _parse_iso_timestamp(signing_key.valid_from, field_name="validFrom")
        except (SupplyChainBundleMalformedError, TypeError, ValueError):
            return False
        if current_time < valid_from:
            return False
    if signing_key.valid_until is None:
        return True
    try:
        expiry = _parse_iso_timestamp(signing_key.valid_until, field_name="validUntil")
    except (SupplyChainBundleMalformedError, TypeError, ValueError):
        return False
    return current_time <= expiry


def resolve_authorized_policy_bundle_signing_key(
    key_id: str,
    *,
    trusted_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
    expected_workspace_id: str | None,
    now: float | None = None,
) -> tuple[PolicyBundleVerificationKey | None, str | None]:
    """Resolve authority from the pinned anchor, never advertised key metadata."""

    if not anchored_keys:
        return None, "trusted_key_unavailable"
    advertised_key = resolve_policy_bundle_signing_key(key_id, trusted_keys)
    anchored_key = resolve_policy_bundle_signing_key(key_id, anchored_keys)
    if advertised_key is None or anchored_key is None:
        return None, "untrusted_signing_key"
    if advertised_key.fingerprint_sha256 != anchored_key.fingerprint_sha256:
        return None, "untrusted_signing_key"
    if anchored_key.purpose != POLICY_BUNDLE_KEY_PURPOSE:
        return None, "signing_key_purpose_mismatch"
    if expected_workspace_id is None:
        return None, "wrong_workspace"
    if anchored_key.workspace_id != expected_workspace_id:
        return None, "signing_key_workspace_mismatch"
    if anchored_key.state == "revoked":
        return None, "signing_key_revoked"
    if not signing_key_is_current(anchored_key, now=now, require_active=True):
        return None, "signing_key_not_current"
    return anchored_key, None


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
    if not isinstance(workspace_id, str) or not workspace_id.strip() or workspace_id != workspace_id.strip():
        raise ValueError("invalid_policy_bundle_verification_keyring:workspaceId")
    return {
        "contractVersion": POLICY_BUNDLE_KEYRING_CONTRACT_VERSION,
        "purpose": POLICY_BUNDLE_KEY_PURPOSE,
        "workspaceId": workspace_id,
        "keys": [item.to_dict() for item in keys],
    }


def _policy_bundle_verification_context_with_source(
    *,
    stored_keyring: object,
    sync_payload: dict[str, object] | None = None,
    supply_chain_keyring: object = None,
    managed_keyring_provenance: object = None,
) -> tuple[
    tuple[PolicyBundleVerificationKey, ...],
    tuple[PolicyBundleVerificationKey, ...],
    bool,
]:
    # Supply-chain keys deliberately live in a separate signing domain.  Keep
    # the argument for the stable call contract, but never merge those keys
    # into either policy discovery or policy authority: doing so would later
    # persist a purpose=supply_chain key inside a strict policy-keyring wrapper
    # and make the next cached-bundle validation fail closed.
    del supply_chain_keyring
    builtin_keys = builtin_policy_bundle_verification_keys()
    stored_keys = safe_load_policy_bundle_verification_keys(stored_keyring)
    sync_keys = load_policy_bundle_verification_keys_from_sync(sync_payload or {})
    managed_configured, managed_keys = managed_policy_bundle_verification_keys()
    if managed_configured:
        # Live machine authority is exclusive. Sync-advertised keys remain
        # unanchored metadata: an exact match can identify the current key, but
        # cannot expand or replace the managed trust root.
        trusted_keys = merge_policy_bundle_trusted_keys(managed_keys, sync_keys)
        return trusted_keys, managed_keys, True
    if managed_keyring_provenance is not None:
        # Older releases mirrored machine-managed keys into the same user
        # state slot used for local anchors. If the root-owned source and cache
        # disappear before repair, any surviving provenance marker quarantines
        # that legacy slot so removed or substituted managed trust cannot be
        # resurrected as local authority. The marker is only a fail-closed
        # migration signal; it never grants authority.
        trusted_keys = merge_policy_bundle_trusted_keys(builtin_keys, sync_keys)
        return trusted_keys, builtin_keys, False
    trusted_keys = merge_policy_bundle_trusted_keys(builtin_keys, stored_keys, sync_keys)
    anchored_keys = merge_policy_bundle_trusted_keys(builtin_keys, stored_keys)
    return trusted_keys, anchored_keys, False


def policy_bundle_verification_context(
    *,
    stored_keyring: object,
    sync_payload: dict[str, object] | None = None,
    supply_chain_keyring: object = None,
    managed_keyring_provenance: object = None,
) -> tuple[tuple[PolicyBundleVerificationKey, ...], tuple[PolicyBundleVerificationKey, ...]]:
    trusted_keys, anchored_keys, _managed_configured = _policy_bundle_verification_context_with_source(
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
        supply_chain_keyring=supply_chain_keyring,
        managed_keyring_provenance=managed_keyring_provenance,
    )
    return trusted_keys, anchored_keys


def validate_synced_policy_bundle(
    policy_bundle: dict[str, object],
    *,
    stored_keyring: object,
    sync_payload: dict[str, object] | None = None,
    supply_chain_keyring: object = None,
    managed_keyring_provenance: object = None,
    expected_workspace_id: str | None = None,
    now: float | None = None,
) -> tuple[dict[str, object] | None, str | None, tuple[PolicyBundleVerificationKey, ...]]:
    trusted_keys, anchored_keys, managed_configured = _policy_bundle_verification_context_with_source(
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
        supply_chain_keyring=supply_chain_keyring,
        managed_keyring_provenance=managed_keyring_provenance,
    )
    validated_bundle, rejection_reason = _policy_bundle_parser_module().validated_policy_bundle_payload(
        policy_bundle,
        trusted_verification_keys=trusted_keys,
        anchored_verification_keys=anchored_keys,
        expected_workspace_id=expected_workspace_id,
        now=now,
    )
    if validated_bundle is None:
        return None, rejection_reason, anchored_keys
    # Live machine authority remains exclusively root-owned. Never copy its
    # keys into the user-local anchor slot: an empty persisted keyring makes a
    # later source/cache removal fail closed instead of resurrecting the last
    # managed key as an unmanaged anchor.
    updated_keys = (
        ()
        if managed_configured
        else persistable_policy_bundle_keyring(
            anchored_keys=anchored_keys,
            policy_bundle=validated_bundle,
        )
    )
    return validated_bundle, None, updated_keys


def persistable_policy_bundle_keyring(
    *,
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
    policy_bundle: dict[str, object],
) -> tuple[PolicyBundleVerificationKey, ...]:
    workspace_id = policy_bundle.get("workspaceId")
    if not isinstance(workspace_id, str) or not workspace_id.strip():
        return ()
    policy_anchors = tuple(
        key for key in anchored_keys if key.purpose == POLICY_BUNDLE_KEY_PURPOSE and key.workspace_id == workspace_id
    )
    verifier = policy_bundle.get("verifier")
    if not isinstance(verifier, dict):
        return policy_anchors
    if verifier.get("algorithm") != "rsa-pss-sha256":
        return policy_anchors
    key_id = verifier.get("keyId")
    if not isinstance(key_id, str) or not key_id.strip():
        return policy_anchors
    signing_key = resolve_policy_bundle_signing_key(key_id.strip(), policy_anchors)
    if signing_key is None:
        return policy_anchors
    return merge_policy_bundle_trusted_keys(policy_anchors, (signing_key,))
