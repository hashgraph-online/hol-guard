"""Trusted verification keys for Guard Cloud policy bundle signatures.

Rust owns key admission, currency, authority resolution, trust-root assembly
and synced-bundle validation. This module keeps the key value type, the
managed-policy and supply-chain reads that feed the resident, and the
transport calls. A native failure is a typed rejection, never a Python verdict.
"""

from __future__ import annotations

import importlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, cast

from .native_policy_bundle import (
    PolicyBundleNativeError,
    native_policy_bundle,
    policy_bundle_chunks,
    policy_bundle_verdict,
)
from .stable_digest import sha256_content_digest

POLICY_BUNDLE_KEY_PURPOSE = "policy_bundle"
POLICY_BUNDLE_KEYRING_CONTRACT_VERSION = "guard-policy-keyring.v1"
MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY = "managed_policy_bundle_keyring_provenance"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


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
        keys = load_policy_bundle_verification_keys([data])
        if len(keys) != 1:
            raise ValueError("invalid_policy_bundle_verification_keys")
        return keys[0]


class _PolicyBundleV2Module(Protocol):
    def policy_bundle_v2_evidence(self, policy_bundle: dict[str, object]) -> dict[str, object]: ...

    def policy_bundle_v2_now_micros(self, now: datetime | None) -> int: ...


def _policy_bundle_v2_module() -> _PolicyBundleV2Module:
    module = importlib.import_module(".policy_bundle_v2", __package__)
    return cast(_PolicyBundleV2Module, cast(object, module))


def _keys_from_wire(items: object) -> tuple[PolicyBundleVerificationKey, ...]:
    if not isinstance(items, list):
        raise PolicyBundleNativeError("native_policy_bundle_authority_schema_mismatch")
    try:
        return tuple(
            PolicyBundleVerificationKey(
                key_id=item["keyId"],
                public_key_pem=item["publicKeyPem"],
                fingerprint_sha256=item["fingerprintSha256"],
                state=item["state"],
                purpose=item["purpose"],
                workspace_id=item["workspaceId"],
                valid_from=item["validFrom"],
                valid_until=item["validUntil"],
            )
            for item in items
        )
    except (KeyError, TypeError) as error:
        raise PolicyBundleNativeError("native_policy_bundle_authority_schema_mismatch") from error


def _wire(keys: tuple[PolicyBundleVerificationKey, ...]) -> list[dict[str, object]]:
    return [key.to_dict() for key in keys]


def policy_bundle_key_fingerprint(public_key_pem: str) -> str:
    normalized_pem = public_key_pem.replace("\r\n", "\n").strip()
    return sha256_content_digest(normalized_pem.encode("utf-8"))


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


def _load_keys(raw: object, *, require_keyring_contract: bool, safe: bool) -> tuple[PolicyBundleVerificationKey, ...]:
    result = policy_bundle_verdict(
        "load_keys", {"raw": raw, "require_contract": require_keyring_contract, "safe": safe}
    )
    return _keys_from_wire(result.get("keys"))


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

    return _load_keys(raw, require_keyring_contract=require_keyring_contract, safe=False)


def safe_load_policy_bundle_verification_keys(
    raw: object,
    *,
    require_keyring_contract: bool = False,
) -> tuple[PolicyBundleVerificationKey, ...]:
    try:
        return _load_keys(raw, require_keyring_contract=require_keyring_contract, safe=True)
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
    try:
        result = native_policy_bundle(
            "key_is_trusted", {"key": signing_key.to_dict(), "anchored_keys": _wire(anchored_keys)}
        )
    except ValueError:
        return False
    return result.get("value") is True


def signing_key_is_current(
    signing_key: PolicyBundleVerificationKey,
    *,
    now: float | None = None,
    require_active: bool = False,
) -> bool:
    try:
        result = native_policy_bundle(
            "key_is_current",
            {
                "key": signing_key.to_dict(),
                "now": now if now is not None else time.time(),
                "require_active": require_active,
            },
        )
    except ValueError:
        return False
    return result.get("value") is True


def resolve_authorized_policy_bundle_signing_key(
    key_id: str,
    *,
    trusted_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
    expected_workspace_id: str | None,
    now: float | None = None,
) -> tuple[PolicyBundleVerificationKey | None, str | None]:
    """Resolve authority from the pinned anchor, never advertised key metadata."""

    try:
        result = policy_bundle_verdict(
            "resolve_authorized",
            {
                "key_id": key_id,
                "trusted_keys": _wire(trusted_keys),
                "anchored_keys": _wire(anchored_keys),
                "expected_workspace_id": expected_workspace_id,
                "now": now if now is not None else time.time(),
            },
        )
        (key,) = _keys_from_wire([result.get("key")])
    except (PolicyBundleNativeError, ValueError) as error:
        return None, getattr(error, "code", "native_policy_bundle_authority_invalid")
    return key, None


def load_policy_bundle_verification_keys_from_sync(
    payload: dict[str, object],
) -> tuple[PolicyBundleVerificationKey, ...]:
    verification_keys = payload.get("policyBundleVerificationKeys")
    if verification_keys is None:
        return ()
    return safe_load_policy_bundle_verification_keys(verification_keys)


def migrate_legacy_policy_bundle_anchors(
    *,
    stored_keyring: object,
    sync_keys: tuple[PolicyBundleVerificationKey, ...],
    expected_workspace_id: str | None,
) -> tuple[PolicyBundleVerificationKey, ...]:
    """Scope an exact legacy anchor using authenticated sync metadata."""

    try:
        result = policy_bundle_verdict(
            "migrate_legacy",
            {
                "stored_keyring": stored_keyring,
                "sync_keys_raw": _wire(sync_keys),
                "expected_workspace_id": expected_workspace_id,
            },
        )
        return _keys_from_wire(result.get("keys"))
    except ValueError:
        return ()


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


def _context_request(
    *,
    stored_keyring: object,
    sync_payload: dict[str, object] | None,
    managed_keyring_provenance: object,
    expected_workspace_id: str | None,
) -> dict[str, object]:
    # Supply-chain keys deliberately live in a separate signing domain and are
    # never merged into policy discovery or authority. Machine-managed trust is
    # read here from the live boundary; the resident assembles the trust root.
    managed_configured, managed_keys = managed_policy_bundle_verification_keys()
    return {
        "stored_keyring": stored_keyring,
        "sync_keys_raw": (sync_payload or {}).get("policyBundleVerificationKeys"),
        "managed_configured": managed_configured,
        "managed_keys": _wire(managed_keys),
        "provenance_present": managed_keyring_provenance is not None,
        "expected_workspace_id": expected_workspace_id,
    }


def _policy_bundle_verification_context_with_source(
    *,
    stored_keyring: object,
    sync_payload: dict[str, object] | None = None,
    supply_chain_keyring: object = None,
    managed_keyring_provenance: object = None,
    expected_workspace_id: str | None = None,
) -> tuple[
    tuple[PolicyBundleVerificationKey, ...],
    tuple[PolicyBundleVerificationKey, ...],
    bool,
]:
    del supply_chain_keyring
    request = _context_request(
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
        managed_keyring_provenance=managed_keyring_provenance,
        expected_workspace_id=expected_workspace_id,
    )
    try:
        result = policy_bundle_verdict("verification_context", request)
        return (
            _keys_from_wire(result.get("trusted_keys")),
            _keys_from_wire(result.get("anchored_keys")),
            result.get("managed_configured") is True,
        )
    except ValueError:
        return (), (), request["managed_configured"] is True


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
    del supply_chain_keyring
    request = _context_request(
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
        managed_keyring_provenance=managed_keyring_provenance,
        expected_workspace_id=expected_workspace_id,
    )
    v2_module = _policy_bundle_v2_module()
    request["now"] = now if now is not None else time.time()
    request["key_now"] = time.time()
    request["now_micros"] = v2_module.policy_bundle_v2_now_micros(None)
    from . import policy_bundle_parser

    request["daemon_version"] = policy_bundle_parser.__version__
    try:
        request["bundle_chunks"] = policy_bundle_chunks(policy_bundle)
        result = native_policy_bundle("validate_synced", request)
        if result.get("needs_evidence") is True:
            request["evidence"] = v2_module.policy_bundle_v2_evidence(policy_bundle)
            result = native_policy_bundle("validate_synced", request)
        anchored = _keys_from_wire(result.get("anchored_keys"))
    except PolicyBundleNativeError as error:
        return None, error.code, ()
    reason = result.get("error")
    if isinstance(reason, str):
        return None, reason, anchored
    if result.get("ok") is not True:
        return None, "native_policy_bundle_authority_schema_mismatch", anchored
    updated = _keys_from_wire(result.get("updated_keys"))
    if result.get("contract") == "v2":
        return policy_bundle, None, updated
    payload_keys = result.get("payload_keys")
    payload_hash = result.get("payload_hash")
    if not isinstance(payload_keys, list) or not isinstance(payload_hash, str):
        return None, "native_policy_bundle_authority_schema_mismatch", anchored
    payload = {key: policy_bundle[key] for key in payload_keys if key != "payloadHash"}
    payload["payloadHash"] = payload_hash
    return payload, None, updated


def persistable_policy_bundle_keyring(
    *,
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
    policy_bundle: dict[str, object],
) -> tuple[PolicyBundleVerificationKey, ...]:
    try:
        result = policy_bundle_verdict(
            "persistable",
            {"anchored_keys": _wire(anchored_keys), "bundle_chunks": policy_bundle_chunks(policy_bundle)},
        )
        return _keys_from_wire(result.get("keys"))
    except ValueError:
        return ()
