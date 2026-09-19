"""Read the effective policy payload persisted by Guard cloud sync."""

from __future__ import annotations

from typing import Protocol

from .policy_bundle_parser import (
    policy_bundle_is_enforceable,
    policy_bundle_is_version_downgrade,
)
from .policy_bundle_trusted_keys import (
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    validate_synced_policy_bundle,
)


class SyncPayloadReader(Protocol):
    """Minimal persistence interface needed to read synced policy state."""

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None: ...

    def get_cloud_workspace_id(self) -> str | None: ...


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def cached_policy_bundle_validation(
    store: SyncPayloadReader,
    cached_policy_bundle: object,
    *,
    now: float | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    if cached_policy_bundle is None or cached_policy_bundle == {}:
        return None, None
    if not isinstance(cached_policy_bundle, dict):
        return None, "invalid_policy_bundle"
    policy_bundle, _rejection_reason, _trusted_keys = validate_synced_policy_bundle(
        cached_policy_bundle,
        stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
        supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
        managed_keyring_provenance=store.get_sync_payload(MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY),
        expected_workspace_id=store.get_cloud_workspace_id(),
        now=now,
    )
    if policy_bundle is None:
        return None, _rejection_reason or "invalid_policy_bundle"
    if not policy_bundle_is_enforceable(policy_bundle):
        return None, "inactive_rollout_state"
    acceptance_checkpoint = store.get_sync_payload("policy_bundle_acceptance_checkpoint")
    if isinstance(acceptance_checkpoint, dict) and policy_bundle_is_version_downgrade(
        acceptance_checkpoint,
        policy_bundle,
    ):
        return None, "bundle_version_downgrade"
    return policy_bundle, None


def synced_policy_bundle_validation(
    store: SyncPayloadReader,
    *,
    now: float | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Return the authenticated cached bundle and its stable rejection reason."""

    return cached_policy_bundle_validation(
        store,
        store.get_sync_payload("policy_bundle"),
        now=now,
    )


def validated_synced_policy_bundle(
    store: SyncPayloadReader,
    *,
    now: float | None = None,
) -> dict[str, object] | None:
    """Return the current cached bundle only when its authority remains valid."""

    policy_bundle, _rejection_reason = synced_policy_bundle_validation(store, now=now)
    return policy_bundle


def synced_policy_payload(store: SyncPayloadReader) -> dict[str, object] | None:
    """Return policy defaults only from an authenticated cached bundle."""

    cached_policy_bundle = store.get_sync_payload("policy_bundle")
    policy_bundle, _rejection_reason = cached_policy_bundle_validation(store, cached_policy_bundle)
    if policy_bundle is not None:
        return policy_defaults_from_validated_bundle(policy_bundle)
    # The legacy top-level ``policy`` sync field is not covered by the policy
    # bundle signature. It must not become enforcement authority whether the
    # signed bundle is absent, malformed, expired, or explicitly cleared.
    return None


def policy_defaults_from_validated_bundle(policy_bundle: dict[str, object]) -> dict[str, object] | None:
    """Project defaults after the caller has authenticated the complete bundle."""

    policy_defaults = policy_bundle.get("policyDefaults")
    if policy_bundle.get("contractVersion") == "guard-policy-bundle.v2":
        document = policy_bundle.get("payload")
        spec = document.get("spec") if isinstance(document, dict) else None
        policy_defaults = spec.get("defaults") if isinstance(spec, dict) else None
    if not isinstance(policy_defaults, dict):
        return None
    payload = dict(policy_defaults)
    for source, target in (("issuedAt", "updatedAt"), ("bundleHash", "bundleHash")):
        value = _optional_string(policy_bundle.get(source))
        if value is not None:
            payload[target] = value
    bundle_version = policy_bundle.get("bundleVersion")
    if type(bundle_version) is int and bundle_version > 0:
        payload["bundleVersion"] = bundle_version
    elif (version_text := _optional_string(bundle_version)) is not None:
        payload["bundleVersion"] = version_text
    receipt_redaction_level = _optional_string(policy_bundle.get("receiptRedactionLevel"))
    if receipt_redaction_level is not None:
        payload["receiptRedactionLevel"] = receipt_redaction_level
    return payload


def offline_policy_lifetime(
    store: SyncPayloadReader,
    *,
    now: float | None = None,
) -> dict[str, object]:
    """Describe current vs last-good lifetime without authorizing expired grants."""

    current, current_error = cached_policy_bundle_validation(
        store,
        store.get_sync_payload("policy_bundle"),
        now=now,
    )
    last_good, last_good_error = cached_policy_bundle_validation(
        store,
        store.get_sync_payload("policy_bundle_last_good"),
        now=now,
    )
    revoked = current_error == "signing_key_revoked" or last_good_error == "signing_key_revoked"
    if current is not None:
        return {
            "state": "current-valid",
            "active": True,
            "retained": False,
            "expired": False,
            "recovery": False,
        }
    if last_good is not None:
        return {
            "state": "last-good-valid",
            "active": True,
            "retained": True,
            "expired": current_error == "bundle_expired",
            "currentError": current_error,
            "recovery": False,
        }
    errors = (current_error, last_good_error)
    if revoked:
        state = "recovery"
    elif any(error is not None and error != "bundle_expired" for error in errors):
        state = "rejected"
    elif "bundle_expired" in errors:
        state = "expired"
    else:
        state = "absent"
    return {
        "state": state,
        "active": False,
        "retained": False,
        "expired": state == "expired",
        "recovery": revoked,
        "currentError": current_error,
        "lastGoodError": last_good_error,
    }


__all__ = [
    "SyncPayloadReader",
    "cached_policy_bundle_validation",
    "offline_policy_lifetime",
    "policy_defaults_from_validated_bundle",
    "synced_policy_bundle_validation",
    "synced_policy_payload",
    "validated_synced_policy_bundle",
]
