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
        policy_defaults = policy_bundle.get("policyDefaults")
        if isinstance(policy_defaults, dict):
            payload = dict(policy_defaults)
            issued_at = _optional_string(policy_bundle.get("issuedAt"))
            bundle_hash = _optional_string(policy_bundle.get("bundleHash"))
            bundle_version = _optional_string(policy_bundle.get("bundleVersion"))
            if issued_at is not None:
                payload["updatedAt"] = issued_at
            if bundle_hash is not None:
                payload["bundleHash"] = bundle_hash
            if bundle_version is not None:
                payload["bundleVersion"] = bundle_version
            receipt_redaction_level = _optional_string(policy_bundle.get("receiptRedactionLevel"))
            if receipt_redaction_level is not None:
                payload["receiptRedactionLevel"] = receipt_redaction_level
            return payload
    # The legacy top-level ``policy`` sync field is not covered by the policy
    # bundle signature. It must not become enforcement authority whether the
    # signed bundle is absent, malformed, expired, or explicitly cleared.
    return None


__all__ = [
    "SyncPayloadReader",
    "cached_policy_bundle_validation",
    "synced_policy_bundle_validation",
    "synced_policy_payload",
    "validated_synced_policy_bundle",
]
