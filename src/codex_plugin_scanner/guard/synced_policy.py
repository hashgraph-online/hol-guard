"""Read the effective policy payload persisted by Guard cloud sync."""

from __future__ import annotations

from typing import Protocol

from .policy_bundle_trusted_keys import validate_cached_policy_bundle
from .store_policy_trust_rows import PolicyBundleTrustRows


class PolicyTrustRowsReader(Protocol):
    """Minimal persistence interface needed to read synced policy state."""

    def policy_bundle_trust_rows(self, *, keys_only: bool = False) -> PolicyBundleTrustRows: ...


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def cached_policy_bundle_validation(
    store: PolicyTrustRowsReader,
    cached_policy_bundle: object,
    *,
    now: float | None = None,
    rows: PolicyBundleTrustRows | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Judge ``cached_policy_bundle`` against the stored keyrings, checkpoint and workspace.

    ``rows`` is a trust-row view the caller already read; without it the rows
    are read once here, so every input comes from the same snapshot.
    """

    if cached_policy_bundle is None or cached_policy_bundle == {}:
        return None, None
    if not isinstance(cached_policy_bundle, dict):
        return None, "invalid_policy_bundle"
    trust = rows if rows is not None else store.policy_bundle_trust_rows()
    policy_bundle, rejection_reason = validate_cached_policy_bundle(
        cached_policy_bundle,
        stored_keyring=trust.policy_bundle_keyring,
        acceptance_checkpoint=trust.acceptance_checkpoint,
        managed_keyring_provenance=trust.managed_keyring_provenance,
        expected_workspace_id=trust.workspace_id,
        now=now,
    )
    if policy_bundle is None:
        return None, rejection_reason or "invalid_policy_bundle"
    return policy_bundle, None


class LastGoodTrustRowsReader(Protocol):
    """Persistence interface that can also read the last good bundle's trust rows."""

    def policy_bundle_trust_rows(
        self, *, keys_only: bool = False, last_good: bool = False
    ) -> PolicyBundleTrustRows: ...


def last_good_policy_bundle_validation(
    store: LastGoodTrustRowsReader,
) -> tuple[dict[str, object] | None, str | None]:
    """Judge the last good bundle against the keyrings, checkpoint and workspace read with it."""

    rows = store.policy_bundle_trust_rows(last_good=True)
    return cached_policy_bundle_validation(store, rows.policy_bundle, rows=rows)


def synced_policy_bundle_validation(
    store: PolicyTrustRowsReader,
    *,
    now: float | None = None,
    rows: PolicyBundleTrustRows | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Return the authenticated cached bundle and its stable rejection reason."""

    trust = rows if rows is not None else store.policy_bundle_trust_rows()
    return cached_policy_bundle_validation(store, trust.policy_bundle, now=now, rows=trust)


def validated_synced_policy_bundle(
    store: PolicyTrustRowsReader,
    *,
    now: float | None = None,
) -> dict[str, object] | None:
    """Return the current cached bundle only when its authority remains valid."""

    policy_bundle, _rejection_reason = synced_policy_bundle_validation(store, now=now)
    return policy_bundle


def synced_policy_payload(store: PolicyTrustRowsReader) -> dict[str, object] | None:
    """Return policy defaults only from an authenticated cached bundle."""

    policy_bundle, _rejection_reason = synced_policy_bundle_validation(store)
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
    "LastGoodTrustRowsReader",
    "PolicyTrustRowsReader",
    "cached_policy_bundle_validation",
    "last_good_policy_bundle_validation",
    "synced_policy_bundle_validation",
    "synced_policy_payload",
    "validated_synced_policy_bundle",
]
