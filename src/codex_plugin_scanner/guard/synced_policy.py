"""Read the effective policy payload persisted by Guard cloud sync."""

from __future__ import annotations

from typing import Protocol


class _SyncPayloadReader(Protocol):
    """Minimal persistence interface needed to read synced policy state."""

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None: ...


def _optional_string(value: object | None) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def synced_policy_payload(store: _SyncPayloadReader) -> dict[str, object] | None:
    """Return signed bundle defaults when present, otherwise legacy policy state."""

    policy_bundle = store.get_sync_payload("policy_bundle")
    if isinstance(policy_bundle, dict):
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
            return payload
    payload = store.get_sync_payload("policy")
    return payload if isinstance(payload, dict) else None


__all__ = ["synced_policy_payload"]
