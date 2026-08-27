"""Readiness checks for the synchronized Guard Review verification keyring."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .policy_bundle_trusted_keys import (
    safe_load_policy_bundle_verification_keys,
    signing_key_is_current,
)

if TYPE_CHECKING:
    from .store import GuardStore

REVIEW_VERIFICATION_KEYRING_SYNC_KEY = "guard_review_verification_keyring"
_REMOTE_APPROVAL_KEY_PURPOSE = "remote_approval"


def review_verification_keyring_ready(store: GuardStore) -> bool:
    """Return whether exact Review decisions can be verified for this workspace."""

    profile = store.get_cloud_sync_profile()
    workspace_id = profile.get("workspace_id") if isinstance(profile, dict) else None
    if not isinstance(workspace_id, str) or not workspace_id.strip():
        return False
    keys = safe_load_policy_bundle_verification_keys(store.get_sync_payload(REVIEW_VERIFICATION_KEYRING_SYNC_KEY))
    return any(
        key.purpose == _REMOTE_APPROVAL_KEY_PURPOSE
        and key.workspace_id == workspace_id
        and key.state != "revoked"
        and signing_key_is_current(key)
        for key in keys
    )


__all__ = ["REVIEW_VERIFICATION_KEYRING_SYNC_KEY", "review_verification_keyring_ready"]
