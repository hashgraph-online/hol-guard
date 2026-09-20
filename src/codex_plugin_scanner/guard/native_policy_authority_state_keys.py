"""Dependency-free state names shared by authority capture and invalidation."""

from __future__ import annotations

from typing import Final

POLICY_BUNDLE_MATERIALIZATION_KEY: Final = "policy_bundle_materialization"
MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY: Final = "managed_policy_bundle_keyring_provenance"
REVIEW_MEMORY_REGISTRY_KEY: Final = "guard_review_memory_registry"
REVIEW_MEMORY_VERSION_KEY: Final = "guard_review_memory_policy_version"
REVIEW_VERIFICATION_KEYRING_SYNC_KEY: Final = "guard_review_verification_keyring"
MANAGED_CONTROLS_ACTIVE_STATE_KEY: Final = "managed_controls_active"
MANAGED_CONTROLS_REVISION_STATE_KEY: Final = "managed_controls_revision"

# Capture ordering is stable. Adding an authority source here also makes its
# committed writes and deletions invalidate the registered publication barrier.
# OAuth remains source-specific and is handled by the existing credential path.
NATIVE_POLICY_AUTHORITY_SYNC_KEYS: Final = (
    "policy_bundle",
    "policy_bundle_keyring",
    "supply_chain_bundle_keyring",
    "policy_bundle_acceptance_checkpoint",
    POLICY_BUNDLE_MATERIALIZATION_KEY,
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    REVIEW_MEMORY_REGISTRY_KEY,
    REVIEW_MEMORY_VERSION_KEY,
    REVIEW_VERIFICATION_KEYRING_SYNC_KEY,
    "policy_integrity",
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
)
