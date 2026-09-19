"""Reconstruct signed memory rows and their authenticated materialization time."""

from __future__ import annotations

from typing import cast

from .policy_bundle_row_authority import PolicyBundleRowStore
from .review_memory_authority import REGISTRY_KEY, VERSION_KEY, bound_registry, memory_oauth_authority, registry_entries
from .review_oauth_binding import GuardReviewContractError
from .store_base import _canonical_utc_timestamp


def current_review_memory_row_identities(store: PolicyBundleRowStore, *, now: str) -> frozenset[tuple[object, ...]]:
    """Legacy or tampered rows cannot become authority from their source label."""
    try:
        oauth, binding = memory_oauth_authority(store)
        registry = bound_registry(store.get_sync_payload(REGISTRY_KEY), binding, store=store)
        version = store.get_sync_payload(VERSION_KEY)
        if registry is None or not isinstance(version, dict):
            return frozenset()
        if any(registry.get(key) != version.get(key) for key in ("policyVersion", "bundleHash")):
            return frozenset()
        integrity = registry.get("integrity")
        signed_at = cast(dict[str, object], integrity).get("signed_at") if isinstance(integrity, dict) else None
        if not isinstance(signed_at, str):
            return frozenset()
        # Every retained row is replaced in the same transaction that
        # signs this registry. Its MAC also authenticates signed_at.
        materialized_at = _canonical_utc_timestamp(signed_at)
        entries = registry_entries(registry, store=store, oauth=oauth, binding=binding, now=now)
    except (GuardReviewContractError, OSError, RuntimeError, TypeError, ValueError):
        return frozenset()
    identities: set[tuple[object, ...]] = set()
    for _, decision in entries.values():
        artifact_id, artifact_hash, workspace, publisher = store._normalized_policy_keys(decision)
        identities.add(
            (
                decision.harness,
                decision.scope,
                artifact_id,
                artifact_hash,
                workspace,
                publisher,
                decision.exact_command_sha256,
                decision.action,
                decision.reason,
                decision.owner,
                decision.source,
                _canonical_utc_timestamp(decision.expires_at) if decision.expires_at else None,
                materialized_at,
            )
        )
    return frozenset(identities)


__all__ = ["current_review_memory_row_identities"]
