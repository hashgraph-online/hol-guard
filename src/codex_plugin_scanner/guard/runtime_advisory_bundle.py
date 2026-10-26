"""Sync context for runtime advisories carried in the cached supply-chain bundle.

Hands the native assessment the stored bundle response, the recorded sync
keyring and the recorded bundle entitlement as they are stored. The native
runtime checks the entitlement and verifies the bundle before any advisory
reaches matching; nothing here trusts or parses either. Reads the local store
only, never Cloud.
"""

from __future__ import annotations

import time
from typing import Any

NOT_CONNECTED = "runtime_advisory_bundle_not_connected"
NOT_CACHED = "runtime_advisory_bundle_not_cached"
BUNDLE_UNREADABLE = "runtime_advisory_bundle_unreadable"


def cached_advisory_bundle(store: Any, *, now: float | None = None) -> tuple[dict[str, object] | None, str | None]:
    """Return the native ``cached_bundle`` input, or ``None`` with the reason there is none."""

    workspace_id = store.get_cloud_workspace_id()
    if not isinstance(workspace_id, str) or not workspace_id:
        return None, NOT_CONNECTED
    cached = store.get_cached_supply_chain_bundle(workspace_id)
    if not isinstance(cached, dict):
        return None, NOT_CACHED
    response = {key: value for key, value in cached.items() if key != "cached_at"}
    return {
        "response": response,
        "workspace_id": workspace_id,
        "sync_keyring": store.get_sync_payload("supply_chain_bundle_keyring"),
        "entitlement": store.get_sync_payload("supply_chain_bundle_entitlement"),
        "now": time.time() if now is None else now,
    }, None


__all__ = ["BUNDLE_UNREADABLE", "NOT_CACHED", "NOT_CONNECTED", "cached_advisory_bundle"]
