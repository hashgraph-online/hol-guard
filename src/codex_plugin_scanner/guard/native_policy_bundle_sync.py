"""Join ordinary source staging to an observed native publication and durable ACK."""

from __future__ import annotations

import sqlite3

from .native_mode import native_mode_requires_rust
from .native_policy_bundle_acceptance import capture_accepted_policy_bundle
from .native_policy_bundle_ack import commit_native_policy_bundle_acknowledgement
from .native_policy_snapshot import get_native_policy_snapshot_publisher
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .oauth_connection_authority import OAuthConnectionSnapshot
from .store import GuardStore


def publish_received_canonical_policy(
    store: GuardStore,
    bundle: dict[str, object],
    *,
    installation_id: str,
    expected_connection: OAuthConnectionSnapshot | None = None,
) -> dict[str, object] | None:
    """A missing/rejected/late publication leaves received or historical ACK intact."""
    if not native_mode_requires_rust():
        return None
    try:
        publisher = get_native_policy_snapshot_publisher(store)
        publisher.start()
        # The existing bounded publisher barrier includes generation recovery.
        # Source staging already requested publication and revoked prior readiness.
        if not publisher.wait_until_ready() or not native_mode_requires_rust():
            return None
        accepted = capture_accepted_policy_bundle(publisher, bundle=bundle, installation_id=installation_id)
        if accepted is None:
            return None
        return commit_native_policy_bundle_acknowledgement(publisher, accepted, expected_connection=expected_connection)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error, NativePolicySnapshotError):
        return None
