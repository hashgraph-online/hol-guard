"""Off-path source presence can require authority, never grant permission."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


def refresh_source_requirement(publisher: NativePolicySnapshotPublisher) -> None:
    """Fence an existing remote source even when this runtime cannot consume it.

    Presence is deliberately conservative: malformed or unreadable authority
    must not turn into the source-free availability policy. Full authentication
    and supported-semantics checks remain in the actual snapshot compilers.
    """
    with publisher._condition:
        epoch = publisher._epoch
    try:
        with publisher.store._connect() as connection:
            connection.execute("begin")
            rows = connection.execute(
                "select state_key from sync_state where state_key in (?, ?, ?, ?) "
                "and payload_json is not null and trim(payload_json) != 'null'",
                (
                    "policy_bundle",
                    "policy_bundle_materialization",
                    "guard_review_memory_registry",
                    "guard_review_memory_policy_version",
                ),
            ).fetchall()
            retained = connection.execute(
                "select exists(select 1 from policy_decisions where source = 'cloud-signed-memory') as memory, "
                "exists(select 1 from policy_decisions where source in "
                "('cloud-sync','team-policy','policy-bundle','policy-bundle-canonical')) as bundle"
            ).fetchone()
        keys = {str(row["state_key"]) for row in rows}
        memory = bool(keys & {"guard_review_memory_registry", "guard_review_memory_policy_version"}) or bool(
            retained["memory"]
        )
        required = bool(keys) or memory or bool(retained["bundle"])
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError, sqlite3.Error):
        required = memory = True
    with publisher._condition:
        if publisher._epoch == epoch:
            publisher._source_authority_required = required
            publisher._source_memory_required = memory
