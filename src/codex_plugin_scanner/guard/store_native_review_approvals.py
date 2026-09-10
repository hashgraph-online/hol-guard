"""Atomic, expiring retry consumption for a verified harness-native Accept.

A resolved inbox row is not a permanent capability. Bind it to the newly
computed request identity and consume it at most once, in the same transaction.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timedelta


def consume_native_review_approval(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_id: str,
    artifact_name: str,
    artifact_hash: str,
    launch_target: str,
    workspace: str | None,
    now: str,
) -> bool:
    current = datetime.fromisoformat(now)
    if current.tzinfo is None or current.utcoffset() is None:
        return False
    if len(artifact_hash) != 64 or any(c not in "0123456789abcdef" for c in artifact_hash):
        return False
    _ = connection.execute("begin immediate")
    rows = connection.execute(
        """select request_id, resolved_at, resolution_action, resolution_scope from approval_requests
           where status = 'resolved'
             and harness = ? and artifact_id = ? and artifact_name = ?
             and artifact_hash = ? and launch_target = ? and workspace is ?
           order by resolved_at desc limit 50""",
        (harness, artifact_id, artifact_name, artifact_hash, launch_target, workspace),
    ).fetchall()
    for row in rows:
        # A later denial supersedes an older allow for this exact request.
        if row["resolution_action"] != "allow" or row["resolution_scope"] != "artifact":
            return False
        try:
            approved_at = datetime.fromisoformat(row["resolved_at"])
        except (TypeError, ValueError):
            continue
        if approved_at.tzinfo is None or approved_at.utcoffset() is None:
            continue
        if not timedelta(0) <= current - approved_at <= timedelta(minutes=5):
            continue
        request_id = str(row["request_id"])
        effect_key = hashlib.sha256(f"native-review-once-v2\0{request_id}".encode()).hexdigest()
        inserted = connection.execute(
            """insert or ignore into guard_continuation_effects
               (effect_key, request_id, evidence_id, event_name, created_at)
               values (?, ?, ?, 'native-review.once-consumed', ?)""",
            (effect_key, request_id, artifact_hash, now),
        )
        return inserted.rowcount == 1
    return False
