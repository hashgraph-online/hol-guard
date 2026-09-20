"""Atomic, expiring retry consumption for a verified harness-native Accept.

A resolved inbox row is not a permanent capability. Bind it to the newly
computed request identity and consume it at most once, in the same transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from .daemon.hook_native_review_binding import native_review_binding_matches

_NATIVE_REVIEW_BINDING = re.compile(r"native-review-v4:[0-9a-f]{64}(?::[a-z0-9_-]{1,128}){4}")


def _aware_utc(value: object) -> datetime | None:
    """Parse one resolution timestamp and normalize its instant to UTC."""

    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


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
    policy_binding: Mapping[str, object] | None = None,
) -> bool:
    """Consume only the chronologically latest matching five-minute allow."""

    current = _aware_utc(now)
    if current is None or _NATIVE_REVIEW_BINDING.fullmatch(artifact_hash) is None:
        return False
    _ = connection.execute("begin immediate")
    rows = connection.execute(
        """select request_id, resolved_at, resolution_action, resolution_scope,
                  action_envelope_json, continuation_snapshot_json from approval_requests
           where status = 'resolved'
             and harness = ? and artifact_id = ? and artifact_name = ?
             and artifact_hash = ? and launch_target = ? and workspace is ?""",
        (harness, artifact_id, artifact_name, artifact_hash, launch_target, workspace),
    ).fetchall()
    resolved_rows: list[tuple[datetime, sqlite3.Row]] = []
    for row in rows:
        resolved_at = _aware_utc(row["resolved_at"])
        if resolved_at is None:
            # The latest decision cannot be established safely when a matching
            # row has an invalid timestamp, so do not reuse any older allow.
            return False
        resolved_rows.append((resolved_at, row))
    if not resolved_rows:
        return False
    resolved_rows.sort(key=lambda item: item[0], reverse=True)
    approved_at = resolved_rows[0][0]
    latest_rows = [row for resolved_at, row in resolved_rows if resolved_at == approved_at]
    # Same-instant decisions are one logical resolution set. Any conflict is
    # ambiguous and must fail closed rather than relying on SQLite row order.
    if any(row["resolution_action"] != "allow" or row["resolution_scope"] != "artifact" for row in latest_rows):
        return False
    if not timedelta(0) <= current - approved_at <= timedelta(minutes=5):
        return False
    if any(not _matches_policy_domain(row, harness=harness, current=policy_binding) for row in latest_rows):
        return False
    row = min(latest_rows, key=lambda candidate: str(candidate["request_id"]))
    request_id = str(row["request_id"])
    # Spend all equivalent decisions at this instant as one capability. This
    # prevents duplicate same-timestamp allows from being consumed separately.
    effect_key = hashlib.sha256(
        f"native-review-once-v3\0{artifact_hash}\0{approved_at.isoformat()}".encode()
    ).hexdigest()
    inserted = connection.execute(
        """insert or ignore into guard_continuation_effects
           (effect_key, request_id, evidence_id, event_name, created_at)
           values (?, ?, ?, 'native-review.once-consumed', ?)""",
        (effect_key, request_id, artifact_hash, current.isoformat()),
    )
    return inserted.rowcount == 1


def _matches_policy_domain(row: sqlite3.Row, *, harness: str, current: Mapping[str, object] | None) -> bool:
    """Check the stored native domain inside the one-use consumption transaction."""
    try:
        envelope = json.loads(row["action_envelope_json"]) if row["action_envelope_json"] is not None else None
        continuation = (
            json.loads(row["continuation_snapshot_json"]) if row["continuation_snapshot_json"] is not None else None
        )
    except (TypeError, ValueError):
        return False
    if envelope is not None and not isinstance(envelope, dict):
        return False
    if continuation is not None and not isinstance(continuation, dict):
        return False
    if harness == "codex" and isinstance(continuation, dict) and continuation.get("capability") == "suspended-response":
        return False
    return native_review_binding_matches({"action_envelope_json": envelope}, current)
