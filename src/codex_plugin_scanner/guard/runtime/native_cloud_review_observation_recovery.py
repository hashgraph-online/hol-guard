"""Recover actual native consumption observations outside the hook path.

Discovery is only a candidate source. Exact read-only native confirmation and
an immutable SDK source join are mandatory before producing a Review event.
Missing SQLite material remains a visible recovery failure, never new authority.

A candidate whose immutable source join can never succeed is quarantined in
durable sync state instead of pinning the discovery cursor forever. Quarantine
retains the native observation as diagnostic evidence; it mints no authority,
acknowledges nothing, and never discards the native journal record. Every other
failure stays retryable so uncertainty is never cleared by a timer or by an
attempt count.
"""

from __future__ import annotations

import sqlite3

from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from .native_cloud_review_application import record_native_application_observation
from .native_cloud_review_v4 import (
    NativeCloudReviewV4Error,
    decode_native_application_observation,
    discover_native_applications,
    request_native_cloud_review,
)

if TYPE_CHECKING:
    from ..store import GuardStore

_STATE_KEY = "guard_native_cloud_review_observation_recovery"
_QUARANTINE_KEY = f"{_STATE_KEY}:quarantine"
_QUARANTINE_SCHEMA = "guard-native-cloud-review-observation-quarantine.v1"
_QUARANTINE_LIMIT = 64
_PAGE_LIMIT = 8
_RECORD_FAILURE_REASONS = frozenset(
    {
        "native_application_immutable_binding_conflict",
        "native_application_pending_request_missing",
        "native_application_pending_request_changed",
        "native_application_delivery_cohort_changed",
    }
)
# Reasons that prove the immutable source join can never succeed for this
# candidate: the frozen SQLite original is permanently missing or changed, or
# an already-persisted immutable binding conflicts. Mismatched re-queries,
# absent snapshots that replay may still deliver, transports, and unknown
# errors are not evidence of permanence and must keep retrying.
_TERMINAL_REASONS = frozenset(
    {
        "native_application_immutable_binding_conflict",
        "native_application_pending_request_missing",
        "native_application_pending_request_changed",
        "native_application_delivery_cohort_changed",
        "native_cloud_review_v4_original_pending_mismatch",
    }
)


def _recovery_reason(error: Exception) -> str:
    if isinstance(error, NativeCloudReviewV4Error):
        return error.code
    reason = str(error)
    return reason if reason in _RECORD_FAILURE_REASONS else "native_application_observation_recovery_unavailable"


def _quarantine_entries(store: GuardStore) -> dict[str, dict[str, object]]:
    try:
        saved = store.get_sync_payload(_QUARANTINE_KEY)
    except (OSError, RuntimeError, sqlite3.Error, ValueError):
        return {}
    entries = saved.get("entries") if isinstance(saved, dict) else None
    if not isinstance(entries, dict):
        return {}
    return {
        request_id: entry
        for request_id, entry in entries.items()
        if isinstance(request_id, str) and isinstance(entry, dict)
    }


def _quarantine_candidate(
    store: GuardStore,
    entries: dict[str, dict[str, object]],
    candidate: dict[str, object],
    reason: str,
    now: str,
) -> bool:
    """Durably retain one terminally failed candidate; bounded and idempotent."""
    request_id = cast(str, candidate["request_id"])
    if request_id in entries:
        return True
    if len(entries) >= _QUARANTINE_LIMIT:
        return False
    entries[request_id] = {
        "state": "quarantined",
        "reason": reason,
        "observation": candidate,
        "quarantinedAt": now,
    }
    try:
        store.set_sync_payload(
            _QUARANTINE_KEY,
            {"schema": _QUARANTINE_SCHEMA, "entries": entries, "updatedAt": now},
            now,
        )
    except (OSError, RuntimeError, sqlite3.Error, ValueError):
        del entries[request_id]
        return False
    return True


def native_observation_recovery_status(store: GuardStore) -> dict[str, object]:
    """Project bounded health metadata, never native receipts or request IDs."""
    saved = store.get_sync_payload(_STATE_KEY)
    saved = saved if isinstance(saved, dict) else {}
    quarantined = len(_quarantine_entries(store))
    state = saved.get("state")
    if not isinstance(state, str) or state not in {"confirmed", "recovery_required", "unavailable"}:
        state = "not_observed"
    if quarantined:
        state = "recovery_required"
    failures = saved.get("failureCount", 0)
    retrying = min(max(failures, 0), _PAGE_LIMIT) if type(failures) is int else 0
    return {"state": state, "retrying_count": retrying, "quarantined_count": quarantined}


def record_native_observation_recovery_failure(
    store: GuardStore, reason: str = "native_application_observation_recovery_unavailable"
) -> dict[str, object]:
    saved = store.get_sync_payload(_STATE_KEY)
    now = datetime.now(timezone.utc).isoformat()
    state = {
        "state": "unavailable",
        "reason": reason,
        "afterRequestId": saved.get("afterRequestId") if isinstance(saved, dict) else None,
        "confirmed": 0,
        "failureCount": 1,
        "observedAt": now,
    }
    store.set_sync_payload(_STATE_KEY, state, now)
    return state


def recover_native_applications_once(store: GuardStore) -> dict[str, object]:
    saved = store.get_sync_payload(_STATE_KEY)
    cursor = saved.get("afterRequestId") if isinstance(saved, dict) else None
    if not isinstance(cursor, str):
        cursor = None
    try:
        observations, next_cursor = discover_native_applications(
            store.guard_home,
            after_request_id=cursor,
            limit=_PAGE_LIMIT,
        )
    except (OSError, RuntimeError, ValueError) as error:
        return record_native_observation_recovery_failure(store, _recovery_reason(error))
    now = datetime.now(timezone.utc).isoformat()
    quarantine = _quarantine_entries(store)
    confirmed = 0
    quarantined = 0
    quarantine_reasons: set[str] = set()
    failures: list[str] = []
    for candidate in observations:
        if cast(str, candidate["request_id"]) in quarantine:
            quarantined += 1
            continue
        try:
            queried = request_native_cloud_review(
                store.guard_home,
                "approval_consumption_query_v4",
                {
                    "schema": "guard-native-cloud-review-consumption-query.v4",
                    "version": 4,
                    "request_id": candidate["request_id"],
                    "decision_receipt_id": candidate["decision_receipt_id"],
                    "source_claim_hash": candidate["source_claim_hash"],
                },
            )
            observed = decode_native_application_observation(queried)
            if observed is None or observed["phase"] != "consumed" or observed != candidate:
                raise NativeCloudReviewV4Error("native_cloud_review_v4_recovery_observation_mismatch")
            record_native_application_observation(store, observed)
            confirmed += 1
        except (NativeCloudReviewV4Error, OSError, RuntimeError, ValueError, KeyError) as error:
            # A per-candidate transport/decode failure must not abort the pass or
            # lose quarantine/cursor progress already made for this page — but
            # unexpected exceptions (programmer errors, cancellation signals)
            # are allowed to propagate so corruption cannot be silently retried.
            reason = _recovery_reason(error)
            if reason in _TERMINAL_REASONS and _quarantine_candidate(store, quarantine, candidate, reason, now):
                quarantined += 1
                quarantine_reasons.add(reason)
            else:
                failures.append(reason)
    state: dict[str, object] = {
        "state": "recovery_required" if failures or quarantine else "confirmed",
        "afterRequestId": cursor if failures else next_cursor,
        "confirmed": confirmed,
        "failureCount": len(failures),
        "quarantined": quarantined,
        "quarantinedTotal": len(quarantine),
        "quarantineReasons": sorted(quarantine_reasons),
        "reasons": sorted(set(failures)),
        "observedAt": now,
    }
    store.set_sync_payload(_STATE_KEY, state, now)
    return state
