"""Recover actual native consumption observations outside the hook path.

Discovery is only a candidate source. Exact read-only native confirmation and
an immutable SDK source join are mandatory before producing a Review event.
Missing SQLite material remains a visible recovery failure, never new authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

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


def recover_native_applications_once(store: GuardStore) -> dict[str, object]:
    saved = store.get_sync_payload(_STATE_KEY)
    cursor = saved.get("afterRequestId") if isinstance(saved, dict) else None
    if not isinstance(cursor, str):
        cursor = None
    try:
        observations, next_cursor = discover_native_applications(
            store.guard_home, after_request_id=cursor, limit=8,
        )
    except NativeCloudReviewV4Error as error:
        if error.code == "native_cloud_review_v4_capability_unavailable":
            return {"state": "unavailable", "reason": error.code, "confirmed": 0}
        raise
    confirmed = 0
    failures: list[str] = []
    for candidate in observations:
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
        except NativeCloudReviewV4Error as error:
            failures.append(error.code)
    state: dict[str, object] = {
        "state": "recovery_required" if failures else "confirmed",
        "afterRequestId": next_cursor,
        "confirmed": confirmed,
        "failureCount": len(failures),
        "reasons": sorted(set(failures)),
        "observedAt": datetime.now(timezone.utc).isoformat(),
    }
    store.set_sync_payload(_STATE_KEY, state, str(state["observedAt"]))
    return state
