"""Report a policy bundle that failed local validation back to Guard Cloud.

Rust builds the failed acknowledgement (``failed_ack`` in
``guard-policy-bundle``). This module only picks which stored bundle and
rejection code to report and persists the result, so Cloud stops showing a
device as applied while Guard enforces nothing from that bundle. Nothing here
changes what Guard enforces.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
from ..policy_bundle_delivery import policy_bundle_failure_acknowledgement
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT, validated_policy_bundle_v2_acknowledgement
from ..store import GuardStore
from ..synced_policy import synced_policy_bundle_validation

_ACK_STATE_KEY = "policy_bundle_ack"
_FAILED = "failed"


def failed_acknowledgement(
    store: GuardStore,
    *,
    policy_bundle: object,
    reason: str | None,
    device_id: str,
    device_name: str,
    synced_at: str,
) -> dict[str, object]:
    """Return the failed acknowledgement for ``policy_bundle``, or ``{}``.

    A native outage is not a verdict about the bundle, so it reports nothing.
    """

    if not reason or reason == NATIVE_UNAVAILABLE_REJECTION:
        return {}
    return policy_bundle_failure_acknowledgement(
        device_id=device_id,
        device_name=device_name,
        policy_bundle=policy_bundle,
        error_code=reason,
        previous=store.get_sync_payload(_ACK_STATE_KEY),
        synced_at=synced_at,
    )


def _stored_failure(acknowledgement: dict[str, object], device_id: str) -> dict[str, object] | None:
    if acknowledgement.get("status") != _FAILED or acknowledgement.get("deviceId") != device_id:
        return None
    if acknowledgement.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        validated, _error = validated_policy_bundle_v2_acknowledgement(acknowledgement)
        return validated
    for key in ("bundleHash", "bundleVersion", "appliedAt"):
        value = acknowledgement.get(key)
        if not isinstance(value, str) or not value.strip():
            return None
    return acknowledgement


def cached_bundle_failure_acknowledgement(
    store: GuardStore,
    *,
    acknowledgement: dict[str, object],
    device_id: str,
    device_name: str,
) -> dict[str, object] | None:
    """Return the failed acknowledgement this device should report, if any.

    ``None`` means the cached bundle still validates (or Guard cannot tell), and
    the caller keeps its normal acknowledgement. An empty map means the cached
    bundle failed but Cloud has no shape that can carry the failure, so no
    acknowledgement should be sent. A built failure is persisted so the next
    request resends the same acknowledgement instead of a conflicting one.
    """

    stored = _stored_failure(acknowledgement, device_id)
    if stored is not None:
        return stored
    payload = store.get_sync_payload("policy_bundle")
    if not isinstance(payload, dict) or not payload:
        return None
    bundle, reason = synced_policy_bundle_validation(store)
    if bundle is not None:
        return None
    synced_at = datetime.now(timezone.utc).isoformat()
    failed = failed_acknowledgement(
        store,
        policy_bundle=payload,
        reason=reason,
        device_id=device_id,
        device_name=device_name,
        synced_at=synced_at,
    )
    if not failed:
        return None if reason in (None, NATIVE_UNAVAILABLE_REJECTION) else {}
    store.set_sync_payload(_ACK_STATE_KEY, failed, synced_at)
    return failed
