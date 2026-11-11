"""Report a policy bundle that failed local validation back to Guard Cloud.

Rust builds the failed acknowledgement (``failed_ack`` in
``guard-policy-bundle``). This module only picks which stored bundle and
rejection code to report and persists the result, so Cloud stops showing a
device as applied while Guard enforces nothing from that bundle. Nothing here
changes what Guard enforces.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from ..native_policy_bundle import NATIVE_UNAVAILABLE_REJECTION
from ..policy_bundle_delivery import is_failed_policy_bundle_acknowledgement, policy_bundle_failure_acknowledgement
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT, validated_policy_bundle_v2_acknowledgement
from ..store import GuardStore

_ACK_STATE_KEY = "policy_bundle_ack"
_FAILED = "failed"


def failed_acknowledgement(
    previous: object,
    *,
    policy_bundle: object,
    reason: str | None,
    device_id: str,
    device_name: str,
    synced_at: str,
) -> dict[str, object] | None:
    """Return the failed acknowledgement to store when Guard rejects or drops a bundle.

    ``previous`` is the stored acknowledgement. The native builder retracts it
    when it told Cloud a bundle was delivered, and otherwise reports
    ``policy_bundle``. ``None`` means there is nothing to report: a native
    outage is not a verdict about the bundle.
    """

    if not reason or reason == NATIVE_UNAVAILABLE_REJECTION:
        return None
    return (
        policy_bundle_failure_acknowledgement(
            device_id=device_id,
            device_name=device_name,
            policy_bundle=policy_bundle,
            error_code=reason,
            previous=previous,
            synced_at=synced_at,
        )
        or None
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
    validate: Callable[[GuardStore, object], tuple[dict[str, object] | None, str | None]],
) -> dict[str, object] | None:
    """Return the failed acknowledgement this device should report, if any.

    ``validate`` is the caller's cached-bundle validator, so this check and the
    rest of the sync agree on whether the cached bundle is trusted.

    ``None`` means the cached bundle still validates (or Guard cannot tell), and
    the caller keeps its normal acknowledgement. An empty map means the cached
    bundle failed but Cloud has no shape that can carry the failure, so no
    acknowledgement should be sent. A built failure is persisted so the next
    request resends the same acknowledgement instead of a conflicting one.
    """

    payload = store.get_sync_payload("policy_bundle")
    has_payload = isinstance(payload, dict) and bool(payload)
    bundle, reason = validate(store, payload) if has_payload else (None, None)
    if bundle is not None:
        # The cached bundle validates again: a legacy failure describes a
        # bundle Guard has since recovered, so it is not resent.
        return {} if is_failed_policy_bundle_acknowledgement(acknowledgement) else None
    stored = _stored_failure(acknowledgement, device_id)
    if stored is not None:
        return stored
    if not has_payload:
        return None
    synced_at = datetime.now(timezone.utc).isoformat()
    failed = failed_acknowledgement(
        acknowledgement,
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
