"""Contract-aware rollout-state admission for v1 and v2 policy bundles."""

from __future__ import annotations

from collections.abc import Mapping

from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT

POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES = frozenset({"enforcing", "enforced", "rollback_available"})
_INACTIVE_ROLLOUT_STATES = frozenset({"draft", "simulated", "pending_approval"})
# Sentinel: v2 ``payload.spec.rolloutState`` was omitted (compatibility path).
_POLICY_BUNDLE_ROLLOUT_STATE_ABSENT = object()


def policy_bundle_rollout_state(policy_bundle: Mapping[str, object]) -> object:
    """Return the publication-contract rollout state for v1 envelopes or v2 documents.

    For v2 documents, omitted ``payload.spec.rolloutState`` returns
    ``_POLICY_BUNDLE_ROLLOUT_STATE_ABSENT``. An explicit JSON null, a non-string
    value, or a missing/malformed ``payload.spec`` is returned as ``None`` or the
    provided value so callers can reject the compatibility path.
    """

    if policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        payload = policy_bundle.get("payload")
        spec = payload.get("spec") if isinstance(payload, Mapping) else None
        if not isinstance(spec, Mapping):
            return None
        if "rolloutState" not in spec:
            return _POLICY_BUNDLE_ROLLOUT_STATE_ABSENT
        return spec["rolloutState"]
    return policy_bundle.get("rolloutState")


def policy_bundle_is_enforceable(policy_bundle: Mapping[str, object]) -> bool:
    """Return whether an authenticated rollout is intended as live authority."""

    rollout_state = policy_bundle_rollout_state(policy_bundle)
    if (
        policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
        and rollout_state is _POLICY_BUNDLE_ROLLOUT_STATE_ABSENT
    ):
        return True
    if isinstance(rollout_state, str) and rollout_state in _INACTIVE_ROLLOUT_STATES:
        return False
    return isinstance(rollout_state, str) and rollout_state in POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES


__all__ = [
    "POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES",
    "_POLICY_BUNDLE_ROLLOUT_STATE_ABSENT",
    "policy_bundle_is_enforceable",
    "policy_bundle_rollout_state",
]
