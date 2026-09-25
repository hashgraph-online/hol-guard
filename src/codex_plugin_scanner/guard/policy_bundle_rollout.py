"""Shared publication-state admission for authenticated v1 and v2 bundles."""

from __future__ import annotations

from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT

POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES = frozenset({"enforcing", "enforced", "rollback_available"})
_POLICY_BUNDLE_ROLLOUT_STATE_ABSENT = object()


def policy_bundle_rollout_state(policy_bundle: dict[str, object]) -> object:
    """Return the publication-contract rollout state for v1 envelopes or v2 documents.

    For v2 documents, omitted ``payload.spec.rolloutState`` returns
    ``_POLICY_BUNDLE_ROLLOUT_STATE_ABSENT``. An explicit JSON null, a non-string
    value, or a missing/malformed ``payload.spec`` is returned as ``None`` or the
    provided value so callers can reject the compatibility path.
    """

    if policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        payload = policy_bundle.get("payload")
        spec = payload.get("spec") if isinstance(payload, dict) else None
        if not isinstance(spec, dict):
            return None
        if "rolloutState" not in spec:
            return _POLICY_BUNDLE_ROLLOUT_STATE_ABSENT
        return spec["rolloutState"]
    return policy_bundle.get("rolloutState")


def policy_bundle_is_enforceable(policy_bundle: dict[str, object]) -> bool:
    """Use one publication-state gate for sync and cached current/LKG reads."""

    rollout_state = policy_bundle_rollout_state(policy_bundle)
    if (
        policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
        and rollout_state is _POLICY_BUNDLE_ROLLOUT_STATE_ABSENT
    ):
        return True
    return isinstance(rollout_state, str) and rollout_state in POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES
