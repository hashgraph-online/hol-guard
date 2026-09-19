"""Apply separately authorized signed Cloud Review policy-memory bundles."""

from __future__ import annotations

from ..store import GuardStore

REVIEW_POLICY_MEMORY_OPERATION = "guard.review.syncPolicyMemory"


def execute_review_policy_memory(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    """Apply signed memory without resolving or authorizing any one-time request."""
    if "localRequestId" in payload or "local_request_id" in payload:
        raise ValueError("review_policy_memory_local_request_forbidden")
    bundle = payload.get("decisionMemoryBundle")
    if not isinstance(bundle, dict) or not bundle:
        raise ValueError("missing_decision_memory_bundle")
    ack = store.apply_review_policy_memory_state(bundle, now=generated_at)
    return {
        "bundleHash": ack.get("bundleHash"),
        "bundleVersion": ack.get("bundleVersion"),
        "decisionMemoryAck": ack,
        "status": str(ack["status"]),
    }


__all__ = ["REVIEW_POLICY_MEMORY_OPERATION", "execute_review_policy_memory"]
