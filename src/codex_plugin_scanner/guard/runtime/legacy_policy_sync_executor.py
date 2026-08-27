"""Narrow compatibility adapter for persisted pre-v3 policy-memory jobs."""

from __future__ import annotations

from ..store import GuardStore
from .command_payload import mapping, optional_text, result
from .review_policy_memory_executor import execute_review_policy_memory


def execute_legacy_policy_sync(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    """Translate the durable legacy envelope into the canonical executor."""

    bundle = mapping(payload.get("decisionMemoryBundle") or payload.get("decision_memory_bundle"))
    canonical = execute_review_policy_memory(
        {"decisionMemoryBundle": bundle},
        store=store,
        generated_at=generated_at,
    )
    return result(
        {
            "action": "policy_sync",
            **canonical,
            "localRequestId": optional_text(payload.get("localRequestId")),
        },
        generated_at=generated_at,
    )


__all__ = ["execute_legacy_policy_sync"]
