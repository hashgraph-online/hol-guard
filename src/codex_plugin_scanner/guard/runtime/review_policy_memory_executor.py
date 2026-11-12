"""Apply separately authorized signed Cloud Review policy-memory bundles."""

from __future__ import annotations

from typing import Any, cast

from ..models import PolicyDecision
from ..review_contracts import guard_review_oauth_metadata
from ..review_decision_memory import (
    validate_decision_memory_bundle_target,
    validated_decision_memory_bundle,
)
from ..review_memory_ack import build_decision_memory_ack
from ..store import GuardStore

REVIEW_POLICY_MEMORY_OPERATION = "guard.review.syncPolicyMemory"
_MEMORY_REGISTRY_KEY = "guard_review_memory_registry"
_MEMORY_VERSION_KEY = "guard_review_memory_policy_version"
_MEMORY_ACK_KEY = "guard_review_memory_last_ack"


def execute_review_policy_memory(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
) -> dict[str, object]:
    """Apply a signed policy-memory bundle after separate local confirmation."""

    if "localRequestId" in payload or "local_request_id" in payload:
        raise ValueError("review_policy_memory_local_request_forbidden")
    bundle_payload = _mapping(payload.get("decisionMemoryBundle"))
    if not bundle_payload:
        raise ValueError("missing_decision_memory_bundle")
    oauth = guard_review_oauth_metadata(store)
    bundle = validated_decision_memory_bundle(bundle_payload, store=store)
    validate_decision_memory_bundle_target(
        bundle=bundle,
        oauth=oauth,
        last_policy_version=_stored_policy_version(store),
    )
    rejected_rule_ids, plan = _memory_plan(bundle, store)
    if rejected_rule_ids:
        ack = build_decision_memory_ack(
            bundle=bundle,
            oauth=oauth,
            status="rejected",
            applied_rule_count=0,
            reason="decision_memory_rule_rejected",
            rejected_rule_ids=rejected_rule_ids,
        )
        store.set_sync_payload(_MEMORY_ACK_KEY, ack, generated_at)
        return _result(bundle, ack)

    applied_rule_count = plan.get("applied_rule_count")
    ack = build_decision_memory_ack(
        bundle=bundle,
        oauth=oauth,
        status="accepted",
        applied_rule_count=applied_rule_count if isinstance(applied_rule_count, int) else 0,
        reason=None,
        rejected_rule_ids=[],
    )
    decisions = _dicts(plan.get("decisions"))
    store.apply_review_policy_memory_state(
        [PolicyDecision(**decision) for decision in decisions],
        registry=_registry(plan.get("registry_rule_ids"), decisions),
        version={"policyVersion": _text(bundle.get("policyVersion"))},
        acknowledgement=ack,
        now=generated_at,
    )
    return _result(bundle, ack)


def _memory_plan(bundle: dict[str, object], store: GuardStore) -> tuple[list[str], dict[str, object]]:
    """Ask the native runtime which memory rules apply and what the store holds after them."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {
        "rules": bundle.get("memoryRules"),
        "revocations": bundle.get("revocations"),
        "workspace_id": bundle.get("workspaceId"),
        "registry": store.get_sync_payload(_MEMORY_REGISTRY_KEY),
        "policies": [item for item in store.list_policy_decisions() if item.get("source") == "policy-bundle"],
    }
    try:
        plan = native_runner_authority("review_policy_memory_plan", request)
    except NativeRunnerAuthorityError as error:
        raise ValueError("review_policy_memory_unavailable") from error
    error = plan.get("error")
    if isinstance(error, str):
        raise ValueError(error)
    rejected = plan.get("rejected_rule_ids")
    if not isinstance(rejected, list):
        raise ValueError("review_policy_memory_unavailable")
    return [str(rule_id) for rule_id in cast("list[object]", rejected)], plan


def _dicts(value: object) -> list[dict[str, Any]]:
    """The plan's decisions; a reply without a list of objects fails closed before the store write."""

    if not isinstance(value, list) or not all(isinstance(item, dict) for item in cast("list[object]", value)):
        raise ValueError("review_policy_memory_unavailable")
    return [cast("dict[str, Any]", item) for item in cast("list[object]", value)]


def _registry(rule_ids: object, decisions: list[dict[str, Any]]) -> list[dict[str, object]]:
    """Pair each registry rule with its decision; the registry's decisions close the list."""

    if not isinstance(rule_ids, list):
        raise ValueError("review_policy_memory_unavailable")
    ids = cast("list[object]", rule_ids)
    if len(ids) > len(decisions):
        raise ValueError("review_policy_memory_unavailable")
    tail = decisions[len(decisions) - len(ids) :]
    return [{"decision": decision, "ruleId": str(rule_id)} for rule_id, decision in zip(ids, tail, strict=True)]


def _result(bundle: dict[str, object], ack: dict[str, object]) -> dict[str, object]:
    return {
        "bundleHash": _text(bundle.get("bundleHash")),
        "bundleVersion": _text(bundle.get("bundleVersion")),
        "decisionMemoryAck": ack,
        "status": str(ack["status"]),
    }


def _mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _stored_policy_version(store: GuardStore) -> str | None:
    payload = store.get_sync_payload(_MEMORY_VERSION_KEY)
    return _text(payload.get("policyVersion")) if isinstance(payload, dict) else None


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ["REVIEW_POLICY_MEMORY_OPERATION", "execute_review_policy_memory"]
