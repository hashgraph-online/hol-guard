"""Shared Guard supply-chain decision evidence contract v1."""

from __future__ import annotations

from collections.abc import Mapping

from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import PackageRequestEvaluation

DECISION_EVIDENCE_CONTRACT_VERSION = "guard-supply-chain-decision-evidence.v1"

DECISION_VALUES = frozenset({"allow", "monitor", "warn", "ask", "block"})
ENFORCEMENT_VALUES = frozenset({"premium_cloud", "local_fallback", "upgrade_required", "free_local", "offline_cached"})
ENTITLEMENT_VALUES = frozenset({"premium", "free", "limit_reached"})
CACHE_STATUS_VALUES = frozenset({"miss", "stale", "upgrade-gated", "hit", "empty"})

REQUIRED_DECISION_EVIDENCE_FIELDS = (
    "contractVersion",
    "decision",
    "recommendation",
    "enforcement",
    "entitlementState",
    "cacheStatus",
    "policyVersion",
    "packageIntentHash",
    "commandShape",
    "reasons",
    "evidenceIds",
)


def validate_decision_evidence_v1(payload: Mapping[str, object]) -> list[str]:
    errors: list[str] = []
    missing = {field for field in REQUIRED_DECISION_EVIDENCE_FIELDS if field not in payload}
    for field in missing:
        errors.append(f"missing field: {field}")
    contract_version = payload.get("contractVersion")
    if "contractVersion" not in missing and contract_version != DECISION_EVIDENCE_CONTRACT_VERSION:
        errors.append(f"unexpected contractVersion: {contract_version!r}")
    decision = payload.get("decision")
    if "decision" not in missing and decision not in DECISION_VALUES:
        errors.append(f"invalid decision: {decision!r}")
    recommendation = payload.get("recommendation")
    if recommendation not in DECISION_VALUES:
        errors.append(f"invalid recommendation: {recommendation!r}")
    enforcement = payload.get("enforcement")
    if "enforcement" not in missing and enforcement not in ENFORCEMENT_VALUES:
        errors.append(f"invalid enforcement: {enforcement!r}")
    entitlement_state = payload.get("entitlementState")
    if "entitlementState" not in missing and entitlement_state not in ENTITLEMENT_VALUES:
        errors.append(f"invalid entitlementState: {entitlement_state!r}")
    cache_status = payload.get("cacheStatus")
    if "cacheStatus" not in missing and cache_status not in CACHE_STATUS_VALUES:
        errors.append(f"invalid cacheStatus: {cache_status!r}")
    command_shape = payload.get("commandShape")
    if not isinstance(command_shape, dict):
        errors.append("commandShape must be an object")
    elif not isinstance(command_shape.get("redacted"), bool):
        errors.append("commandShape.redacted must be boolean")
    reasons = payload.get("reasons")
    if not isinstance(reasons, list):
        errors.append("reasons must be an array")
    evidence_ids = payload.get("evidenceIds")
    if not isinstance(evidence_ids, list):
        errors.append("evidenceIds must be an array")
    return errors


def package_evaluation_to_decision_evidence_v1(
    evaluation: PackageRequestEvaluation,
    *,
    command_shape: Mapping[str, object],
    package_intent_hash: str,
    recommendation: str | None = None,
) -> dict[str, object]:
    resolved_recommendation = recommendation or evaluation.decision
    return {
        "contractVersion": DECISION_EVIDENCE_CONTRACT_VERSION,
        "decision": evaluation.decision,
        "recommendation": resolved_recommendation,
        "enforcement": evaluation.enforcement,
        "entitlementState": evaluation.entitlement_state,
        "cacheStatus": evaluation.cache_status,
        "policyVersion": evaluation.policy_version,
        "packageIntentHash": package_intent_hash,
        "commandShape": dict(command_shape),
        "reasons": [dict(item) for item in evaluation.reasons],
        "evidenceIds": list(evaluation.evidence_ids),
    }


def cloud_evaluate_response_to_decision_evidence_v1(
    response: Mapping[str, object],
    *,
    package_intent_hash: str,
    command_shape: Mapping[str, object],
) -> dict[str, object]:
    reasons = response.get("reasons")
    evidence_ids = response.get("evidenceIds")
    return {
        "contractVersion": DECISION_EVIDENCE_CONTRACT_VERSION,
        "decision": response.get("decision"),
        "recommendation": response.get("recommendation", response.get("decision")),
        "enforcement": response.get("enforcement"),
        "entitlementState": response.get("entitlementState"),
        "cacheStatus": response.get("cacheStatus"),
        "policyVersion": response.get("policyVersion"),
        "packageIntentHash": package_intent_hash,
        "commandShape": dict(command_shape),
        "reasons": list(reasons) if isinstance(reasons, list) else [],
        "evidenceIds": list(evidence_ids) if isinstance(evidence_ids, list) else [],
    }
