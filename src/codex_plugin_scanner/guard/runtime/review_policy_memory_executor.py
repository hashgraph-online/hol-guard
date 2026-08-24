"""Apply separately authorized signed Cloud Review policy-memory bundles."""

from __future__ import annotations

from typing import TypeGuard

from ..action_lattice import is_guard_action
from ..models import DECISION_SCOPE_VALUES, DecisionScope, PolicyDecision
from ..review_contracts import (
    GuardReviewContractError,
    guard_review_oauth_metadata,
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
    rejected_rule_ids: list[str] = []
    validated_rules: list[tuple[str, PolicyDecision]] = []
    rules = bundle.get("memoryRules")
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            raise ValueError("invalid_decision_memory_rule")
        rule_id = _text(rule.get("ruleId"))
        if rule_id is None:
            raise ValueError("invalid_decision_memory_rule")
        try:
            decision = _decision_from_rule(bundle=bundle, rule=rule)
        except GuardReviewContractError:
            rejected_rule_ids.append(rule_id)
            continue
        validated_rules.append((rule_id, decision))
    status = "accepted" if not rejected_rule_ids else "rejected"
    if status == "rejected":
        ack = build_decision_memory_ack(
            bundle=bundle,
            oauth=oauth,
            status=status,
            applied_rule_count=0,
            reason="decision_memory_rule_rejected",
            rejected_rule_ids=rejected_rule_ids,
        )
        store.set_sync_payload(_MEMORY_ACK_KEY, ack, generated_at)
        return {
            "bundleHash": _text(bundle.get("bundleHash")),
            "bundleVersion": _text(bundle.get("bundleVersion")),
            "decisionMemoryAck": ack,
            "status": str(ack["status"]),
        }

    registry = _stored_registry(store)
    revocations = bundle.get("revocations")
    for revoked_rule_id in revocations if isinstance(revocations, list) else []:
        revoked_key = _text(revoked_rule_id)
        if revoked_key is not None:
            registry.pop(revoked_key, None)
    for rule_id, decision in validated_rules:
        registry[rule_id] = {"decision": decision.to_dict(), "ruleId": rule_id}
    store.replace_remote_policies(
        [
            *_existing_non_memory_policies(store),
            *[_decision_from_registry_entry(entry) for entry in registry.values()],
        ],
        generated_at,
        remote_write_authorized=True,
    )
    store.set_sync_payload(_MEMORY_REGISTRY_KEY, list(registry.values()), generated_at)
    store.set_sync_payload(
        _MEMORY_VERSION_KEY,
        {"policyVersion": _text(bundle.get("policyVersion"))},
        generated_at,
    )
    ack = build_decision_memory_ack(
        bundle=bundle,
        oauth=oauth,
        status=status,
        applied_rule_count=len(validated_rules),
        reason=None,
        rejected_rule_ids=rejected_rule_ids,
    )
    store.set_sync_payload(_MEMORY_ACK_KEY, ack, generated_at)
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


def _stored_registry(store: GuardStore) -> dict[str, dict[str, object]]:
    payload = store.get_sync_payload(_MEMORY_REGISTRY_KEY)
    if not isinstance(payload, list):
        return {}
    registry: dict[str, dict[str, object]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        rule_id = _text(item.get("ruleId"))
        decision = item.get("decision")
        if rule_id is not None and isinstance(decision, dict):
            registry[rule_id] = {"decision": dict(decision), "ruleId": rule_id}
    return registry


def _existing_non_memory_policies(store: GuardStore) -> list[PolicyDecision]:
    decisions: list[PolicyDecision] = []
    for item in store.list_policy_decisions():
        if item.get("source") != "policy-bundle":
            continue
        scope = _text(item.get("scope"))
        action = _text(item.get("action"))
        harness = _text(item.get("harness"))
        if scope is None or action is None or harness is None or not _is_scope(scope) or not is_guard_action(action):
            continue
        decisions.append(
            PolicyDecision(
                harness=harness,
                scope=scope,
                action=action,
                artifact_id=_text(item.get("artifact_id")),
                artifact_hash=_text(item.get("artifact_hash")),
                workspace=_text(item.get("workspace")),
                publisher=_text(item.get("publisher")),
                reason=_text(item.get("reason")),
                owner=_text(item.get("owner")),
                source="policy-bundle",
                expires_at=_text(item.get("expires_at")),
            )
        )
    return decisions


def _decision_from_registry_entry(entry: dict[str, object]) -> PolicyDecision:
    decision = entry.get("decision")
    if not isinstance(decision, dict):
        raise ValueError("invalid_decision_memory_registry")
    harness = _text(decision.get("harness"))
    scope = _text(decision.get("scope"))
    action = _text(decision.get("action"))
    if harness is None or scope is None or action is None or not _is_scope(scope) or not is_guard_action(action):
        raise ValueError("invalid_decision_memory_registry")
    return PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=_text(decision.get("artifact_id")),
        artifact_hash=_text(decision.get("artifact_hash")),
        workspace=_text(decision.get("workspace")),
        publisher=_text(decision.get("publisher")),
        reason=_text(decision.get("reason")),
        owner=_text(decision.get("owner")),
        source=str(decision.get("source") or "cloud-signed-memory"),
        expires_at=_text(decision.get("expires_at")),
    )


def _decision_from_rule(*, bundle: dict[str, object], rule: dict[str, object]) -> PolicyDecision:
    harness = _text(rule.get("harnessId"))
    artifact_id = _text(rule.get("artifactId"))
    action = _text(rule.get("action"))
    scope_value = _text(rule.get("scope"))
    if harness is None or artifact_id is None or action is None or scope_value is None or not is_guard_action(action):
        raise GuardReviewContractError("invalid_decision_memory_rule")
    if action == "allow" and scope_value not in {"artifact", "workspace"}:
        raise GuardReviewContractError("decision_memory_allow_scope_unsupported")
    scope = _local_scope(scope_value)
    target = rule.get("target")
    target_payload = target if isinstance(target, dict) else {}
    workspace_ids = target_payload.get("workspaceIds")
    workspace = _text(bundle.get("workspaceId"))
    if scope == "workspace" and isinstance(workspace_ids, list):
        workspace = next((item for value in workspace_ids if (item := _text(value)) is not None), workspace)
    return PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=artifact_id,
        artifact_hash=_text(rule.get("artifactHash")),
        workspace=workspace if scope == "workspace" else None,
        publisher=None,
        reason=_text(rule.get("reason")) or "Guard Cloud signed decision memory sync",
        owner=None,
        source="cloud-signed-memory",
        expires_at=_text(rule.get("expiresAt")),
    )


def _local_scope(scope: str) -> DecisionScope:
    return "workspace" if scope in {"workspace", "team", "policy", "machine", "project"} else "artifact"


def _is_scope(value: object) -> TypeGuard[DecisionScope]:
    return isinstance(value, str) and value in DECISION_SCOPE_VALUES


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ["REVIEW_POLICY_MEMORY_OPERATION", "execute_review_policy_memory"]
