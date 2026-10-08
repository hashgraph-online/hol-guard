"""Apply separately authorized signed Cloud Review policy-memory bundles."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from ..action_lattice import is_guard_action
from ..models import DecisionScope, PolicyDecision
from ..review_contracts import (
    GuardReviewContractError,
    guard_review_oauth_metadata,
    payload_hash_for_decision_memory_bundle,
    validate_decision_memory_bundle_target,
    validated_decision_memory_bundle,
)
from ..review_memory_ack import build_decision_memory_ack
from ..review_signature_verification import _verify_signed_payload
from ..store import GuardStore

REVIEW_POLICY_MEMORY_OPERATION = "guard.review.syncPolicyMemory"
_MEMORY_REGISTRY_KEY = "guard_review_memory_registry"
_MEMORY_VERSION_KEY = "guard_review_memory_policy_version"
_MEMORY_ACK_KEY = "guard_review_memory_last_ack"
_EXACT_COMMAND_PREFIX = "memory:exact-command:"
_CLOUD_WORKSPACE_PREFIX = "cloud-workspace:"


def execute_review_policy_memory(
    payload: dict[str, object],
    *,
    store: GuardStore,
    generated_at: str,
    machine_installation_id: object,
) -> dict[str, object]:
    """Apply a signed policy-memory bundle after separate local confirmation."""

    if "localRequestId" in payload or "local_request_id" in payload:
        raise ValueError("review_policy_memory_local_request_forbidden")
    bundle_payload = _mapping(payload.get("decisionMemoryBundle"))
    if not bundle_payload:
        raise ValueError("missing_decision_memory_bundle")
    oauth = guard_review_oauth_metadata(store)
    bundle = validated_decision_memory_bundle(bundle_payload, store=store)
    expected = _mapping(payload.get("expectedApplication"))
    if not isinstance(machine_installation_id, str):
        raise GuardReviewContractError("decision_memory_transport_owner_missing")
    try:
        if str(UUID(machine_installation_id)) != machine_installation_id:
            raise ValueError
    except ValueError as error:
        raise GuardReviewContractError("decision_memory_transport_owner_invalid") from error
    identity = {
        "bundleHash": bundle.get("bundleHash"),
        "bundleVersion": bundle.get("bundleVersion"),
        "deviceId": oauth.device_id,
        "machineId": oauth.machine_id,
        "machineInstallationId": machine_installation_id,
        "policyVersion": bundle.get("policyVersion"),
        "workspaceId": oauth.workspace_id,
    }
    if expected != identity:
        raise GuardReviewContractError("decision_memory_application_identity_mismatch")
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
            machine_installation_id=machine_installation_id,
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
    for entry in registry.values():
        _decision_from_registry_entry(entry, store=store)
    revocations = bundle.get("revocations")
    for revoked_rule_id in revocations if isinstance(revocations, list) else []:
        revoked_key = _text(revoked_rule_id)
        if revoked_key is not None:
            registry.pop(revoked_key, None)
    for rule_id, decision in validated_rules:
        registry[rule_id] = {
            "decision": decision.to_dict(),
            "ruleId": rule_id,
            "sourceBundle": bundle,
        }
    ack = build_decision_memory_ack(
        bundle=bundle,
        oauth=oauth,
        machine_installation_id=machine_installation_id,
        status=status,
        applied_rule_count=len(validated_rules),
        reason=None,
        rejected_rule_ids=rejected_rule_ids,
    )
    store.apply_review_policy_memory_state(
        [_decision_from_registry_entry(entry, store=store) for entry in registry.values()],
        registry=list(registry.values()),
        version={"policyVersion": _text(bundle.get("policyVersion"))},
        acknowledgement=ack,
        now=generated_at,
    )
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
            raise GuardReviewContractError("invalid_decision_memory_registry")
        rule_id = _text(item.get("ruleId"))
        if rule_id is None or rule_id in registry:
            raise GuardReviewContractError("invalid_decision_memory_registry")
        registry[rule_id] = dict(item)
    return registry


def _decision_from_registry_entry(entry: dict[str, object], *, store: GuardStore) -> PolicyDecision:
    """Reconstruct authority from the retained signed rule, never its row copy.

    Delivery expiry limits admission, not a separately expiring retained rule.
    The retained signature uses the same anchored-key verification as admission;
    current key validity and the current OAuth target still have to match.
    """

    bundle = _mapping(entry.get("sourceBundle"))
    try:
        issued_at = datetime.fromisoformat(str(bundle.get("issuedAt", "")).replace("Z", "+00:00"))
    except ValueError as error:
        raise GuardReviewContractError("invalid_decision_memory_registry") from error
    if issued_at.tzinfo is None:
        raise GuardReviewContractError("invalid_decision_memory_registry")
    payload_hash = payload_hash_for_decision_memory_bundle(bundle)
    if payload_hash != bundle.get("payloadHash") or payload_hash != bundle.get("bundleHash"):
        raise GuardReviewContractError("decision_memory_bundle_hash_mismatch")
    _verify_signed_payload(
        bundle,
        store=store,
        signature_algorithm=_text(bundle.get("signatureAlgorithm")) or "",
    )
    validate_decision_memory_bundle_target(bundle=bundle, oauth=guard_review_oauth_metadata(store))
    rule_id = _text(entry.get("ruleId"))
    rules = bundle.get("memoryRules")
    matching = (
        [rule for rule in rules if isinstance(rule, dict) and rule.get("ruleId") == rule_id]
        if isinstance(rules, list)
        else []
    )
    if len(matching) != 1:
        raise GuardReviewContractError("invalid_decision_memory_registry")
    decision = _decision_from_rule(bundle=bundle, rule=matching[0])
    if entry.get("decision") != decision.to_dict():
        raise GuardReviewContractError("decision_memory_registry_projection_mismatch")
    return decision


def native_review_policy_memory_actions(store: GuardStore) -> list[dict[str, object]]:
    """Publish exact, Cloud-workspace-bound rules into the governed snapshot."""

    actions: list[dict[str, object]] = []
    for entry in _stored_registry(store).values():
        decision = _decision_from_registry_entry(entry, store=store)
        if decision.artifact_id is None or not decision.artifact_id.startswith(_EXACT_COMMAND_PREFIX):
            continue
        workspace = decision.workspace
        if workspace is None or not workspace.startswith(_CLOUD_WORKSPACE_PREFIX):
            raise GuardReviewContractError("decision_memory_cloud_workspace_required")
        actions.append(
            {
                "harness": decision.harness,
                "command_sha256": decision.artifact_id[len(_EXACT_COMMAND_PREFIX) :],
                "cloud_workspace_id": workspace[len(_CLOUD_WORKSPACE_PREFIX) :],
                "action": decision.action,
                "expires_at": decision.expires_at,
            }
        )
    return actions


def _decision_from_rule(*, bundle: dict[str, object], rule: dict[str, object]) -> PolicyDecision:
    harness = _text(rule.get("harnessId"))
    artifact_id = _text(rule.get("artifactId"))
    action = _text(rule.get("action"))
    scope_value = _text(rule.get("scope"))
    if harness is None or artifact_id is None or action is None or scope_value is None or not is_guard_action(action):
        raise GuardReviewContractError("invalid_decision_memory_rule")
    if action == "allow" and scope_value not in {"artifact", "workspace"}:
        raise GuardReviewContractError("decision_memory_allow_scope_unsupported")
    if scope_value not in {"artifact", "workspace"}:
        raise GuardReviewContractError("decision_memory_scope_unsupported")
    scope: DecisionScope = "workspace" if scope_value == "workspace" else "artifact"
    workspace = _text(bundle.get("workspaceId"))
    exact_command = rule.get("exactCommand")
    command_memory = rule.get("capabilityCategory") == "command" or exact_command is not None
    if command_memory:
        if (
            not isinstance(exact_command, dict)
            or set(exact_command) != {"contractVersion", "sha256"}
            or exact_command.get("contractVersion") != "guard.exact-command.v1"
            or not isinstance(digest := exact_command.get("sha256"), str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or workspace is None
            or _text(rule.get("expiresAt")) is None
        ):
            raise GuardReviewContractError("decision_memory_exact_command_required")
        artifact_id = _EXACT_COMMAND_PREFIX + digest
        # Cloud workspace identity is not a local filesystem workspace path.
        scope = "workspace"
        workspace = _CLOUD_WORKSPACE_PREFIX + workspace
    return PolicyDecision(
        harness=harness,
        scope=scope,
        action=action,
        artifact_id=artifact_id,
        artifact_hash=None if command_memory else _text(rule.get("artifactHash")),
        workspace=workspace if scope == "workspace" else None,
        publisher=None,
        reason=_text(rule.get("reason")) or "Guard Cloud signed decision memory sync",
        owner=None,
        source="cloud-signed-memory",
        expires_at=_text(rule.get("expiresAt")),
    )


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = [
    "REVIEW_POLICY_MEMORY_OPERATION",
    "execute_review_policy_memory",
    "native_review_policy_memory_actions",
]
