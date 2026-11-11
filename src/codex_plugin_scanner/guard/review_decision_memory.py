"""Signed decision-memory bundles sent by Guard Cloud with a policy update."""

from __future__ import annotations

from datetime import datetime

from .review_contracts import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    _canonical_signed_payload,
    _non_empty_string,
    _now,
    _parse_iso_timestamp,
    _sha256_hex,
    _verify_signed_payload,
)

_DECISION_MEMORY_BUNDLE_CONTRACT_VERSION = "guard.decision-memory-bundle.v1"


def payload_hash_for_decision_memory_bundle(bundle: dict[str, object]) -> str:
    return _sha256_hex(_canonical_signed_payload(bundle))


def validated_decision_memory_bundle(bundle: dict[str, object], *, store) -> dict[str, object]:
    if bundle.get("contractVersion") != _DECISION_MEMORY_BUNDLE_CONTRACT_VERSION:
        raise GuardReviewContractError("unsupported_memory_bundle_contract")
    issued_at = _parse_iso_timestamp(bundle.get("issuedAt"), field_name="issued_at")
    expires_at = _parse_iso_timestamp(bundle.get("expiresAt"), field_name="expires_at")
    if expires_at <= issued_at or expires_at <= _now():
        raise GuardReviewContractError("decision_memory_bundle_expired")
    bundle_hash = _non_empty_string(bundle.get("bundleHash"))
    payload_hash = payload_hash_for_decision_memory_bundle(bundle)
    if bundle_hash is None or bundle_hash != payload_hash:
        raise GuardReviewContractError("decision_memory_bundle_hash_mismatch")
    if _non_empty_string(bundle.get("payloadHash")) != payload_hash:
        raise GuardReviewContractError("decision_memory_payload_hash_mismatch")
    _verify_signed_payload(
        bundle,
        signature_algorithm=_non_empty_string(bundle.get("signatureAlgorithm")) or "",
        store=store,
    )
    return bundle


def _policy_version_ordering_key(value: str) -> tuple[datetime, str] | None:
    prefix, separator, suffix = value.partition(":")
    if not separator:
        return None
    try:
        return (_parse_iso_timestamp(prefix, field_name="policy_version"), suffix)
    except GuardReviewContractError:
        return None


def _policy_version_is_stale(current: str, previous: str) -> bool:
    current_key = _policy_version_ordering_key(current)
    previous_key = _policy_version_ordering_key(previous)
    if current_key is not None and previous_key is not None:
        return current_key <= previous_key
    return current <= previous


def validate_decision_memory_bundle_target(
    *,
    bundle: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    last_policy_version: str | None = None,
) -> None:
    if _non_empty_string(bundle.get("workspaceId")) != oauth.workspace_id:
        raise GuardReviewContractError("decision_memory_workspace_mismatch")
    if last_policy_version is not None:
        current = _non_empty_string(bundle.get("policyVersion"))
        if current is not None and _policy_version_is_stale(current, last_policy_version):
            raise GuardReviewContractError("decision_memory_policy_version_stale")
    rules = bundle.get("memoryRules")
    revocations = bundle.get("revocations")
    if not isinstance(rules, list):
        raise GuardReviewContractError("decision_memory_rules_missing")
    if not rules and not (isinstance(revocations, list) and revocations):
        raise GuardReviewContractError("decision_memory_rules_missing")
    for rule in rules:
        if not isinstance(rule, dict):
            raise GuardReviewContractError("decision_memory_rule_invalid")
        target = rule.get("target")
        if not isinstance(target, dict):
            raise GuardReviewContractError("decision_memory_target_invalid")
        machine_ids = target.get("machineIds")
        if (
            isinstance(machine_ids, list)
            and machine_ids
            and oauth.installation_id not in {str(item) for item in machine_ids}
        ):
            raise GuardReviewContractError("decision_memory_machine_mismatch")
