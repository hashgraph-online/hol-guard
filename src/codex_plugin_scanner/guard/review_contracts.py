"""Guard Review backend contracts shared by local daemon and command queue."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Literal

from .approval_scope_support import (
    APPROVAL_SCOPE_CONTRACT_VERSION,
    IneligibleApprovalScopeError,
    request_scope_contract,
    resolve_request_scope_selection,
)
from .continuation_snapshot import canonical_continuation_correlation_id
from .models import DECISION_SCOPE_VALUES
from .project_identity import resolve_portable_project_identity
from .review_claim_hashing import (
    compute_legacy_local_review_request_claim_hash,
    compute_local_review_request_claim_hash,
    local_review_request_claim_hash_matches,  # noqa: F401 - public compatibility re-export
)
from .review_exact_capability_advertisement import attach_exact_review_capability
from .review_native_claim_bindings import (
    NATIVE_BINDING_FIELDS,
    NATIVE_BINDING_VERSION,
    native_binding_commitment_matches,
)
from .review_native_claim_bindings import (
    canonical_native_launch_target as _canonical_native_launch_target,  # noqa: F401 - compatibility re-export
)
from .review_native_claim_bindings import (
    native_review_claim_bindings as _native_review_claim_bindings,
)
from .review_oauth_binding import (
    GuardReviewContractError,
    GuardReviewOAuthMetadata,
    guard_review_oauth_metadata,  # noqa: F401 - compatibility re-export
)
from .review_signature_verification import (
    _anchored_review_verification_keys,  # noqa: F401 - compatibility re-export
    _resolve_anchored_signing_key,  # noqa: F401 - compatibility re-export
    _verification_keys_from_payload,  # noqa: F401 - compatibility re-export
    _verify_signed_payload,
    validated_review_verification_keys_from_sync,  # noqa: F401 - public compatibility re-export
)
from .stable_digest import sha256_content_digest
from .stable_json import stable_json_serialize

_LOCAL_REVIEW_REQUEST_CONTRACT_VERSION = "guard.local-review-request.v1"
_REMOTE_APPROVAL_CONTRACT_VERSION = "guard.remote-approval.v1"
_DECISION_MEMORY_BUNDLE_CONTRACT_VERSION = "guard.decision-memory-bundle.v1"
_REMOTE_APPROVAL_ALLOWED_SCOPES = frozenset(DECISION_SCOPE_VALUES)
_REMOTE_APPROVAL_RESOLVER_ROLES = frozenset({"owner", "workspace-owner", "admin", "operator"})
_REMOTE_APPROVAL_ADMIN_ROLES = frozenset({"owner", "workspace-owner", "admin"})
_REMOTE_APPROVAL_WORKSPACE_ADMIN_MFA_AUTHORITY = "workspace_admin_mfa"
_REMOTE_APPROVAL_KEY_PURPOSE = "remote_approval"
_REMOTE_APPROVAL_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
_DECISION_MEMORY_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
_NATIVE_ACTION_BINDING_DOMAIN = "guard-native-workspace-review-action-binding-v1\0"
_NATIVE_INTENT_BINDING_DOMAIN = "guard-native-workspace-review-intent-binding-v1\0"
_NATIVE_POLICY_BINDING_DOMAIN = "guard-native-workspace-review-policy-binding-v1\0"
_SIGNED_PAYLOAD_STRIP_KEYS = ("payloadHash", "signature", "signatureAlgorithm", "verificationKeys", "bundleHash")

RemoteApprovalDecision = Literal["allow", "block"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


_stable_serialize = stable_json_serialize


def _sha256_hex(value: str) -> str:
    return sha256_content_digest(value.encode("utf-8"))


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _read_json_mapping(value: object) -> dict[str, object] | None:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    if value is None:
        return None
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    return {str(key): item for key, item in parsed.items()}


def _strip_keys(value: dict[str, object], keys: tuple[str, ...]) -> dict[str, object]:
    clone = deepcopy(value)
    for key in keys:
        clone.pop(key, None)
    return clone


def _parse_iso_timestamp(value: object, *, field_name: str) -> datetime:
    normalized = _non_empty_string(value)
    if normalized is None:
        raise GuardReviewContractError(f"invalid_{field_name}")
    candidate = normalized[:-1] + "+00:00" if normalized.endswith(("Z", "z")) else normalized
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise GuardReviewContractError(f"invalid_{field_name}") from error
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _canonical_signed_payload(value: dict[str, object]) -> str:
    return _stable_serialize(_strip_keys(value, _SIGNED_PAYLOAD_STRIP_KEYS))


def _action_envelope_hash(request_row: dict[str, object]) -> str:
    envelope = _read_json_mapping(request_row.get("action_envelope_json")) or {}
    return _sha256_hex(_stable_serialize(envelope))


def _project_identity(request_row: dict[str, object]) -> str | None:
    return resolve_portable_project_identity(_non_empty_string(request_row.get("workspace")))


def _capability_category(request_row: dict[str, object]) -> str:
    harness = (_non_empty_string(request_row.get("harness")) or "").lower()
    artifact_id = (_non_empty_string(request_row.get("artifact_id")) or "").lower()
    action_envelope = _read_json_mapping(request_row.get("action_envelope_json")) or {}
    action_type = (_non_empty_string(action_envelope.get("action_type")) or "").lower()
    risk_signals = request_row.get("risk_signals")
    normalized_signals = {str(item).lower() for item in risk_signals} if isinstance(risk_signals, list) else set()
    if artifact_id.startswith("pkg:") or "package" in artifact_id or "package" in harness:
        return "package-install"
    if any(token in artifact_id for token in ("mcp", "modelcontextprotocol")) or "mcp" in harness:
        return "mcp-server"
    if any(token in harness for token in ("bash", "shell")) or action_type == "shell_command":
        return "shell-command"
    if any(token in normalized_signals for token in ("secret", "credential", "token")):
        return "secret-read"
    if "skill" in artifact_id:
        return "skill-action"
    return "tool-call"


def _risk_category(request_row: dict[str, object]) -> str:
    for key in ("risk_headline", "risk_summary", "policy_action"):
        value = (_non_empty_string(request_row.get(key)) or "").lower()
        if any(token in value for token in ("critical", "high", "block", "destructive")):
            return "high"
        if any(token in value for token in ("medium", "review", "reapproval")):
            return "medium"
        if any(token in value for token in ("low", "allow")):
            return "low"
    return "unknown"


def _policy_version(request_row: dict[str, object]) -> str:
    decision_v2 = _read_json_mapping(request_row.get("decision_v2_json")) or {}
    value = _non_empty_string(decision_v2.get("policyVersion"))
    if value is not None:
        return value
    last_seen_at = _non_empty_string(request_row.get("last_seen_at")) or _non_empty_string(
        request_row.get("created_at")
    )
    return f"request:{last_seen_at or request_row['request_id']}"


def _claim_expiry(request_row: dict[str, object]) -> str:
    created_at = _parse_iso_timestamp(request_row.get("created_at"), field_name="created_at")
    last_seen_at = _parse_iso_timestamp(
        request_row.get("last_seen_at") or request_row.get("created_at"),
        field_name="last_seen_at",
    )
    baseline = max(created_at, last_seen_at)
    return (baseline + timedelta(minutes=10)).astimezone(timezone.utc).isoformat()


def build_local_review_request_claim(
    *,
    request_row: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    store,
) -> dict[str, object]:
    local_request_id = _non_empty_string(request_row.get("request_id"))
    approval_id = _non_empty_string(request_row.get("request_id"))
    artifact_id = _non_empty_string(request_row.get("artifact_id"))
    harness_id = _non_empty_string(request_row.get("harness"))
    policy_action = _non_empty_string(request_row.get("policy_action"))
    recommended_scope = _request_recommended_scope(request_row)
    created_at = _non_empty_string(request_row.get("created_at"))
    last_seen_at = _non_empty_string(request_row.get("last_seen_at")) or created_at
    required_fields = (local_request_id, approval_id, artifact_id, harness_id, policy_action)
    required_fields += (recommended_scope, created_at, last_seen_at)
    if None in required_fields:
        raise GuardReviewContractError("invalid_request_row")
    assert local_request_id is not None
    native_bindings = _native_review_claim_bindings(request_row)
    claim: dict[str, object] = {
        "contractVersion": _LOCAL_REVIEW_REQUEST_CONTRACT_VERSION,
        "correlationId": canonical_continuation_correlation_id(
            request_id=local_request_id,
            request_row=request_row,
            operation_metadata={},
        ),
        "actionEnvelopeHash": _action_envelope_hash(request_row),
        "actionIdentity": _non_empty_string(request_row.get("action_identity")) or local_request_id,
        "approvalId": approval_id,
        "artifactHash": _non_empty_string(request_row.get("artifact_hash")),
        "artifactId": artifact_id,
        "capabilityCategory": _capability_category(request_row),
        "createdAt": created_at,
        "deviceId": oauth.device_id,
        "expiresAt": _claim_expiry(request_row),
        "grantId": oauth.grant_id,
        "harnessId": harness_id,
        "lastSeenAt": last_seen_at,
        "localRequestId": local_request_id,
        "machineId": oauth.machine_id,
        "machineInstallationId": oauth.installation_id,
        **native_bindings,
        "nonce": _non_empty_string(request_row.get("queue_group_id")) or local_request_id,
        "policyAction": policy_action,
        "policyVersion": _policy_version(request_row),
        "projectIdentity": _project_identity(request_row),
        "queueGroupId": _non_empty_string(request_row.get("queue_group_id")),
        "recommendedScope": recommended_scope,
        "riskCategory": _risk_category(request_row),
        "runtimeId": oauth.runtime_id,
        "workspaceId": oauth.workspace_id,
    }
    claim["claimHash"] = compute_local_review_request_claim_hash(claim)
    return attach_exact_review_capability(claim, oauth, store)


def validate_local_review_request_claim(claim: dict[str, object]) -> dict[str, object]:
    if claim.get("contractVersion") != _LOCAL_REVIEW_REQUEST_CONTRACT_VERSION:
        raise GuardReviewContractError("unsupported_claim_contract_version")
    has_native_bindings = any(isinstance(claim.get(key), str) for key in NATIVE_BINDING_FIELDS) or any(
        key in claim for key in ("nativeBindingVersion", "nativeBindingDigest")
    )
    if has_native_bindings and not native_binding_commitment_matches(claim):
        raise GuardReviewContractError("native_binding_digest_mismatch")
    expected_hash = compute_local_review_request_claim_hash(claim)
    claim_hash = _non_empty_string(claim.get("claimHash"))
    if claim_hash != expected_hash and (
        has_native_bindings or claim_hash != compute_legacy_local_review_request_claim_hash(claim)
    ):
        raise GuardReviewContractError("claim_hash_mismatch")
    return claim


def payload_hash_for_remote_approval_envelope(envelope: dict[str, object]) -> str:
    return _sha256_hex(_canonical_signed_payload(envelope))


def remote_approval_uses_workspace_admin_mfa(envelope: dict[str, object]) -> bool:
    """Return True when Cloud signed a team-admin MFA decision for this request."""

    return envelope.get("authority") == _REMOTE_APPROVAL_WORKSPACE_ADMIN_MFA_AUTHORITY


def normalize_remote_approval_decision(value: object) -> RemoteApprovalDecision | None:
    """Normalize only the documented signed remote decision wire values."""
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    folded = normalized.replace("_", "-")
    if folded in {"allow", "allow-once"} or normalized == "allowOnce":
        return "allow"
    if folded in {"block", "deny", "denied", "blocked"}:
        return "block"
    return None


def validated_remote_approval_envelope(
    envelope: dict[str, object],
    *,
    store,
    admitted_at: object | None = None,
) -> dict[str, object]:
    if envelope.get("contractVersion") != _REMOTE_APPROVAL_CONTRACT_VERSION:
        raise GuardReviewContractError("unsupported_remote_approval_contract")
    scope = envelope.get("scope")
    if not isinstance(scope, str) or scope not in _REMOTE_APPROVAL_ALLOWED_SCOPES:
        raise GuardReviewContractError("invalid_remote_approval_scope")
    if normalize_remote_approval_decision(envelope.get("decision")) is None:
        raise GuardReviewContractError("invalid_remote_approval_decision")
    issued_at = _parse_iso_timestamp(envelope.get("issuedAt"), field_name="issued_at")
    expires_at = _parse_iso_timestamp(envelope.get("expiresAt"), field_name="expires_at")
    if expires_at <= issued_at:
        raise GuardReviewContractError("remote_approval_expired")
    if expires_at <= _now():
        if admitted_at is None:
            raise GuardReviewContractError("remote_approval_expired")
        queue_admitted_at = _parse_iso_timestamp(admitted_at, field_name="queue_admitted_at")
        if queue_admitted_at > expires_at:
            raise GuardReviewContractError("remote_approval_expired")
    payload_hash = _non_empty_string(envelope.get("payloadHash"))
    if payload_hash is None or payload_hash != payload_hash_for_remote_approval_envelope(envelope):
        raise GuardReviewContractError("remote_approval_payload_hash_mismatch")
    workspace_id = _non_empty_string(envelope.get("workspaceId"))
    if workspace_id is None:
        raise GuardReviewContractError("signing_key_workspace_mismatch")
    _verify_signed_payload(
        envelope,
        signature_algorithm=_non_empty_string(envelope.get("signatureAlgorithm")) or "",
        store=store,
        expected_key_purpose=_REMOTE_APPROVAL_KEY_PURPOSE,
        expected_workspace_id=workspace_id,
    )
    return envelope


def validate_remote_approval_request_binding(
    *,
    envelope: dict[str, object],
    request_row: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    store,
    claim_request_row: dict[str, object] | None = None,
) -> None:
    claim_row = claim_request_row if claim_request_row is not None else request_row
    if _non_empty_string(envelope.get("localRequestId")) != _non_empty_string(request_row.get("request_id")):
        raise GuardReviewContractError("remote_approval_request_id_mismatch")
    if _non_empty_string(envelope.get("approvalId")) != _non_empty_string(request_row.get("request_id")):
        raise GuardReviewContractError("remote_approval_approval_id_mismatch")
    if _non_empty_string(envelope.get("workspaceId")) != oauth.workspace_id:
        raise GuardReviewContractError("remote_approval_workspace_mismatch")
    if _non_empty_string(envelope.get("machineInstallationId")) != oauth.installation_id:
        raise GuardReviewContractError("remote_approval_installation_mismatch")
    if _non_empty_string(envelope.get("machineId")) != oauth.machine_id:
        raise GuardReviewContractError("remote_approval_machine_mismatch")
    if _non_empty_string(envelope.get("deviceId")) != oauth.device_id:
        raise GuardReviewContractError("remote_approval_device_mismatch")
    if _non_empty_string(envelope.get("runtimeId")) != oauth.runtime_id:
        raise GuardReviewContractError("remote_approval_runtime_mismatch")
    reviewer_user_id = _non_empty_string(envelope.get("reviewerUserId"))
    reviewer_role = _non_empty_string(envelope.get("reviewerRole"))
    if reviewer_user_id is None or reviewer_role not in _REMOTE_APPROVAL_RESOLVER_ROLES:
        raise GuardReviewContractError("remote_approval_reviewer_not_authorized")
    if remote_approval_uses_workspace_admin_mfa(envelope):
        if reviewer_role not in _REMOTE_APPROVAL_ADMIN_ROLES:
            raise GuardReviewContractError("remote_approval_reviewer_not_authorized")
        if _non_empty_string(envelope.get("stepUpChallengeId")) is None:
            raise GuardReviewContractError("remote_approval_step_up_required")
    if _non_empty_string(envelope.get("harnessId")) != _non_empty_string(claim_row.get("harness")):
        raise GuardReviewContractError("remote_approval_harness_mismatch")
    if _non_empty_string(envelope.get("actionEnvelopeHash")) != _action_envelope_hash(claim_row):
        raise GuardReviewContractError("remote_approval_action_hash_mismatch")
    if _non_empty_string(envelope.get("policyVersion")) != _policy_version(claim_row):
        raise GuardReviewContractError("remote_approval_policy_version_mismatch")
    expected_claim = build_local_review_request_claim(request_row=claim_row, oauth=oauth, store=store)
    source_claim_hash = envelope.get("sourceClaimHash")
    if envelope.get("nativeBindingVersion") == NATIVE_BINDING_VERSION:
        hash_matches = native_binding_commitment_matches(expected_claim) and (
            _non_empty_string(source_claim_hash) == _non_empty_string(expected_claim.get("claimHash"))
            and _non_empty_string(envelope.get("nativeBindingDigest"))
            == _non_empty_string(expected_claim.get("nativeBindingDigest"))
        )
    elif envelope.get("nativeBindingVersion") is None:
        hash_matches = envelope.get("nativeBindingDigest") is None and (
            _non_empty_string(source_claim_hash) == compute_legacy_local_review_request_claim_hash(expected_claim)
        )
    else:
        hash_matches = False
    if not hash_matches:
        raise GuardReviewContractError("remote_approval_claim_hash_mismatch")
    expected_nonce = _non_empty_string(expected_claim.get("nonce"))
    receipt_id = _non_empty_string(envelope.get("receiptId"))
    envelope_nonce = _non_empty_string(envelope.get("nonce"))
    if expected_nonce is None or receipt_id is None or envelope_nonce != f"{expected_nonce}:{receipt_id}":
        raise GuardReviewContractError("remote_approval_nonce_mismatch")
    envelope_scope = _non_empty_string(envelope.get("scope"))
    action = normalize_remote_approval_decision(envelope.get("decision"))
    if action is None:
        raise GuardReviewContractError("invalid_remote_approval_decision")
    contract = request_scope_contract(claim_row)
    if envelope_scope is None:
        raise GuardReviewContractError("remote_approval_scope_mismatch")
    try:
        resolve_request_scope_selection(
            claim_row,
            action=action,
            requested_scope=envelope_scope,
            contract_version=APPROVAL_SCOPE_CONTRACT_VERSION,
            contract_digest=contract.digest,
        )
    except (IneligibleApprovalScopeError, ValueError) as error:
        raise GuardReviewContractError("remote_approval_scope_mismatch") from error


def _request_recommended_scope(request_row: dict[str, object], *, decision: str | None = None) -> str | None:
    recommendations = request_row.get("recommended_scope_by_action")
    if isinstance(recommendations, dict):
        action = "block" if decision == "block" else "allow"
        selected = _non_empty_string(recommendations.get(action))
        if selected is not None:
            return selected
        if decision is None:
            fallback = _non_empty_string(recommendations.get("block"))
            if fallback is not None:
                return fallback
    return _non_empty_string(request_row.get("recommended_scope"))


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
