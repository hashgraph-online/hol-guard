"""Guard Review backend contracts shared by local daemon and command queue."""

from __future__ import annotations

import base64
import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    merge_policy_bundle_trusted_keys,
    policy_bundle_keys_from_supply_chain_keyring,
    resolve_policy_bundle_signing_key,
    safe_load_policy_bundle_verification_keys,
    signing_key_is_current,
)

_LOCAL_REVIEW_REQUEST_CONTRACT_VERSION = "guard.local-review-request.v1"
_REMOTE_APPROVAL_CONTRACT_VERSION = "guard.remote-approval.v1"
_DECISION_MEMORY_BUNDLE_CONTRACT_VERSION = "guard.decision-memory-bundle.v1"
_REMOTE_APPROVAL_ALLOWED_SCOPES = frozenset(("artifact", "one-time"))
_REMOTE_APPROVAL_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
_DECISION_MEMORY_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
_CLAIM_HASH_KEYS = ("claimHash",)
_SIGNED_PAYLOAD_STRIP_KEYS = ("payloadHash", "signature", "signatureAlgorithm", "verificationKeys", "bundleHash")
_GUARD_REVIEW_VERIFICATION_KEYRING_SYNC_KEY = "guard_review_verification_keyring"


class GuardReviewContractError(ValueError):
    """Raised when a Guard Review backend contract is malformed or unsafe."""


@dataclass(frozen=True, slots=True)
class GuardReviewOAuthMetadata:
    device_id: str
    grant_id: str | None
    installation_id: str
    machine_id: str
    runtime_id: str | None
    workspace_id: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stable_serialize(value: object) -> str:
    if isinstance(value, list):
        return f"[{','.join(_stable_serialize(item) for item in value)}]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                f"{json.dumps(key, separators=(',', ':'), ensure_ascii=False)}:{_stable_serialize(value[key])}"
                for key in sorted(value)
            )
            + "}"
        )
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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


def _verification_keys_from_payload(value: object) -> tuple[PolicyBundleVerificationKey, ...]:
    if not isinstance(value, list) or not value:
        raise GuardReviewContractError("missing_verification_keys")
    parsed: list[PolicyBundleVerificationKey] = []
    for item in value:
        if not isinstance(item, dict):
            raise GuardReviewContractError("invalid_verification_key")
        parsed.append(PolicyBundleVerificationKey.from_dict(item))
    return tuple(parsed)


def _anchored_review_verification_keys(store) -> tuple[PolicyBundleVerificationKey, ...]:
    return merge_policy_bundle_trusted_keys(
        safe_load_policy_bundle_verification_keys(store.get_sync_payload(_GUARD_REVIEW_VERIFICATION_KEYRING_SYNC_KEY)),
        safe_load_policy_bundle_verification_keys(store.get_sync_payload("policy_bundle_keyring")),
        policy_bundle_keys_from_supply_chain_keyring(store.get_sync_payload("supply_chain_bundle_keyring")),
    )


def _resolve_anchored_signing_key(
    *,
    advertised_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
    key_id: str,
) -> PolicyBundleVerificationKey:
    signing_key = resolve_policy_bundle_signing_key(key_id, anchored_keys)
    if signing_key is None:
        raise GuardReviewContractError("unknown_signing_key")
    advertised_key = resolve_policy_bundle_signing_key(key_id, advertised_keys)
    if advertised_key is None:
        raise GuardReviewContractError("missing_signing_key")
    if advertised_key.fingerprint_sha256 != signing_key.fingerprint_sha256:
        raise GuardReviewContractError("untrusted_signing_key")
    if not signing_key_is_current(signing_key):
        raise GuardReviewContractError("expired_signing_key")
    return signing_key


def _verify_signed_payload(
    payload: dict[str, object],
    *,
    signature_algorithm: str,
    store,
) -> None:
    if signature_algorithm not in {_REMOTE_APPROVAL_SIGNATURE_ALGORITHM, _DECISION_MEMORY_SIGNATURE_ALGORITHM}:
        raise GuardReviewContractError("invalid_signature_algorithm")
    signature = _non_empty_string(payload.get("signature"))
    if signature is None:
        raise GuardReviewContractError("missing_signature")
    key_id = _non_empty_string(payload.get("issuerKeyId")) or _non_empty_string(payload.get("keyId"))
    if key_id is None:
        verifier = payload.get("verifier")
        if isinstance(verifier, dict):
            key_id = _non_empty_string(verifier.get("keyId"))
    if key_id is None:
        raise GuardReviewContractError("missing_signing_key_id")
    advertised_keys = _verification_keys_from_payload(payload.get("verificationKeys"))
    signing_key = _resolve_anchored_signing_key(
        advertised_keys=advertised_keys,
        anchored_keys=_anchored_review_verification_keys(store),
        key_id=key_id,
    )
    try:
        public_key = serialization.load_pem_public_key(signing_key.public_key_pem.encode("utf-8"))
    except (UnsupportedAlgorithm, ValueError, TypeError) as error:
        raise GuardReviewContractError("invalid_signing_key") from error
    if not isinstance(public_key, RSAPublicKey):
        raise GuardReviewContractError("invalid_signing_key")
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception as error:  # pragma: no cover - defensive
        raise GuardReviewContractError("invalid_signature") from error
    canonical_payload = _canonical_signed_payload(payload).encode("utf-8")
    try:
        public_key.verify(
            signature_bytes,
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise GuardReviewContractError("signature_mismatch") from error


def guard_review_oauth_metadata(store) -> GuardReviewOAuthMetadata:
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    if not isinstance(credentials, dict):
        raise GuardReviewContractError("missing_oauth_credentials")
    installation_id = _non_empty_string(store.get_or_create_installation_id())
    machine_id = _non_empty_string(credentials.get("machine_id"))
    workspace_id = _non_empty_string(credentials.get("workspace_id"))
    if installation_id is None or machine_id is None or workspace_id is None:
        raise GuardReviewContractError("missing_oauth_binding")
    device_id = _non_empty_string(credentials.get("device_id")) or machine_id
    return GuardReviewOAuthMetadata(
        device_id=device_id,
        grant_id=_non_empty_string(credentials.get("grant_id")),
        installation_id=installation_id,
        machine_id=machine_id,
        runtime_id=_non_empty_string(credentials.get("runtime_id")),
        workspace_id=workspace_id,
    )


def _action_envelope_hash(request_row: dict[str, object]) -> str:
    envelope = _read_json_mapping(request_row.get("action_envelope_json")) or {}
    return _sha256_hex(_stable_serialize(envelope))


def _project_identity(request_row: dict[str, object], store) -> str | None:
    operation = store.get_guard_operation_for_approval_request(str(request_row["request_id"]))
    if not isinstance(operation, dict):
        return None
    metadata = operation.get("metadata")
    if isinstance(metadata, dict):
        for key in ("project_id", "projectId", "workspace_path", "workspacePath"):
            value = _non_empty_string(metadata.get(key))
            if value is not None:
                return value
    return _non_empty_string(operation.get("operation_id"))


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
    recommended_scope = _non_empty_string(request_row.get("recommended_scope"))
    created_at = _non_empty_string(request_row.get("created_at"))
    last_seen_at = _non_empty_string(request_row.get("last_seen_at")) or created_at
    required_fields = (
        local_request_id,
        approval_id,
        artifact_id,
        harness_id,
        policy_action,
        recommended_scope,
        created_at,
        last_seen_at,
    )
    if None in required_fields:
        raise GuardReviewContractError("invalid_request_row")
    claim: dict[str, object] = {
        "contractVersion": _LOCAL_REVIEW_REQUEST_CONTRACT_VERSION,
        "actionEnvelopeHash": _action_envelope_hash(request_row),
        "actionIdentity": _non_empty_string(request_row.get("action_identity")) or local_request_id,
        "approvalId": approval_id,
        "artifactHash": _non_empty_string(request_row.get("artifact_hash")),
        "artifactId": artifact_id,
        "capabilityCategory": _capability_category(request_row),
        "createdAt": created_at,
        "deviceId": oauth.device_id,
        "expiresAt": _claim_expiry(request_row),
        "harnessId": harness_id,
        "lastSeenAt": last_seen_at,
        "localRequestId": local_request_id,
        "machineId": oauth.machine_id,
        "machineInstallationId": oauth.installation_id,
        "nonce": _non_empty_string(request_row.get("queue_group_id")) or local_request_id,
        "policyAction": policy_action,
        "policyVersion": _policy_version(request_row),
        "projectIdentity": _project_identity(request_row, store),
        "queueGroupId": _non_empty_string(request_row.get("queue_group_id")),
        "recommendedScope": recommended_scope,
        "riskCategory": _risk_category(request_row),
        "runtimeGrantId": oauth.runtime_id,
        "workspaceId": oauth.workspace_id,
    }
    claim["claimHash"] = compute_local_review_request_claim_hash(claim)
    return claim


def compute_local_review_request_claim_hash(claim: dict[str, object]) -> str:
    return _sha256_hex(_stable_serialize(_strip_keys(claim, _CLAIM_HASH_KEYS)))


def validate_local_review_request_claim(claim: dict[str, object]) -> dict[str, object]:
    if claim.get("contractVersion") != _LOCAL_REVIEW_REQUEST_CONTRACT_VERSION:
        raise GuardReviewContractError("unsupported_claim_contract_version")
    expected_hash = compute_local_review_request_claim_hash(claim)
    if _non_empty_string(claim.get("claimHash")) != expected_hash:
        raise GuardReviewContractError("claim_hash_mismatch")
    return claim


def payload_hash_for_remote_approval_envelope(envelope: dict[str, object]) -> str:
    return _sha256_hex(_canonical_signed_payload(envelope))


def validated_remote_approval_envelope(envelope: dict[str, object], *, store) -> dict[str, object]:
    if envelope.get("contractVersion") != _REMOTE_APPROVAL_CONTRACT_VERSION:
        raise GuardReviewContractError("unsupported_remote_approval_contract")
    if envelope.get("scope") not in _REMOTE_APPROVAL_ALLOWED_SCOPES:
        raise GuardReviewContractError("invalid_remote_approval_scope")
    issued_at = _parse_iso_timestamp(envelope.get("issuedAt"), field_name="issued_at")
    expires_at = _parse_iso_timestamp(envelope.get("expiresAt"), field_name="expires_at")
    if expires_at <= issued_at or expires_at <= _now():
        raise GuardReviewContractError("remote_approval_expired")
    payload_hash = _non_empty_string(envelope.get("payloadHash"))
    if payload_hash is None or payload_hash != payload_hash_for_remote_approval_envelope(envelope):
        raise GuardReviewContractError("remote_approval_payload_hash_mismatch")
    _verify_signed_payload(
        envelope,
        signature_algorithm=_non_empty_string(envelope.get("signatureAlgorithm")) or "",
        store=store,
    )
    return envelope


def validate_remote_approval_request_binding(
    *,
    envelope: dict[str, object],
    request_row: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
    store,
) -> None:
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
    if _non_empty_string(envelope.get("harnessId")) != _non_empty_string(request_row.get("harness")):
        raise GuardReviewContractError("remote_approval_harness_mismatch")
    if _non_empty_string(envelope.get("actionEnvelopeHash")) != _action_envelope_hash(request_row):
        raise GuardReviewContractError("remote_approval_action_hash_mismatch")
    if _non_empty_string(envelope.get("policyVersion")) != _policy_version(request_row):
        raise GuardReviewContractError("remote_approval_policy_version_mismatch")
    expected_claim = build_local_review_request_claim(request_row=request_row, oauth=oauth, store=store)
    if _non_empty_string(envelope.get("sourceClaimHash")) != _non_empty_string(expected_claim.get("claimHash")):
        raise GuardReviewContractError("remote_approval_claim_hash_mismatch")


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
