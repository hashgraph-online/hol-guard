"""Policy bundle schema validation and integrity hashing."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from ..version import __version__
from .cloud_exceptions import policy_bundle_cloud_exceptions_are_valid
from .config import VALID_RECEIPT_REDACTION_LEVELS
from .policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    policy_bundle_key_fingerprint,
    resolve_authorized_policy_bundle_signing_key,
)
from .policy_bundle_v2 import (
    POLICY_BUNDLE_MAX_BYTES,
    POLICY_BUNDLE_MAX_COLLECTION_ITEMS,
    POLICY_BUNDLE_MAX_DEPTH,
    POLICY_BUNDLE_MAX_STRING_LENGTH,
)

_POLICY_BUNDLE_CORE_KEYS = (
    "contractVersion",
    "bundleVersion",
    "issuedAt",
    "expiresAt",
    "verifier",
    "rolloutState",
    "policyDefaults",
    "rules",
)

# receiptRedactionLevel is included in the policy bundle signing payload by the
# portal (buildPolicyBundleCore), so it must be part of the canonical hash.
# Older bundles may not have it, so treat it as optional in hash computation.
_POLICY_BUNDLE_OPTIONAL_CORE_KEYS = ("receiptRedactionLevel",)

_POLICY_BUNDLE_DEFAULT_ACTIONS = frozenset({"allow", "warn", "block"})
_POLICY_BUNDLE_MODE_VALUES = frozenset({"observe", "prompt", "enforce"})
_POLICY_BUNDLE_REVIEW_ACTIONS = frozenset({"allow", "review", "block"})
_POLICY_BUNDLE_CHANGED_HASH_ACTIONS = frozenset({"allow", "warn", "require-reapproval", "block"})
_POLICY_BUNDLE_RULE_ACTIONS = frozenset({"allow", "block", "review", "ignore"})
_POLICY_BUNDLE_ROLLOUT_STATES = frozenset(
    {"draft", "simulated", "pending_approval", "enforcing", "enforced", "rollback_available"}
)
_POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES = frozenset({"enforcing", "enforced", "rollback_available"})
_POLICY_BUNDLE_BROWSER_SCOPE_KEYS = frozenset(
    {
        "browserIntent",
        "browserOperation",
        "browserProfile",
        "origin",
        "pathPrefix",
        "sensitiveSurface",
    }
)
_POLICY_BUNDLE_SCOPE_KEYS = _POLICY_BUNDLE_BROWSER_SCOPE_KEYS | frozenset(
    {
        "agents",
        "devices",
        "ecosystems",
        "environments",
        "harnesses",
        "locations",
    }
)
_VALID_BROWSER_INTENTS = frozenset(
    {
        "browser.navigation",
        "browser.inspect",
        "browser.interact",
        "browser.transfer",
        "browser.privileged",
    }
)
_VALID_BROWSER_PROFILES = frozenset({"isolated", "dedicated", "shared", "remote-debugging", "unknown"})
_POLICY_BUNDLE_RULE_MATCHER_FAMILIES = frozenset(
    {"file-read", "mcp", "mcp-tool", "package-request", "prompt", "prompt-env-read", "tool-action"}
)
_POLICY_BUNDLE_DEFAULT_ENVIRONMENTS = frozenset({"development"})
_POLICY_BUNDLE_CLOCK_SKEW_SECONDS = 300
_POLICY_BUNDLE_TRUST_REMEDIATION_REASONS = frozenset(
    {
        "missing_signature",
        "missing_signing_key_id",
        "signing_key_fingerprint_mismatch",
        "signing_key_not_current",
        "signing_key_purpose_mismatch",
        "signing_key_revoked",
        "signing_key_workspace_mismatch",
        "trusted_key_unavailable",
        "unsupported_signature_algorithm",
        "untrusted_signing_key",
    }
)
_POLICY_BUNDLE_SIGNATURE_REMEDIATION_REASONS = frozenset(
    {
        "bundle_signature_invalid",
        "invalid_signature_encoding",
        "invalid_verifier",
    }
)
_POLICY_BUNDLE_INTEGRITY_REMEDIATION_REASONS = frozenset(
    {
        "bundle_hash_mismatch",
        "invalid_bundle_hash",
        "invalid_payload_hash",
        "payload_hash_mismatch",
    }
)
_POLICY_BUNDLE_SCHEMA_REMEDIATION_REASONS = frozenset(
    {
        "invalid_acknowledgements",
        "invalid_cloud_exceptions",
        "invalid_policy_bundle",
        "invalid_policy_defaults",
        "invalid_receipt_redaction_level",
        "invalid_rollout_state",
        "invalid_rules",
        "missing_required_field",
    }
)
_POLICY_BUNDLE_WORKSPACE_REMEDIATION_REASONS = frozenset({"invalid_workspace_id", "wrong_workspace"})
_POLICY_BUNDLE_FRESHNESS_REMEDIATION_REASONS = frozenset(
    {"bundle_expired", "bundle_not_yet_valid", "invalid_expires_at", "invalid_issued_at"}
)
_POLICY_BUNDLE_VERSION_REMEDIATION_REASONS = frozenset(
    {
        "bundle_version_downgrade",
        "invalid_bundle_version",
        "invalid_min_daemon_version",
        "unsupported_contract_version",
        "unsupported_daemon_version",
    }
)


def _policy_bundle_resource_limit_error(value: object) -> str | None:
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > POLICY_BUNDLE_MAX_DEPTH:
            return "limit_depth"
        if isinstance(current, str):
            if len(current.encode("utf-8")) > POLICY_BUNDLE_MAX_STRING_LENGTH:
                return "limit_string"
            continue
        if current is None or isinstance(current, (bool, int, float)):
            continue
        if isinstance(current, dict):
            if len(current) > POLICY_BUNDLE_MAX_COLLECTION_ITEMS:
                return "limit_collection"
            if not all(isinstance(key, str) for key in current):
                return "invalid_json_value"
            stack.extend((item, depth + 1) for item in current.values())
            continue
        if isinstance(current, list):
            if len(current) > POLICY_BUNDLE_MAX_COLLECTION_ITEMS:
                return "limit_collection"
            stack.extend((item, depth + 1) for item in current)
            continue
        return "invalid_json_value"
    try:
        encoded = json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError):
        return "invalid_json_value"
    return "limit_bytes" if len(encoded) > POLICY_BUNDLE_MAX_BYTES else None


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


def computed_policy_bundle_hash(policy_bundle: dict[str, object]) -> str:
    bundle_core: dict[str, object] = {}
    for key in _POLICY_BUNDLE_CORE_KEYS:
        if key not in policy_bundle:
            raise ValueError(f"missing_policy_bundle_key:{key}")
        bundle_core[key] = policy_bundle[key]
    for key in _POLICY_BUNDLE_OPTIONAL_CORE_KEYS:
        if key in policy_bundle:
            bundle_core[key] = policy_bundle[key]
    verifier = bundle_core.get("verifier")
    if isinstance(verifier, dict):
        normalized_verifier = dict(verifier)
        if verifier.get("algorithm") == "rsa-pss-sha256":
            normalized_verifier["publicKeyPem"] = None
        else:
            normalized_verifier.pop("publicKeyPem", None)
        normalized_verifier["signature"] = None
        bundle_core["verifier"] = normalized_verifier
    workspace_id = policy_bundle.get("workspaceId")
    if workspace_id is not None:
        bundle_core["workspaceId"] = workspace_id
    min_daemon_version = _non_empty_string(policy_bundle.get("minDaemonVersion"))
    if min_daemon_version is not None:
        bundle_core["minDaemonVersion"] = min_daemon_version
    return f"sha256:{hashlib.sha256(_stable_serialize(bundle_core).encode('utf-8')).hexdigest()}"


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _policy_bundle_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _policy_bundle_rule_is_valid(rule: object) -> bool:
    if not isinstance(rule, dict):
        return False
    if _non_empty_string(rule.get("ruleId")) is None:
        return False
    if rule.get("action") not in _POLICY_BUNDLE_RULE_ACTIONS:
        return False
    if not isinstance(rule.get("reason"), str):
        return False
    source_receipt_id = rule.get("sourceReceiptId")
    if source_receipt_id is not None and _non_empty_string(source_receipt_id) is None:
        return False
    source_local_request_id = rule.get("sourceLocalRequestId")
    if source_local_request_id is not None and _non_empty_string(source_local_request_id) is None:
        return False
    source_receipt_ids = rule.get("sourceReceiptIds")
    if source_receipt_ids is not None and not _policy_bundle_string_list(source_receipt_ids):
        return False
    audit_event_ids = rule.get("auditEventIds")
    if audit_event_ids is not None and not _policy_bundle_string_list(audit_event_ids):
        return False
    if "matcherFamilies" in rule:
        matcher_families = rule.get("matcherFamilies")
        if not isinstance(matcher_families, list) or any(
            _non_empty_string(family) is None or family not in _POLICY_BUNDLE_RULE_MATCHER_FAMILIES
            for family in matcher_families
        ):
            return False
    expires_at = rule.get("expiresAt")
    if expires_at is not None:
        normalized_expiry = _non_empty_string(expires_at)
        if normalized_expiry is None or _parse_policy_bundle_timestamp(normalized_expiry) is None:
            return False
    scope = rule.get("scope")
    if not isinstance(scope, dict):
        return False
    # Validate that all present scope keys map to string lists
    for key in _POLICY_BUNDLE_SCOPE_KEYS:
        if key in scope and not _policy_bundle_string_list(scope.get(key)):
            return False
    # Validate browser scope enum values (HGBM073)
    browser_intent = scope.get("browserIntent")
    if browser_intent is not None:
        if not _policy_bundle_string_list(browser_intent):
            return False
        for intent_value in browser_intent:
            if intent_value not in _VALID_BROWSER_INTENTS:
                return False
    browser_profile = scope.get("browserProfile")
    if browser_profile is not None:
        if not _policy_bundle_string_list(browser_profile):
            return False
        for profile_value in browser_profile:
            if profile_value not in _VALID_BROWSER_PROFILES:
                return False
    return True


def _policy_bundle_acknowledgement_is_valid(acknowledgement: object) -> bool:
    if not isinstance(acknowledgement, dict):
        return False
    if _non_empty_string(acknowledgement.get("deviceId")) is None:
        return False
    device_name = acknowledgement.get("deviceName")
    if device_name is not None and _non_empty_string(device_name) is None:
        return False
    acknowledged_at = acknowledgement.get("acknowledgedAt")
    if acknowledged_at is not None and _non_empty_string(acknowledged_at) is None:
        return False
    return acknowledgement.get("status") in {"pending", "synced", "failed", "offline"}


def canonical_policy_bundle_payload(policy_bundle: dict[str, object]) -> bytes:
    bundle_core: dict[str, object] = {}
    for key in _POLICY_BUNDLE_CORE_KEYS:
        if key not in policy_bundle:
            raise ValueError(f"missing_policy_bundle_key:{key}")
        bundle_core[key] = policy_bundle[key]
    for key in _POLICY_BUNDLE_OPTIONAL_CORE_KEYS:
        if key in policy_bundle:
            bundle_core[key] = policy_bundle[key]
    verifier = bundle_core.get("verifier")
    if isinstance(verifier, dict):
        normalized_verifier = dict(verifier)
        if verifier.get("algorithm") == "rsa-pss-sha256":
            normalized_verifier["publicKeyPem"] = None
        normalized_verifier["signature"] = None
        bundle_core["verifier"] = normalized_verifier
    workspace_id = policy_bundle.get("workspaceId")
    if workspace_id is not None:
        bundle_core["workspaceId"] = workspace_id
    acknowledgements = policy_bundle.get("acknowledgements")
    if acknowledgements is None:
        raise ValueError("missing_policy_bundle_key:acknowledgements")
    bundle_core["acknowledgements"] = acknowledgements
    cloud_exceptions = policy_bundle.get("cloudExceptions")
    if cloud_exceptions is not None:
        bundle_core["cloudExceptions"] = cloud_exceptions
    min_daemon_version = _non_empty_string(policy_bundle.get("minDaemonVersion"))
    if min_daemon_version is not None:
        bundle_core["minDaemonVersion"] = min_daemon_version
    return _stable_serialize(bundle_core).encode("utf-8")


def payload_hash_for_policy_bundle(policy_bundle: dict[str, object]) -> str:
    return hashlib.sha256(canonical_policy_bundle_payload(policy_bundle)).hexdigest()


def _version_tuple(value: str) -> tuple[int, ...] | None:
    tokens = [token for token in re.split(r"[^0-9]+", value) if token]
    if not tokens:
        return None
    return tuple(int(token) for token in tokens)


def policy_bundle_daemon_version_supported(policy_bundle: dict[str, object]) -> bool:
    min_daemon_version = _non_empty_string(policy_bundle.get("minDaemonVersion"))
    if min_daemon_version is None:
        return True
    current = _version_tuple(__version__)
    minimum = _version_tuple(min_daemon_version)
    return current is not None and minimum is not None and current >= minimum


def policy_bundle_is_enforceable(policy_bundle: dict[str, object]) -> bool:
    """Return whether an authenticated rollout is intended as live authority."""

    if policy_bundle.get("contractVersion") == "guard-policy-bundle.v2":
        return True
    return policy_bundle.get("rolloutState") in _POLICY_BUNDLE_ENFORCEABLE_ROLLOUT_STATES


def policy_bundle_acceptance_checkpoint(policy_bundle: dict[str, object]) -> dict[str, object]:
    """Return the signed identity fields needed for monotonic replay defense."""

    checkpoint = {
        "bundleHash": policy_bundle.get("bundleHash"),
        "bundleVersion": policy_bundle.get("bundleVersion"),
        "issuedAt": policy_bundle.get("issuedAt"),
        "payloadHash": policy_bundle.get("payloadHash"),
        "workspaceId": policy_bundle.get("workspaceId"),
    }
    return {key: value for key, value in checkpoint.items() if value is not None}


def policy_bundle_is_version_downgrade(
    accepted_bundle: dict[str, object] | None,
    candidate_bundle: dict[str, object],
) -> bool:
    """Reject older or unordered signed payloads relative to accepted authority.

    ``bundleHash`` covers the portal's core policy projection, while the signed
    ``payloadHash`` additionally covers acknowledgements and Cloud exceptions.
    Equality is therefore safe only when both integrity identities match. A
    distinct payload at the same issue instant and version is unordered and is
    rejected so an older signed variant cannot be replayed.
    """

    if not isinstance(accepted_bundle, dict) or not accepted_bundle:
        return False
    accepted_v2_version = accepted_bundle.get("bundleVersion")
    candidate_v2_version = candidate_bundle.get("bundleVersion")
    if (
        isinstance(accepted_v2_version, int)
        and not isinstance(accepted_v2_version, bool)
        and isinstance(candidate_v2_version, int)
        and not isinstance(candidate_v2_version, bool)
    ):
        if candidate_v2_version != accepted_v2_version:
            return candidate_v2_version < accepted_v2_version
        return accepted_bundle.get("bundleHash") != candidate_bundle.get("bundleHash")
    accepted_workspace = _non_empty_string(accepted_bundle.get("workspaceId"))
    candidate_workspace = _non_empty_string(candidate_bundle.get("workspaceId"))
    if accepted_workspace is not None and candidate_workspace is not None and accepted_workspace != candidate_workspace:
        # Workspace reconnects start an independent policy version sequence.
        return False
    accepted_bundle_hash = _non_empty_string(accepted_bundle.get("bundleHash"))
    candidate_bundle_hash = _non_empty_string(candidate_bundle.get("bundleHash"))
    accepted_payload_hash = _non_empty_string(accepted_bundle.get("payloadHash"))
    candidate_payload_hash = _non_empty_string(candidate_bundle.get("payloadHash"))
    if (
        accepted_bundle_hash is not None
        and accepted_bundle_hash == candidate_bundle_hash
        and (
            (accepted_payload_hash is not None and accepted_payload_hash == candidate_payload_hash)
            or (accepted_payload_hash is None and candidate_payload_hash is None)
        )
    ):
        return False
    accepted_issued_at = _non_empty_string(accepted_bundle.get("issuedAt"))
    candidate_issued_at = _non_empty_string(candidate_bundle.get("issuedAt"))
    if accepted_issued_at is None or candidate_issued_at is None:
        return True
    accepted_timestamp = _parse_policy_bundle_timestamp(accepted_issued_at)
    candidate_timestamp = _parse_policy_bundle_timestamp(candidate_issued_at)
    if accepted_timestamp is None or candidate_timestamp is None:
        return True
    if candidate_timestamp != accepted_timestamp:
        return candidate_timestamp < accepted_timestamp

    accepted_version = _non_empty_string(accepted_bundle.get("bundleVersion"))
    candidate_version = _non_empty_string(candidate_bundle.get("bundleVersion"))
    if accepted_version is None or candidate_version is None:
        return True
    accepted_numeric = _version_tuple(accepted_version)
    candidate_numeric = _version_tuple(candidate_version)
    if accepted_numeric is None or candidate_numeric is None:
        return (
            accepted_version != candidate_version
            or accepted_bundle_hash != candidate_bundle_hash
            or accepted_payload_hash != candidate_payload_hash
        )
    return candidate_numeric <= accepted_numeric


def _verify_policy_bundle_signature(
    policy_bundle: dict[str, object],
    canonical_payload: bytes,
    *,
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...],
    expected_workspace_id: str | None,
    now: float | None,
) -> str | None:
    verifier = policy_bundle.get("verifier")
    if not isinstance(verifier, dict):
        return "invalid_verifier"
    algorithm = verifier.get("algorithm")
    if algorithm != "rsa-pss-sha256":
        return "unsupported_signature_algorithm"
    key_id = _non_empty_string(verifier.get("keyId"))
    signature = _non_empty_string(verifier.get("signature"))
    if key_id is None:
        return "missing_signing_key_id"
    if signature is None:
        return "missing_signature"
    signing_key, authority_error = resolve_authorized_policy_bundle_signing_key(
        key_id,
        trusted_keys=trusted_verification_keys,
        anchored_keys=anchored_verification_keys,
        expected_workspace_id=expected_workspace_id,
        now=now,
    )
    if signing_key is None:
        return authority_error or "untrusted_signing_key"
    bundled_public_key = verifier.get("publicKeyPem")
    if bundled_public_key is not None:
        bundled_public_key_pem = _non_empty_string(bundled_public_key)
        if bundled_public_key_pem is None:
            return "invalid_verifier"
        bundled_fingerprint = policy_bundle_key_fingerprint(bundled_public_key_pem)
        if bundled_fingerprint != signing_key.fingerprint_sha256:
            return "signing_key_fingerprint_mismatch"
    embedded_fingerprint = verifier.get("fingerprintSha256")
    if embedded_fingerprint is not None:
        normalized_fingerprint = _non_empty_string(embedded_fingerprint)
        if normalized_fingerprint is None:
            return "invalid_verifier"
        if normalized_fingerprint != signing_key.fingerprint_sha256:
            return "signing_key_fingerprint_mismatch"
    try:
        public_key = serialization.load_pem_public_key(signing_key.public_key_pem.encode("utf-8"))
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return "invalid_verifier"
    if not isinstance(public_key, RSAPublicKey):
        return "invalid_verifier"
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        return "invalid_signature_encoding"
    try:
        public_key.verify(
            signature_bytes,
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError):
        return "bundle_signature_invalid"
    return None


def _parse_policy_bundle_timestamp(value: str) -> float | None:
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).timestamp()


def policy_bundle_rejection_message(reason: str | None) -> str | None:
    if reason == "inactive_rollout_state":
        return (
            "The authenticated policy bundle is not active for local enforcement. "
            "Approve or publish the rollout in Guard Cloud, then sync again."
        )
    if reason in _POLICY_BUNDLE_TRUST_REMEDIATION_REASONS | _POLICY_BUNDLE_SIGNATURE_REMEDIATION_REASONS:
        return (
            "The policy bundle was not applied because its signing authority could not be verified. "
            "Sync again after the workspace policy signing key is provisioned or rotated."
        )
    if reason in _POLICY_BUNDLE_INTEGRITY_REMEDIATION_REASONS:
        return (
            "The policy bundle was not applied because its integrity checks failed. "
            "Sync again to fetch a complete policy bundle; if the error persists, contact your workspace administrator."
        )
    if reason in _POLICY_BUNDLE_SCHEMA_REMEDIATION_REASONS:
        return (
            "The policy bundle was not applied because its schema or required fields are invalid. "
            "Sync again to fetch a complete policy bundle; if the error persists, contact your workspace administrator."
        )
    if reason in _POLICY_BUNDLE_WORKSPACE_REMEDIATION_REASONS:
        return (
            "The policy bundle was not applied because it does not match the connected workspace. "
            "Reconnect Guard to the intended workspace. Sync again after the workspace connection is confirmed."
        )
    if reason in _POLICY_BUNDLE_FRESHNESS_REMEDIATION_REASONS:
        return (
            "The policy bundle was not applied because its validity period is not current. "
            "Check the system clock. Sync again to fetch the current workspace policy."
        )
    if reason in _POLICY_BUNDLE_VERSION_REMEDIATION_REASONS:
        return (
            "The policy bundle was not applied because its contract or daemon version is incompatible. "
            "Update Guard to a supported version if required. Sync again to fetch the current workspace policy."
        )
    return None


def validated_policy_bundle_payload(
    policy_bundle: dict[str, object],
    *,
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    expected_workspace_id: str | None = None,
    now: float | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    resource_error = _policy_bundle_resource_limit_error(policy_bundle)
    if resource_error is not None:
        return None, resource_error
    required_top_level = (*_POLICY_BUNDLE_CORE_KEYS, "bundleHash", "acknowledgements")
    if any(key not in policy_bundle for key in required_top_level):
        return None, "missing_required_field"
    if policy_bundle.get("contractVersion") != "guard-policy-bundle.v1":
        return None, "unsupported_contract_version"
    if _non_empty_string(policy_bundle.get("bundleVersion")) is None:
        return None, "invalid_bundle_version"
    issued_at = _non_empty_string(policy_bundle.get("issuedAt"))
    if issued_at is None:
        return None, "invalid_issued_at"
    issued_at_timestamp = _parse_policy_bundle_timestamp(issued_at)
    if issued_at_timestamp is None:
        return None, "invalid_issued_at"
    expires_at = policy_bundle.get("expiresAt")
    if expires_at is not None and _non_empty_string(expires_at) is None:
        return None, "invalid_expires_at"
    expires_at_timestamp = _parse_policy_bundle_timestamp(expires_at) if isinstance(expires_at, str) else None
    if expires_at is not None and expires_at_timestamp is None:
        return None, "invalid_expires_at"
    if expires_at_timestamp is not None and expires_at_timestamp <= issued_at_timestamp:
        return None, "invalid_expires_at"
    current_time = now if now is not None else time.time()
    if issued_at_timestamp > current_time + _POLICY_BUNDLE_CLOCK_SKEW_SECONDS:
        return None, "bundle_not_yet_valid"
    if expires_at_timestamp is not None and current_time > expires_at_timestamp:
        return None, "bundle_expired"
    workspace_id = policy_bundle.get("workspaceId")
    normalized_workspace_id = _non_empty_string(workspace_id)
    if workspace_id is not None and normalized_workspace_id is None:
        return None, "invalid_workspace_id"
    verifier = policy_bundle.get("verifier")
    if not isinstance(verifier, dict):
        return None, "invalid_verifier"
    if verifier.get("algorithm") != "rsa-pss-sha256":
        return None, "unsupported_signature_algorithm"
    if _non_empty_string(verifier.get("keyId")) is None:
        return None, "missing_signing_key_id"
    if _non_empty_string(verifier.get("signature")) is None:
        return None, "missing_signature"
    if normalized_workspace_id is None or expected_workspace_id is None:
        return None, "wrong_workspace"
    if normalized_workspace_id != expected_workspace_id:
        return None, "wrong_workspace"
    if "minDaemonVersion" in policy_bundle:
        min_daemon_version = _non_empty_string(policy_bundle.get("minDaemonVersion"))
        if min_daemon_version is None or _version_tuple(min_daemon_version) is None:
            return None, "invalid_min_daemon_version"
        if not policy_bundle_daemon_version_supported(policy_bundle):
            return None, "unsupported_daemon_version"
    if "receiptRedactionLevel" in policy_bundle:
        receipt_redaction_level = policy_bundle.get("receiptRedactionLevel")
        if (
            not isinstance(receipt_redaction_level, str)
            or receipt_redaction_level not in VALID_RECEIPT_REDACTION_LEVELS
        ):
            return None, "invalid_receipt_redaction_level"
    if policy_bundle.get("rolloutState") not in _POLICY_BUNDLE_ROLLOUT_STATES:
        return None, "invalid_rollout_state"
    defaults = policy_bundle.get("policyDefaults")
    if not isinstance(defaults, dict):
        return None, "invalid_policy_defaults"
    if defaults.get("mode") not in _POLICY_BUNDLE_MODE_VALUES:
        return None, "invalid_policy_defaults"
    if defaults.get("defaultAction") not in _POLICY_BUNDLE_DEFAULT_ACTIONS:
        return None, "invalid_policy_defaults"
    if defaults.get("unknownPublisherAction") not in _POLICY_BUNDLE_REVIEW_ACTIONS:
        return None, "invalid_policy_defaults"
    if defaults.get("changedHashAction") not in _POLICY_BUNDLE_CHANGED_HASH_ACTIONS:
        return None, "invalid_policy_defaults"
    if defaults.get("newNetworkDomainAction") not in _POLICY_BUNDLE_DEFAULT_ACTIONS:
        return None, "invalid_policy_defaults"
    if defaults.get("subprocessAction") not in _POLICY_BUNDLE_DEFAULT_ACTIONS:
        return None, "invalid_policy_defaults"
    if not isinstance(defaults.get("telemetryEnabled"), bool) or not isinstance(defaults.get("syncEnabled"), bool):
        return None, "invalid_policy_defaults"
    rules = policy_bundle.get("rules")
    if not isinstance(rules, list) or not all(_policy_bundle_rule_is_valid(rule) for rule in rules):
        return None, "invalid_rules"
    if not policy_bundle_cloud_exceptions_are_valid(policy_bundle):
        return None, "invalid_cloud_exceptions"
    acknowledgements = policy_bundle.get("acknowledgements")
    if not isinstance(acknowledgements, list) or not all(
        _policy_bundle_acknowledgement_is_valid(acknowledgement) for acknowledgement in acknowledgements
    ):
        return None, "invalid_acknowledgements"
    canonical_payload = canonical_policy_bundle_payload(policy_bundle)
    payload_hash = _non_empty_string(policy_bundle.get("payloadHash"))
    computed_payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    if payload_hash is None or payload_hash != payload_hash.strip():
        return None, "invalid_payload_hash"
    if payload_hash.lower() not in {computed_payload_hash, f"sha256:{computed_payload_hash}"}:
        return None, "payload_hash_mismatch"
    bundle_hash = _non_empty_string(policy_bundle.get("bundleHash"))
    if bundle_hash is None:
        return None, "invalid_bundle_hash"
    computed_hash = computed_policy_bundle_hash(policy_bundle)
    if bundle_hash != computed_hash:
        return None, "bundle_hash_mismatch"
    signature_error = _verify_policy_bundle_signature(
        policy_bundle,
        canonical_payload,
        trusted_verification_keys=trusted_verification_keys,
        anchored_verification_keys=anchored_verification_keys,
        expected_workspace_id=expected_workspace_id,
        now=current_time,
    )
    if signature_error is not None:
        return None, signature_error
    payload = {
        "contractVersion": policy_bundle["contractVersion"],
        "bundleVersion": policy_bundle["bundleVersion"],
        "bundleHash": bundle_hash,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        **(
            {"minDaemonVersion": policy_bundle["minDaemonVersion"]}
            if _non_empty_string(policy_bundle.get("minDaemonVersion"))
            else {}
        ),
        "verifier": verifier,
        "rolloutState": policy_bundle["rolloutState"],
        "policyDefaults": defaults,
        "rules": rules,
        "acknowledgements": acknowledgements,
    }
    if "receiptRedactionLevel" in policy_bundle:
        payload["receiptRedactionLevel"] = policy_bundle["receiptRedactionLevel"]
    cloud_exceptions = policy_bundle.get("cloudExceptions")
    if isinstance(cloud_exceptions, list):
        payload["cloudExceptions"] = cloud_exceptions
    if payload_hash is not None:
        # Collapse accepted prefix/case variants to one monotonic checkpoint
        # identity so equivalent encodings cannot fork replay bookkeeping.
        payload["payloadHash"] = computed_payload_hash
    if workspace_id is not None:
        payload["workspaceId"] = workspace_id
    return payload, None


non_empty_string = _non_empty_string
POLICY_BUNDLE_DEFAULT_ENVIRONMENTS = _POLICY_BUNDLE_DEFAULT_ENVIRONMENTS
POLICY_BUNDLE_RULE_ACTIONS = _POLICY_BUNDLE_RULE_ACTIONS
POLICY_BUNDLE_RULE_MATCHER_FAMILIES = _POLICY_BUNDLE_RULE_MATCHER_FAMILIES
POLICY_BUNDLE_BROWSER_SCOPE_KEYS = _POLICY_BUNDLE_BROWSER_SCOPE_KEYS
