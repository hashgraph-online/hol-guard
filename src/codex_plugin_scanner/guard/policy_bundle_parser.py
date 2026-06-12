"""Policy bundle schema validation and integrity hashing."""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    policy_bundle_key_fingerprint,
    resolve_policy_bundle_signing_key,
    signing_key_is_current,
    signing_key_is_trusted,
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

_POLICY_BUNDLE_DEFAULT_ACTIONS = frozenset({"allow", "warn", "block"})
_POLICY_BUNDLE_MODE_VALUES = frozenset({"observe", "prompt", "enforce"})
_POLICY_BUNDLE_REVIEW_ACTIONS = frozenset({"allow", "review", "block"})
_POLICY_BUNDLE_CHANGED_HASH_ACTIONS = frozenset({"allow", "warn", "require-reapproval", "block"})
_POLICY_BUNDLE_RULE_ACTIONS = frozenset({"allow", "block", "review", "ignore"})
_POLICY_BUNDLE_ROLLOUT_STATES = frozenset(
    {"draft", "simulated", "pending_approval", "enforcing", "enforced", "rollback_available"}
)
_POLICY_BUNDLE_SCOPE_KEYS = frozenset({"agents", "devices", "ecosystems", "environments", "harnesses", "locations"})
_POLICY_BUNDLE_RULE_MATCHER_FAMILIES = frozenset(
    {"file-read", "mcp", "package-request", "prompt", "prompt-env-read", "tool-action"}
)
_POLICY_BUNDLE_DEFAULT_ENVIRONMENTS = frozenset({"development"})


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
    scope = rule.get("scope")
    return isinstance(scope, dict) and all(
        _policy_bundle_string_list(scope.get(key)) for key in _POLICY_BUNDLE_SCOPE_KEYS
    )


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
    verifier = bundle_core.get("verifier")
    if isinstance(verifier, dict):
        normalized_verifier = dict(verifier)
        normalized_verifier["signature"] = None
        bundle_core["verifier"] = normalized_verifier
    workspace_id = policy_bundle.get("workspaceId")
    if workspace_id is not None:
        bundle_core["workspaceId"] = workspace_id
    acknowledgements = policy_bundle.get("acknowledgements")
    if acknowledgements is None:
        raise ValueError("missing_policy_bundle_key:acknowledgements")
    bundle_core["acknowledgements"] = acknowledgements
    min_daemon_version = _non_empty_string(policy_bundle.get("minDaemonVersion"))
    if min_daemon_version is not None:
        bundle_core["minDaemonVersion"] = min_daemon_version
    return _stable_serialize(bundle_core).encode("utf-8")


def payload_hash_for_policy_bundle(policy_bundle: dict[str, object]) -> str:
    return hashlib.sha256(canonical_policy_bundle_payload(policy_bundle)).hexdigest()


def _verify_policy_bundle_signature(
    policy_bundle: dict[str, object],
    canonical_payload: bytes,
    *,
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...],
) -> str | None:
    verifier = policy_bundle.get("verifier")
    if not isinstance(verifier, dict):
        return "invalid_verifier"
    algorithm = verifier.get("algorithm")
    if algorithm == "sha256":
        return None
    if algorithm != "rsa-pss-sha256":
        return "invalid_verifier"
    key_id = _non_empty_string(verifier.get("keyId"))
    signature = _non_empty_string(verifier.get("signature"))
    if key_id is None or signature is None:
        return "invalid_verifier"
    signing_key = resolve_policy_bundle_signing_key(key_id, trusted_verification_keys)
    if signing_key is None:
        return "untrusted_signing_key"
    if not signing_key_is_trusted(signing_key, anchored_verification_keys):
        return "untrusted_signing_key"
    bundled_public_key_pem = _non_empty_string(verifier.get("publicKeyPem"))
    if bundled_public_key_pem is not None:
        bundled_fingerprint = policy_bundle_key_fingerprint(bundled_public_key_pem)
        if bundled_fingerprint != signing_key.fingerprint_sha256:
            return "untrusted_signing_key"
    if not signing_key_is_current(signing_key):
        return "untrusted_signing_key"
    try:
        public_key = serialization.load_pem_public_key(signing_key.public_key_pem.encode("utf-8"))
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return "invalid_verifier"
    if not isinstance(public_key, RSAPublicKey):
        return "invalid_verifier"
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception:
        return "invalid_verifier"
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


def validated_policy_bundle_payload(
    policy_bundle: dict[str, object],
    *,
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
) -> tuple[dict[str, object] | None, str | None]:
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
    expires_at = policy_bundle.get("expiresAt")
    if expires_at is not None and _non_empty_string(expires_at) is None:
        return None, "invalid_expires_at"
    workspace_id = policy_bundle.get("workspaceId")
    if workspace_id is not None and _non_empty_string(workspace_id) is None:
        return None, "invalid_workspace_id"
    verifier = policy_bundle.get("verifier")
    if not isinstance(verifier, dict):
        return None, "invalid_verifier"
    if (
        verifier.get("algorithm") not in {"sha256", "rsa-pss-sha256"}
        or _non_empty_string(verifier.get("keyId")) is None
    ):
        return None, "invalid_verifier"
    signature = verifier.get("signature")
    if signature is not None and _non_empty_string(signature) is None:
        return None, "invalid_verifier"
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
    acknowledgements = policy_bundle.get("acknowledgements")
    if not isinstance(acknowledgements, list) or not all(
        _policy_bundle_acknowledgement_is_valid(acknowledgement) for acknowledgement in acknowledgements
    ):
        return None, "invalid_acknowledgements"
    canonical_payload = canonical_policy_bundle_payload(policy_bundle)
    payload_hash = _non_empty_string(policy_bundle.get("payloadHash"))
    if payload_hash is not None and payload_hash != hashlib.sha256(canonical_payload).hexdigest():
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
    if payload_hash is not None:
        payload["payloadHash"] = payload_hash
    if workspace_id is not None:
        payload["workspaceId"] = workspace_id
    return payload, None


non_empty_string = _non_empty_string
POLICY_BUNDLE_DEFAULT_ENVIRONMENTS = _POLICY_BUNDLE_DEFAULT_ENVIRONMENTS
POLICY_BUNDLE_RULE_ACTIONS = _POLICY_BUNDLE_RULE_ACTIONS
POLICY_BUNDLE_RULE_MATCHER_FAMILIES = _POLICY_BUNDLE_RULE_MATCHER_FAMILIES
