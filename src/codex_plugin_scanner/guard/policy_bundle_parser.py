"""Policy bundle schema validation and integrity hashing.

Rust owns v1 bundle schema validation, canonical hashing, signature
verification and downgrade ordering. This module keeps the public names,
remediation text rendering and the transport calls; a native failure is a
typed rejection, never a Python verdict.
"""

from __future__ import annotations

import time

from ..version import __version__
from .native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
    native_policy_bundle,
    native_rejection_code,
    policy_bundle_chunks,
    policy_bundle_paged_text,
    policy_bundle_verdict,
)
from .policy_bundle_trusted_keys import PolicyBundleVerificationKey

_POLICY_BUNDLE_RULE_MATCHER_FAMILIES = frozenset(
    {"file-read", "mcp", "mcp-tool", "package-request", "prompt", "prompt-env-read", "tool-action"}
)

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


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _bundle_value(kind: str, policy_bundle: dict[str, object]) -> str:
    result = policy_bundle_verdict(kind, {"bundle_chunks": policy_bundle_chunks(policy_bundle)})
    return str(result["value"])


def _bundle_text(kind: str, policy_bundle: dict[str, object]) -> str:
    return policy_bundle_paged_text(kind, {"bundle_chunks": policy_bundle_chunks(policy_bundle)})


def computed_policy_bundle_hash(policy_bundle: dict[str, object]) -> str:
    return _bundle_value("v1_bundle_hash", policy_bundle)


def canonical_policy_bundle_payload(policy_bundle: dict[str, object]) -> bytes:
    return _bundle_text("v1_canonical_payload", policy_bundle).encode("utf-8")


def payload_hash_for_policy_bundle(policy_bundle: dict[str, object]) -> str:
    return _bundle_value("v1_payload_hash", policy_bundle)


def _flag(kind: str, request: dict[str, object], *, otherwise: bool) -> bool:
    """Return one Rust boolean verdict.

    ``otherwise`` is the fail-closed answer when Rust rejects the request as
    malformed or answers with an error verdict. An outage of the resident is not
    a verdict: ``PolicyBundleNativeUnavailableError`` propagates so callers report it
    as unavailable rather than as an inactive, unsupported or downgraded bundle.
    """

    try:
        result = native_policy_bundle(kind, request)
    except PolicyBundleNativeUnavailableError:
        raise
    except ValueError:
        return otherwise
    if isinstance(result.get("error"), str):
        return otherwise
    return result.get("value") is True


def policy_bundle_daemon_version_supported(policy_bundle: dict[str, object]) -> bool:
    slim = {key: policy_bundle[key] for key in ("minDaemonVersion",) if key in policy_bundle}
    return _flag("daemon_version_supported", {"bundle": slim, "daemon_version": __version__}, otherwise=False)


def policy_bundle_is_enforceable(policy_bundle: dict[str, object]) -> bool:
    """Return whether an authenticated rollout is intended as live authority."""

    slim = {key: policy_bundle[key] for key in ("contractVersion", "rolloutState") if key in policy_bundle}
    return _flag("is_enforceable", {"bundle": slim}, otherwise=False)


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


_ORDERING_KEYS = ("bundleVersion", "bundleHash", "payloadHash", "issuedAt", "workspaceId")


def _ordering_view(bundle: object) -> object:
    if not isinstance(bundle, dict):
        return bundle
    return {key: bundle[key] for key in _ORDERING_KEYS if key in bundle}


def policy_bundle_is_version_downgrade(
    accepted_bundle: dict[str, object] | None,
    candidate_bundle: dict[str, object],
) -> bool:
    """Reject older or unordered signed payloads relative to accepted authority."""

    try:
        accepted_chunks = None if accepted_bundle is None else policy_bundle_chunks(_ordering_view(accepted_bundle))
        request: dict[str, object] = {
            "accepted_chunks": accepted_chunks,
            "bundle_chunks": policy_bundle_chunks(_ordering_view(candidate_bundle)),
        }
    except ValueError:
        return True
    return _flag("is_downgrade", request, otherwise=True)


def policy_bundle_rejection_message(reason: str | None) -> str | None:
    if reason == "inactive_rollout_state":
        return (
            "The authenticated policy bundle is not active for local enforcement. "
            "Approve or publish the rollout in Guard Cloud, then sync again."
        )
    if reason == NATIVE_UNAVAILABLE_REJECTION:
        return (
            "The policy bundle was not applied because the Guard native runtime could not be reached. "
            "Check that Guard is healthy, then sync again."
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
    try:
        result = policy_bundle_verdict(
            "validate_v1",
            {
                "bundle_chunks": policy_bundle_chunks(policy_bundle),
                "trusted_keys": [key.to_dict() for key in trusted_verification_keys],
                "anchored_keys": [key.to_dict() for key in anchored_verification_keys],
                "expected_workspace_id": expected_workspace_id,
                "now": now if now is not None else time.time(),
                "daemon_version": __version__,
            },
        )
    except PolicyBundleNativeError as error:
        return None, "invalid_json_value" if error.code == "non_finite_number" else native_rejection_code(error)
    keys = result.get("payload_keys")
    payload_hash = result.get("payload_hash")
    if not isinstance(keys, list) or not isinstance(payload_hash, str):
        return None, "native_policy_bundle_authority_schema_mismatch"
    payload = {key: policy_bundle[key] for key in keys if key != "payloadHash"}
    payload["payloadHash"] = payload_hash
    return payload, None


non_empty_string = _non_empty_string
POLICY_BUNDLE_RULE_MATCHER_FAMILIES = _POLICY_BUNDLE_RULE_MATCHER_FAMILIES
