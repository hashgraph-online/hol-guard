"""Test-only wrappers over the native v1 policy bundle verdicts.

Production code reaches the v1 bundle hash, canonical payload and full
validation through Rust during sync. Tests still compute them directly to
build and check signed fixtures, so the thin wrappers live here.
"""

from __future__ import annotations

import time

from codex_plugin_scanner.guard.native_policy_bundle import (
    PolicyBundleNativeError,
    native_rejection_code,
    policy_bundle_chunks,
    policy_bundle_paged_text,
    policy_bundle_verdict,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import PolicyBundleVerificationKey
from codex_plugin_scanner.version import __version__

POLICY_BUNDLE_RULE_MATCHER_FAMILIES = frozenset(
    {"file-read", "mcp", "mcp-tool", "package-request", "prompt", "prompt-env-read", "tool-action"}
)


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
